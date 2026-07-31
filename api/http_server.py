#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ApiService - HTTP REST API 服务.

提供机机接口供 ai agent 调用, 监听 0.0.0.0:8899.
Jython 环境用 com.sun.net.httpserver.HttpServer, CPython 环境用 BaseHTTPServer.

端点设计:
  GET    /api/config                     读取全部配置
  PUT    /api/config/llm                  设置 LLM 配置
  PUT    /api/config/user/{id}/identify  设置用户标识
  PUT    /api/config/blacklist            设置黑名单
  POST   /api/action/autorize             开关 autorize
  POST   /api/action/extract-params       提取参数
  POST   /api/action/generate-attacks     生成攻击
  POST   /api/action/auto-idor            开关 auto idor
  POST   /api/action/batch-attack-get     批量执行 GET 攻击
  POST   /api/action/execute-attack        执行单个攻击
  POST   /api/action/prune-attacks         AI 剪枝: 删除低价值 POC (Feature 1)
  POST   /api/action/ai-verify            AI 越权验证: 深度报文判断 (Feature 2)
  POST   /api/action/ai-generate-poc       AI 介入 POC 生成 (Feature 3)
  POST   /api/action/autorize                开关 Autorize (on/off)
  POST   /api/action/clear-db                清空数据库 (流量/攻击/参数, 保留 config/users)
  POST   /api/action/refresh-traffic-identity  刷新缓存流量的用户标识
  GET    /api/attacks                      查询攻击结果 (含 ai_verified 字段)
  GET    /api/attacks/{id}                查询单个攻击详情 (含完整报文)
  DELETE /api/attacks/{id}                删除单个攻击 (剪枝补充)
  POST   /api/recommend                   获取参数推荐
  POST   /api/recommend/apply             应用推荐值
  POST   /api/user/{id}/header            新增/更新 header
  POST   /api/user/{id}/cookie            新增/更新 cookie
  DELETE /api/user/{id}/header/{key}      删除 header
  GET    /api/status                      服务状态
"""

import json
import re
import sys
import traceback

try:
    from java.util.concurrent.locks import ReentrantLock
except ImportError:
    class ReentrantLock(object):
        def lock(self): pass
        def unlock(self): pass

from api.config_manager import ConfigManager

# ----------------------------------------------------------------------------
# 端口配置
# ----------------------------------------------------------------------------
API_PORT = 8899
API_HOST = "0.0.0.0"

# Module-level server reference — survives extension reload within same JVM.
# When a new ApiService starts, it can find and stop the old server first.
_existing_httpd = None


class ApiService(object):
    """
    HTTP REST API 服务.
    持有 extender 引用, 通过 ConfigManager 读写配置, 调用业务层方法.
    核心路由逻辑在 handle_request 中, 测试时可直接调用.
    """

    def __init__(self, extender):
        self.extender = extender
        self.config_manager = ConfigManager()
        self.db_manager = extender.db_manager if hasattr(extender, "db_manager") else None
        self.server = None
        self._lock = ReentrantLock()

    # ------------------------------------------------------------------
    # 服务器启动/停止
    # ------------------------------------------------------------------
    def start(self):
        """启动 HTTP server, 监听 0.0.0.0:8899.

        使用 Python 标准库 BaseHTTPServer/http.server, 同时兼容 Jython 2.7 和 CPython 3.
        不再依赖 com.sun.net.httpserver (在 Burp 的 Jython 类加载器中无法加载).
        """
        global _existing_httpd

        # 先停止已有的 server (防止端口占用)
        if self.server is not None:
            self.stop()

        # 停止上一个扩展实例留下的 server (同 JVM 内 reload 场景)
        if _existing_httpd is not None:
            print("[API] Stopping leftover server from previous extension load...")
            try:
                _existing_httpd.shutdown()
            except:
                pass
            try:
                _existing_httpd.server_close()
            except:
                pass
            _existing_httpd = None

        print("[API] Attempting to start HTTP server on port {}...".format(API_PORT))

        try:
            self._start_httpd()
            return True
        except Exception as e:
            print("[API] ERROR: Failed to start HTTP server: " + str(e))
            import traceback
            traceback.print_exc()
            return False

    def _start_httpd(self):
        """启动基于 Python 标准库的 HTTP server (Jython + CPython 通用)."""
        global _existing_httpd
        import threading

        # Python 2 (Jython 2.7) has BaseHTTPServer; Python 3 has http.server
        try:
            from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
        except ImportError:
            from http.server import BaseHTTPRequestHandler, HTTPServer

        api_service = self

        class _Handler(BaseHTTPRequestHandler):
            def _handle(self):
                method = self.command
                path = self.path
                body = None
                if method in ("POST", "PUT", "DELETE"):
                    length = int(self.headers.get("Content-Length", 0))
                    if length > 0:
                        body = self.rfile.read(length)

                # 解析 query params
                query_params = {}
                if "?" in path:
                    path_part, query_str = path.split("?", 1)
                    path = path_part
                    for pair in query_str.split("&"):
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            query_params[k] = v

                status, response = api_service.handle_request(
                    method, path, query_params, body
                )
                response_bytes = json.dumps(response).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(response_bytes)))
                self.end_headers()
                self.wfile.write(response_bytes)

            def do_GET(self): self._handle()
            def do_POST(self): self._handle()
            def do_PUT(self): self._handle()
            def do_DELETE(self): self._handle()
            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.end_headers()

            def log_message(self, format, *args):
                pass

        # allow_reuse_address 必须在 __init__ 前设为类属性,
        # 这样 server_bind() 时会设置 SO_REUSEADDR, 允许端口复用.
        HTTPServer.allow_reuse_address = True

        httpd = HTTPServer((API_HOST, API_PORT), _Handler)
        try:
            t = threading.Thread(target=httpd.serve_forever)
            t.daemon = True
            t.start()
        except Exception:
            # 线程创建/启动失败时必须关闭已绑定的 socket,
            # 否则端口会泄漏 (旧代码的 bug: stop() 找不到 httpd 因为 self.server 未赋值).
            httpd.server_close()
            raise

        self.server = httpd
        _existing_httpd = httpd
        print("[API] HTTP server started on 0.0.0.0:{}".format(API_PORT))

    def stop(self):
        """停止 HTTP server."""
        global _existing_httpd
        if self.server:
            try:
                if hasattr(self.server, "shutdown"):
                    self.server.shutdown()
                elif hasattr(self.server, "stop"):
                    self.server.stop(0)
            except Exception as e:
                print("[API] Error stopping server: " + str(e))
            try:
                self.server.server_close()
            except:
                pass
            self.server = None
        _existing_httpd = None

    # ------------------------------------------------------------------
    # 核心路由分发
    # ------------------------------------------------------------------
    def handle_request(self, method, path, query_params=None, body=None):
        """
        核心路由分发方法. 测试时可直接调用此方法.

        参数:
            method: "GET" / "POST" / "PUT" / "DELETE"
            path: 请求路径 (不含 query string), 如 "/api/config"
            query_params: dict, 如 {"status": "VULNERABLE", "limit": "50"}
            body: dict (已解析的 JSON) 或 None

        返回: (status_code, response_dict)
        """
        if query_params is None:
            query_params = {}
        if isinstance(body, str) and body:
            try:
                body = json.loads(body)
            except ValueError:
                return 400, {"status": "error", "message": "Invalid JSON body"}
        if body is None:
            body = {}

        # 路由匹配
        try:
            route = self._match_route(method, path)
            if route is None:
                return 404, {"status": "error", "message": "Not found: {} {}".format(method, path)}

            handler_name, path_params = route
            handler = getattr(self, handler_name)
            return handler(path_params, query_params, body)
        except Exception as e:
            print("[API] Error handling {} {}: {}".format(method, path, str(e)))
            traceback.print_exc()
            return 500, {"status": "error", "message": str(e)}

    def _match_route(self, method, path):
        """
        匹配路由, 返回 (handler_name, path_params) 或 None.
        path_params: dict, 如 {"id": "1", "key": "user_id"}
        """
        # 路由表: (method, pattern, handler_name)
        # pattern 用正则匹配, 捕获组作为 path_params
        routes = [
            ("GET",    r"/api/status$",                        "_handle_status"),
            ("GET",    r"/api/config$",                        "_handle_get_config"),
            ("PUT",    r"/api/config/llm$",                    "_handle_put_llm"),
            ("PUT",    r"/api/config/blacklist$",              "_handle_put_blacklist"),
            ("PUT",    r"/api/config/user/(\d+)/identify$",    "_handle_put_identify"),
            ("POST",   r"/api/action/autorize$",               "_handle_action_autorize"),
            ("POST",   r"/api/action/clear-db$",               "_handle_action_clear_db"),
            ("POST",   r"/api/action/extract-params$",         "_handle_action_extract"),
            ("POST",   r"/api/action/generate-attacks$",      "_handle_action_generate"),
            ("POST",   r"/api/action/auto-idor$",             "_handle_action_auto_idor"),
            ("POST",   r"/api/action/batch-attack-get$",       "_handle_action_batch"),
            ("POST",   r"/api/action/execute-attack$",          "_handle_action_execute_attack"),
            ("POST",   r"/api/action/prune-attacks$",          "_handle_action_prune"),
            ("POST",   r"/api/action/ai-verify$",              "_handle_action_ai_verify"),
            ("POST",   r"/api/action/ai-generate-poc$",         "_handle_action_ai_generate_poc"),
            ("POST",   r"/api/action/refresh-traffic-identity$", "_handle_action_refresh_identity"),
            ("GET",    r"/api/attacks$",                       "_handle_get_attacks"),
            ("GET",    r"/api/attacks/(\d+)$",                 "_handle_get_attack_detail"),
            ("DELETE", r"/api/attacks/(\d+)$",                 "_handle_delete_attack"),
            ("POST",   r"/api/recommend$",                     "_handle_recommend"),
            ("POST",   r"/api/recommend/apply$",               "_handle_recommend_apply"),
            ("POST",   r"/api/user/(\d+)/header$",            "_handle_upsert_header"),
            ("POST",   r"/api/user/(\d+)/cookie$",             "_handle_upsert_cookie"),
            ("DELETE", r"/api/user/(\d+)/header/(.+)$",       "_handle_delete_header"),
        ]

        for m, pattern, handler_name in routes:
            if m != method:
                continue
            match = re.match(pattern, path)
            if match:
                groups = match.groups()
                path_params = {}
                if handler_name in ("_handle_put_identify", "_handle_upsert_header",
                                    "_handle_upsert_cookie"):
                    path_params["user_id"] = int(groups[0])
                elif handler_name in ("_handle_get_attack_detail", "_handle_delete_attack"):
                    path_params["id"] = int(groups[0])
                elif handler_name == "_handle_delete_header":
                    path_params["user_id"] = int(groups[0])
                    path_params["key"] = groups[1]
                return (handler_name, path_params)

        return None

    # ------------------------------------------------------------------
    # 工具方法
    # ------------------------------------------------------------------
    def _ok(self, data=None, message=""):
        """返回成功响应."""
        resp = {"status": "ok"}
        if data is not None:
            resp["data"] = data
        if message:
            resp["message"] = message
        return (200, resp)

    def _error(self, message, code=400):
        """返回错误响应."""
        return (code, {"status": "error", "message": message})

    def _mask_api_key(self, key):
        """掩码 API Key, 只显示前4位和后4位."""
        if not key or len(key) < 8:
            return "***"
        return key[:4] + "****" + key[-4:]

    # ------------------------------------------------------------------
    # GET /api/status
    # ------------------------------------------------------------------
    def _handle_status(self, params, query, body):
        """服务状态检查."""
        return self._ok({
            "running": True,
            "db_connected": self.db_manager is not None,
            "config_keys": len(self.config_manager._cache),
            "config_version": self.config_manager.get_config_version(),
            "attacks_version": self.config_manager.get_attacks_version(),
        })

    # ------------------------------------------------------------------
    # GET /api/config
    # ------------------------------------------------------------------
    def _handle_get_config(self, params, query, body):
        """读取全部配置."""
        cm = self.config_manager
        llm = cm.get_llm_config()
        users = cm.get_users()
        return self._ok({
            "llm": {
                "enable": llm["enabled"],
                "base_url": llm["base_url"],
                "api_key": self._mask_api_key(llm["api_key"]),
                "model": llm["model"],
                "verify_ssl": llm["verify_ssl"],
                "extract_params": llm["extract_params"],
                "generate_values": llm["generate_values"],
                "identify_risk": llm["identify_risk"],
                "analyze_result": llm["analyze_result"],
            },
            "users": users,
            "blacklist_params": cm.get("blacklist_params", ""),
            "auto_idor": cm.get_bool("auto_idor_enabled"),
            "autorize_intercept": cm.get_int("autorize_intercept", 0),
        })

    # ------------------------------------------------------------------
    # PUT /api/config/llm
    # ------------------------------------------------------------------
    def _handle_put_llm(self, params, query, body):
        """设置 LLM 配置."""
        cm = self.config_manager
        if "enable" in body:
            cm.set_bool("enable_llm", body["enable"])
        if "base_url" in body:
            cm.set("llm_base_url", body["base_url"])
        if "api_key" in body:
            cm.set("llm_api_key", body["api_key"])
        if "model" in body:
            cm.set("llm_model", body["model"])
        if "verify_ssl" in body:
            cm.set_bool("llm_disable_ssl_verification", not body["verify_ssl"])
        if "extract_params" in body:
            cm.set_bool("llm_extract_params", body["extract_params"])
        if "generate_values" in body:
            cm.set_bool("llm_generate_values", body["generate_values"])
        if "identify_risk" in body:
            cm.set_bool("llm_identify_risk", body["identify_risk"])
        if "analyze_result" in body:
            cm.set_bool("llm_analyze_result", body["analyze_result"])
        return self._ok(message="LLM config updated")

    # ------------------------------------------------------------------
    # PUT /api/config/user/{id}/identify
    # ------------------------------------------------------------------
    def _handle_put_identify(self, params, query, body):
        """设置用户标识字符串, 可选同时设置 headers_text."""
        user_id = params["user_id"]
        identify_string = body.get("identify_string", "")
        cm = self.config_manager
        # 获取现有用户或创建新用户
        user = cm.get_user_by_id(user_id)
        # 如果 body 中包含 headers_text, 使用新值; 否则保留现有值
        if "headers_text" in body:
            headers_text = body["headers_text"]
        elif user:
            headers_text = user.get("headers_text", "")
        else:
            headers_text = ""
        name = user.get("name", "User " + str(user_id)) if user else "User " + str(user_id)
        cm.save_user(user_id, name, identify_string, headers_text)
        return self._ok(message="User {} identify updated".format(user_id))

    # ------------------------------------------------------------------
    # PUT /api/config/blacklist
    # ------------------------------------------------------------------
    def _handle_put_blacklist(self, params, query, body):
        """设置黑名单参数."""
        params_str = body.get("params", "")
        self.config_manager.set("blacklist_params", params_str)
        return self._ok(message="Blacklist updated")

    # ------------------------------------------------------------------
    # POST /api/action/autorize
    # ------------------------------------------------------------------
    def _handle_action_autorize(self, params, query, body):
        """开关 autorize 拦截."""
        on = body.get("on", False)
        cm = self.config_manager
        cm.set_int("autorize_intercept", 1 if on else 0)
        # 同步到 extender (handle_message 检查 self.intercept)
        ext = self.extender
        if ext:
            ext.intercept = 1 if on else 0
        # 同步到 GUI
        if ext and hasattr(ext, "startButton"):
            try:
                from javax.swing import SwingUtilities
                def update():
                    ext.startButton.setText("Autorize is on" if on else "Autorize is off")
                    ext.startButton.setSelected(on)
                SwingUtilities.invokeLater(update)
            except ImportError:
                pass
        return self._ok(message="Autorize is {}".format("on" if on else "off"))

    # ------------------------------------------------------------------
    # POST /api/action/clear-db  - 清空数据库 (流量/攻击/参数)
    # ------------------------------------------------------------------
    def _handle_action_clear_db(self, params, query, body):
        """
        清空数据库中的流量/攻击/参数数据, 保留 config/users/rules.

        body: {
            "keep_config": true   // 始终保留 config/users/match_replace_rules
        }
        """
        db = self.db_manager
        if not db:
            return self._error("Database not available")
        try:
            success = db.clear_all_data()
            if success:
                # 通知配置变更, 刷新前端
                if self.config_manager:
                    self.config_manager.notify_attacks_changed()
                return self._ok(
                    {"cleared_tables": [
                        "attack_queue", "parameter_pool",
                        "raw_requests", "api_metadata", "sqlite_sequence"
                    ]},
                    "Database cleared (traffic/attacks/params removed, config/users preserved)"
                )
            else:
                return self._error("Failed to clear database", 500)
        except Exception as e:
            return self._error("Clear DB failed: " + str(e))

    # ------------------------------------------------------------------
    # POST /api/action/extract-params
    # ------------------------------------------------------------------
    def _handle_action_extract(self, params, query, body):
        """提取参数 (调用 Extractor.process_unanalyzed_requests)."""
        ext = self.extender
        if not ext or not hasattr(ext, "extractor"):
            return self._error("Extractor not available")
        try:
            ext.extractor.process_unanalyzed_requests()
            return self._ok(message="Parameter extraction completed")
        except Exception as e:
            return self._error("Extraction failed: " + str(e))

    # ------------------------------------------------------------------
    # POST /api/action/generate-attacks
    # ------------------------------------------------------------------
    def _handle_action_generate(self, params, query, body):
        """生成攻击 (调用 AttackEngine.generate_attacks)."""
        ext = self.extender
        if not ext or not hasattr(ext, "attack_engine"):
            return self._error("AttackEngine not available")
        try:
            hidden_param_config = body.get("hidden_param_config", None)
            created = ext.attack_engine.generate_attacks(hidden_param_config)
            self.config_manager.notify_attacks_changed()
            return self._ok(message="Attacks generated: {} created".format(created), data={"generated": created})
        except Exception as e:
            return self._error("Generation failed: " + str(e))

    # ------------------------------------------------------------------
    # POST /api/action/auto-idor
    # ------------------------------------------------------------------
    def _handle_action_auto_idor(self, params, query, body):
        """开关 auto IDOR 定时循环."""
        enable = body.get("enable", False)
        cm = self.config_manager
        cm.set_bool("auto_idor_enabled", enable)
        ext = self.extender
        if ext and hasattr(ext, "scheduler") and ext.scheduler:
            try:
                if enable:
                    ext.scheduler.start()
                else:
                    ext.scheduler.stop()
            except Exception as e:
                print("[API] scheduler error: " + str(e))
        return self._ok(message="Auto IDOR {}".format("enabled" if enable else "disabled"))

    # ------------------------------------------------------------------
    # POST /api/action/batch-attack-get
    # ------------------------------------------------------------------
    def _handle_action_batch(self, params, query, body):
        """批量执行 GET 攻击."""
        ext = self.extender
        if not ext or not hasattr(ext, "attack_engine"):
            return self._error("AttackEngine not available")
        try:
            limit = body.get("limit", 50)
            hidden_param_config = body.get("hidden_param_config", None)
            llm_config = self.config_manager.get_llm_config()
            summary = ext.attack_engine.execute_pending_get_attacks(
                ext._callbacks,
                ext._helpers,
                llm_config,
                limit,
                hidden_param_config,
                body.get("apply_hidden_param_on_execute", False),
            )
            self.config_manager.notify_attacks_changed()
            return self._ok(summary, "Batch attack completed")
        except Exception as e:
            return self._error("Batch attack failed: " + str(e))

    # ------------------------------------------------------------------
    # POST /api/action/execute-attack
    # ------------------------------------------------------------------
    def _handle_action_execute_attack(self, params, query, body):
        """
        执行单个选定攻击 (等价于 GUI 的 Execute Selected).
        body: {"attack_id": 1}
        """
        ext = self.extender
        if not ext or not hasattr(ext, "attack_engine"):
            return self._error("AttackEngine not available")
        attack_id = body.get("attack_id")
        if not attack_id:
            return self._error("Missing 'attack_id' in body")
        try:
            llm_config = self.config_manager.get_llm_config()
            result = ext.attack_engine.execute_attack(
                int(attack_id),
                ext._callbacks,
                ext._helpers,
                llm_config,
                body.get("hidden_param_config", None),
                body.get("apply_hidden_param_on_execute", False),
            )
            self.config_manager.notify_attacks_changed()
            return self._ok({"attack_id": int(attack_id), "result": result},
                            "Attack {} executed".format(attack_id))
        except Exception as e:
            return self._error("Execute attack failed: " + str(e))

    # ------------------------------------------------------------------
    # GET /api/attacks
    # ------------------------------------------------------------------
    def _handle_get_attacks(self, params, query, body):
        """查询攻击结果列表. 包含 AI 验证字段 (高优先级标识)."""
        db = self.db_manager
        if not db:
            return self._error("Database not available")

        conditions = []
        sql_params = []

        status = query.get("status")
        if status:
            conditions.append("a.status = ?")
            sql_params.append(status)

        verified = query.get("verified")
        if verified is not None:
            conditions.append("a.verified = ?")
            sql_params.append(1 if verified in ("true", "1") else 0)

        ai_verified = query.get("ai_verified")
        if ai_verified is not None:
            conditions.append("a.ai_verified = ?")
            sql_params.append(1 if ai_verified in ("true", "1") else 0)

        limit = int(query.get("limit", "100"))

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
        sql = (
            "SELECT a.id, r.method, r.path, a.status, a.response_code, "
            "a.vulnerability_score, a.llm_verification_result, a.payload_description, "
            "a.verified, a.ai_verification_result, a.ai_verified "
            "FROM attack_queue a "
            "JOIN raw_requests r ON a.original_request_id = r.id" +
            where_clause +
            " ORDER BY a.ai_verified DESC, a.verified DESC, a.id DESC LIMIT ?"
        )
        sql_params.append(limit)

        rows = db.fetch_all(sql, sql_params)
        if rows is None:
            return self._error("Database query failed", 500)

        attacks = []
        for row in rows:
            attacks.append({
                "id": row[0],
                "method": row[1],
                "path": row[2],
                "status": row[3],
                "response_code": row[4],
                "vulnerability_score": row[5],
                "llm_verification_result": row[6] if row[6] else "",
                "payload_description": row[7] if row[7] else "",
                "verified": bool(row[8]) if row[8] is not None else False,
                "ai_verification_result": row[9] if row[9] else "",
                "ai_verified": bool(row[10]) if row[10] is not None else False,
            })

        return self._ok({"attacks": attacks, "total": len(attacks)})

    # ------------------------------------------------------------------
    # GET /api/attacks/{id}
    # ------------------------------------------------------------------
    def _handle_get_attack_detail(self, params, query, body):
        """查询单个攻击详情. 包含 AI 验证字段和完整 request/response 报文."""
        db = self.db_manager
        if not db:
            return self._error("Database not available")

        attack_id = params["id"]
        sql = (
            "SELECT a.id, r.method, r.path, r.host, r.url, a.status, a.response_code, "
            "a.vulnerability_score, a.llm_verification_result, a.payload_description, a.verified, "
            "a.executed_request_data, a.response_data, r.headers, r.body, "
            "r.response_headers, r.response_body, "
            "a.ai_verification_result, a.ai_verified, a.request_data "
            "FROM attack_queue a "
            "JOIN raw_requests r ON a.original_request_id = r.id "
            "WHERE a.id = ?"
        )
        rows = db.fetch_all(sql, [attack_id])
        if rows is None:
            return self._error("Database query failed", 500)
        if not rows:
            return self._error("Attack not found", 404)

        row = rows[0]
        return self._ok({
            "id": row[0],
            "method": row[1],
            "path": row[2],
            "host": row[3],
            "url": row[4],
            "status": row[5],
            "response_code": row[6],
            "vulnerability_score": row[7],
            "llm_verification_result": row[8] if row[8] else "",
            "payload_description": row[9] if row[9] else "",
            "verified": bool(row[10]) if row[10] is not None else False,
            "attack_request": row[11] if row[11] else "",
            "attack_response": row[12] if row[12] else "",
            "original_request_headers": row[13] if row[13] else "",
            "original_request_body": row[14] if row[14] else "",
            "original_response_headers": row[15] if row[15] else "",
            "original_response_body": row[16] if row[16] else "",
            "ai_verification_result": row[17] if row[17] else "",
            "ai_verified": bool(row[18]) if row[18] is not None else False,
            "request_data": row[19] if row[19] else "",
        })

    # ------------------------------------------------------------------
    # POST /api/recommend
    # ------------------------------------------------------------------
    def _handle_recommend(self, params, query, body):
        """
        获取参数推荐值.
        body: {"key": "user_id", "location": "Auto|Query|Header|Body|Path", "user_id": 1, "use_llm": false}
        """
        key = body.get("key", "")
        location = body.get("location", "Auto")
        if not key:
            return self._error("Missing 'key' in body")

        db = self.db_manager
        if not db:
            return self._error("Database not available")

        # 从 parameter_pool 查找候选值
        location_map = {
            "Query": "QUERY", "Header": "HEADER", "Body": "BODY",
            "Path": "PATH", "Auto": None, "COOKIE": "COOKIE",
        }
        loc = location_map.get(location, None)

        if loc:
            sql = (
                "SELECT DISTINCT param_value, api_signature, user_identifier "
                "FROM parameter_pool WHERE param_name = ? AND location = ? "
                "ORDER BY id DESC LIMIT 20"
            )
            rows = db.fetch_all(sql, [key, loc])
        else:
            sql = (
                "SELECT DISTINCT param_value, api_signature, user_identifier "
                "FROM parameter_pool WHERE param_name = ? "
                "ORDER BY id DESC LIMIT 20"
            )
            rows = db.fetch_all(sql, [key])

        if rows is None:
            return self._error("Database query failed", 500)

        recommendations = []
        for i, row in enumerate(rows):
            value = row[0] if row[0] else ""
            endpoint = row[1] if row[1] else ""
            user = row[2] if row[2] else ""
            recommendations.append({
                "rank": i + 1,
                "key": key,
                "value": value,
                "source_user": user,
                "endpoint": endpoint,
                "location": loc or "Auto",
                "score": 100 - i * 10,
            })

        return self._ok({"recommendations": recommendations})

    # ------------------------------------------------------------------
    # POST /api/recommend/apply
    # ------------------------------------------------------------------
    def _handle_recommend_apply(self, params, query, body):
        """
        应用推荐值到指定用户的 Match/Replace 规则.
        body: {"user_id": 1, "key": "user_id", "value": "10086", "location": "Query|Header"}
        """
        user_id = body.get("user_id", 1)
        key = body.get("key", "")
        value = body.get("value", "")
        location = body.get("location", "Header")

        if not key or not value:
            return self._error("Missing 'key' or 'value'")

        cm = self.config_manager
        if location.lower() in ("header", "cookie"):
            rule_id = cm.upsert_user_header(user_id, key, value)
        else:
            # Query param: 用 Query Add/Set 规则
            rule_id = cm.save_match_replace_rule(user_id, "Query Add/Set:", key, value)

        return self._ok({"rule_id": rule_id}, "Rule applied")

    # ------------------------------------------------------------------
    # POST /api/user/{id}/header
    # ------------------------------------------------------------------
    def _handle_upsert_header(self, params, query, body):
        """新增/更新用户 header (upsert 语义)."""
        user_id = params["user_id"]
        key = body.get("key", "")
        value = body.get("value", "")
        if not key:
            return self._error("Missing 'key'")
        rule_id = self.config_manager.upsert_user_header(user_id, key, value)
        return self._ok({"rule_id": rule_id, "action": "upsert"})

    # ------------------------------------------------------------------
    # POST /api/user/{id}/cookie
    # ------------------------------------------------------------------
    def _handle_upsert_cookie(self, params, query, body):
        """新增/更新用户 cookie."""
        user_id = params["user_id"]
        value = body.get("value", "")
        if not value:
            return self._error("Missing 'value'")
        rule_id = self.config_manager.upsert_user_cookie(user_id, "Cookie", value)
        return self._ok({"rule_id": rule_id, "action": "upsert"})

    # ------------------------------------------------------------------
    # DELETE /api/user/{id}/header/{key}
    # ------------------------------------------------------------------
    def _handle_delete_header(self, params, query, body):
        """删除用户 header 规则."""
        user_id = params["user_id"]
        key = params["key"]
        cm = self.config_manager
        rules = cm.get_match_replace_rules(user_id)
        for rule in rules:
            if rule["rule_type"] == "Header Add/Set:" and rule["match_text"] == key:
                cm.delete_match_replace_rule(rule["id"])
                return self._ok(message="Header '{}' deleted".format(key))
        return self._error("Header '{}' not found".format(key), 404)

    # ------------------------------------------------------------------
    # DELETE /api/attacks/{id}  - Feature 1 补充: 删除单个攻击 (剪枝)
    # ------------------------------------------------------------------
    def _handle_delete_attack(self, params, query, body):
        """删除单个攻击条目. 使用参数化 DELETE, 不影响自增序列和索引."""
        db = self.db_manager
        if not db:
            return self._error("Database not available")

        attack_id = params["id"]

        # 检查是否存在
        rows = db.fetch_all(
            "SELECT id, status FROM attack_queue WHERE id = ?",
            [attack_id],
        )
        if rows is None:
            return self._error("Database query failed", 500)
        if not rows:
            return self._error("Attack {} not found".format(attack_id), 404)

        status = rows[0][1] if rows[0][1] else "UNKNOWN"
        # 不允许删除正在执行中的攻击
        if status == "SENT":
            return self._error("Cannot delete attack {} (status=SENT)".format(attack_id), 400)

        ok = db.execute_query(
            "DELETE FROM attack_queue WHERE id = ?",
            [attack_id],
            commit=True,
        )
        if not ok:
            return self._error("Failed to delete attack {}".format(attack_id), 500)

        self.config_manager.notify_attacks_changed()
        return self._ok(
            {"deleted_id": attack_id},
            "Attack {} deleted".format(attack_id),
        )

    # ------------------------------------------------------------------
    # POST /api/action/prune-attacks  - Feature 1: AI 剪枝
    # ------------------------------------------------------------------
    def _handle_action_prune(self, params, query, body):
        """
        AI 剪枝: 对 PENDING 攻击进行 LLM 评分, 删除低价值 POC.
        body: {
            "limit": 50,           // 最多评分多少条 (默认 50)
            "score_threshold": 30,  // 低于此分数则删除 (默认 30)
            "use_llm": true         // 是否使用 LLM 评分, false 则用启发式 (默认 true)
        }
        """
        ext = self.extender
        if not ext or not hasattr(ext, "attack_engine"):
            return self._error("AttackEngine not available")

        limit = int(body.get("limit", 50))
        score_threshold = int(body.get("score_threshold", 30))
        use_llm = body.get("use_llm", True)

        llm_config = None
        if use_llm:
            llm_config = self.config_manager.get_llm_config()

        try:
            result = ext.attack_engine.prune_attacks(
                llm_config=llm_config,
                limit=limit,
                score_threshold=score_threshold,
            )
            self.config_manager.notify_attacks_changed()
            return self._ok(result, "Pruned {} of {} attacks".format(
                result.get("pruned", 0), result.get("total", 0)))
        except Exception as e:
            return self._error("Prune failed: " + str(e))

    # ------------------------------------------------------------------
    # POST /api/action/ai-verify  - Feature 2: AI 越权验证
    # ------------------------------------------------------------------
    def _handle_action_ai_verify(self, params, query, body):
        """
        AI 越权验证: 越权 agent 可看到 fuzz 报文和原始报文, 提供更精确判断.
        body: {
            "attack_id": 1,               // 必填: 要验证的攻击 ID
            "extra_context": "...",        // 可选: agent 提供的额外上下文
            "force_reverify": false        // 可选: 强制重新验证 (即使已验证过)
        }
        """
        ext = self.extender
        if not ext or not hasattr(ext, "attack_engine"):
            return self._error("AttackEngine not available")

        attack_id = body.get("attack_id")
        if not attack_id:
            return self._error("Missing 'attack_id' in body")

        attack_id = int(attack_id)

        # 检查是否已验证过
        if not body.get("force_reverify", False):
            rows = self.db_manager.fetch_all(
                "SELECT ai_verified, ai_verification_result FROM attack_queue WHERE id = ?",
                [attack_id],
            )
            if rows and rows[0][0]:
                # 已验证过, 返回已有结果
                try:
                    existing = json.loads(rows[0][1]) if rows[0][1] else {}
                except Exception:
                    existing = {}
                return self._ok({
                    "attack_id": attack_id,
                    "ai_result": existing,
                    "already_verified": True,
                }, "Attack already AI-verified")

        llm_config = self.config_manager.get_llm_config()
        extra_context = body.get("extra_context", "")

        try:
            result = ext.attack_engine.ai_verify_attack(
                attack_id,
                llm_config=llm_config,
                callbacks=ext._callbacks if hasattr(ext, "_callbacks") else None,
                helpers=ext._helpers if hasattr(ext, "_helpers") else None,
                extra_context=extra_context,
            )
            self.config_manager.notify_attacks_changed()
            return self._ok(result, "AI verification completed for attack {}".format(attack_id))
        except Exception as e:
            return self._error("AI verify failed: " + str(e))

    # ------------------------------------------------------------------
    # POST /api/action/ai-generate-poc  - Feature 3: AI 介入 POC 生成
    # ------------------------------------------------------------------
    def _handle_action_ai_generate_poc(self, params, query, body):
        """
        AI POC 生成: 让 AI agent 介入参数修改, 或自动生成.
        body: {
            "request_id": 1,           // 必填: 原始请求 ID
            "modifications": [          // 可选: 手动指定修改 (不传则用 LLM 自动生成)
                {
                    "param": "user_id",
                    "original_value": "10086",
                    "new_value": "10087",
                    "location": "QUERY",
                    "reason": "swap to user 2's ID"
                }
            ],
            "target_user": "User 2",     // 可选: 目标用户
            "use_llm": true              // 可选: modifications 为空时是否用 LLM 自动生成 (默认 true)
        }
        """
        ext = self.extender
        if not ext or not hasattr(ext, "attack_engine"):
            return self._error("AttackEngine not available")

        request_id = body.get("request_id")
        if not request_id:
            return self._error("Missing 'request_id' in body")

        request_id = int(request_id)
        modifications = body.get("modifications")
        target_user = body.get("target_user")
        use_llm = body.get("use_llm", True)

        llm_config = None
        if not modifications and use_llm:
            llm_config = self.config_manager.get_llm_config()

        try:
            result = ext.attack_engine.ai_create_poc(
                request_id,
                modifications=modifications,
                llm_config=llm_config,
                target_user=target_user,
            )
            self.config_manager.notify_attacks_changed()
            return self._ok(result, "Generated {} AI POCs".format(
                result.get("generated", 0)))
        except Exception as e:
            return self._error("AI generate POC failed: " + str(e))

    # ------------------------------------------------------------------
    # POST /api/action/refresh-traffic-identity  - 刷新缓存流量的用户标识
    # ------------------------------------------------------------------
    def _handle_action_refresh_identity(self, params, query, body):
        """
        当用户事后配置了 user-identify 映射后, 刷新所有缓存流量的 user_identifier.

        会对 raw_requests 中所有 user_identifier 以 "auto:" 开头 (自动检测的临时标识)
        或为空且未匹配映射的记录, 重新检查 headers 是否匹配当前已配置的 identify_string.
        匹配成功的记录会更新为对应用户名, 并同步刷新 parameter_pool 中的 user_identifier.

        body: {
            "dry_run": false  // 可选: 只统计不实际更新 (默认 false)
        }
        """
        db = self.db_manager
        if not db:
            return self._error("Database not available")

        dry_run = body.get("dry_run", False)
        cm = self.config_manager

        # 获取当前已配置的用户标识映射
        users = cm.get_users()
        mappings = []
        for user in users:
            ident_str = (user.get("identify_string") or "").strip()
            if ident_str:
                mappings.append({
                    "identify_string": ident_str,
                    "user_name": user.get("name", "User " + str(user.get("id"))),
                    "user_id": user.get("id"),
                })

        if not mappings:
            return self._ok({
                "total_cached": 0,
                "refreshed": 0,
                "still_unmapped": 0,
            }, "No user-identify mappings configured yet")

        # 查询所有需要刷新的流量记录 (auto: 开头 或 user_identifier 为空)
        # 只刷新未分析或已分析的都行, 但跳过已生成攻击的 (避免影响)
        sql = (
            "SELECT id, headers, user_identifier FROM raw_requests "
            "WHERE user_identifier LIKE 'auto:%' OR user_identifier IS NULL OR user_identifier = ''"
        )
        rows = db.fetch_all(sql)
        if rows is None:
            return self._error("Database query failed", 500)
        if not rows:
            return self._ok({
                "total_cached": 0,
                "refreshed": 0,
                "still_unmapped": 0,
            }, "No cached traffic to refresh")

        refreshed = 0
        still_unmapped = 0
        refresh_details = []

        for row in rows:
            req_id = row[0]
            headers_json = row[1] if row[1] else ""
            old_ident = row[2] if row[2] else ""

            # 解析 headers
            try:
                headers_list = json.loads(headers_json) if headers_json else []
                if not isinstance(headers_list, list):
                    headers_list = [str(headers_list)]
            except Exception:
                headers_list = [str(headers_json)] if headers_json else []

            headers_str = "\n".join(str(h) for h in headers_list)

            # 重新匹配 identify_string
            new_ident = None
            for m in mappings:
                if m["identify_string"] in headers_str:
                    new_ident = m["user_name"]
                    break

            if new_ident and new_ident != old_ident:
                if not dry_run:
                    # 更新 raw_requests
                    db.execute_query(
                        "UPDATE raw_requests SET user_identifier = ? WHERE id = ?",
                        [new_ident, req_id],
                        commit=True,
                    )
                    # 同步刷新 parameter_pool 中该请求相关的 user_identifier
                    db.execute_query(
                        "UPDATE parameter_pool SET user_identifier = ? "
                        "WHERE user_identifier = ? AND api_signature IN "
                        "(SELECT api_signature FROM raw_requests WHERE id = ?)",
                        [new_ident, old_ident, req_id],
                        commit=True,
                    )
                refreshed += 1
                refresh_details.append({
                    "request_id": req_id,
                    "old_identifier": old_ident,
                    "new_identifier": new_ident,
                })
            elif not new_ident:
                still_unmapped += 1

        return self._ok({
            "total_cached": len(rows),
            "refreshed": refreshed,
            "still_unmapped": still_unmapped,
            "details": refresh_details[:50],
            "dry_run": bool(dry_run),
        }, "Refreshed {} of {} cached traffic records".format(refreshed, len(rows)))
