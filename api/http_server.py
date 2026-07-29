#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ApiService - HTTP REST API 服务.

提供机机接口供 ai agent 调用, 监听 127.0.0.1:8899.
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
  GET    /api/attacks                      查询攻击结果
  GET    /api/attacks/{id}                查询单个攻击详情
  POST   /api/recommend                   获取参数推荐
  POST   /api/recommend/apply             应用推荐值
  POST   /api/user/{id}/header            新增/更新 header
  POST   /api/user/{id}/cookie            新增/更新 cookie
  DELETE /api/user/{id}/header/{key}      删除 header
  GET    /api/status                      服务状态
"""

import json
import re
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
API_HOST = "127.0.0.1"


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
        """启动 HTTP server, 监听 127.0.0.1:8899."""
        try:
            from com.sun.net.httpserver import HttpServer
            from java.net import InetSocketAddress

            server = HttpServer.create(InetSocketAddress(API_HOST, API_PORT), 0)
            server.createContext("/", _JythonHandler(self))
            server.setExecutor(None)
            server.start()
            self.server = server
            print("[API] HTTP server started on {}:{}".format(API_HOST, API_PORT))
        except ImportError:
            # CPython fallback
            self._start_cpython()

    def _start_cpython(self):
        """CPython 环境的 HTTP server (用于测试)."""
        import threading
        from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

        api_service = self

        class CPythonHandler(BaseHTTPRequestHandler):
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

        self._handler_cls = CPythonHandler
        self._httpd = HTTPServer((API_HOST, API_PORT), CPythonHandler)
        t = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        t.start()
        self.server = self._httpd
        print("[API] HTTP server started (CPython) on {}:{}".format(API_HOST, API_PORT))

    def stop(self):
        """停止 HTTP server."""
        if self.server:
            try:
                if hasattr(self.server, "stop"):
                    self.server.stop(0)
                elif hasattr(self.server, "shutdown"):
                    self.server.shutdown()
            except Exception as e:
                print("[API] Error stopping server: " + str(e))
            self.server = None

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
            ("POST",   r"/api/action/extract-params$",         "_handle_action_extract"),
            ("POST",   r"/api/action/generate-attacks$",      "_handle_action_generate"),
            ("POST",   r"/api/action/auto-idor$",             "_handle_action_auto_idor"),
            ("POST",   r"/api/action/batch-attack-get$",       "_handle_action_batch"),
            ("GET",    r"/api/attacks$",                       "_handle_get_attacks"),
            ("GET",    r"/api/attacks/(\d+)$",                 "_handle_get_attack_detail"),
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
                elif handler_name == "_handle_get_attack_detail":
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
        """设置用户标识字符串."""
        user_id = params["user_id"]
        identify_string = body.get("identify_string", "")
        cm = self.config_manager
        # 获取现有用户或创建新用户
        user = cm.get_user_by_id(user_id)
        if user:
            cm.save_user(user_id, user.get("name", "User " + str(user_id)),
                         identify_string, user.get("headers_text", ""))
        else:
            cm.save_user(user_id, "User " + str(user_id), identify_string, "")
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
        # 同步到 GUI
        ext = self.extender
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
            ext.attack_engine.generate_attacks(hidden_param_config)
            self.config_manager.notify_attacks_changed()
            return self._ok(message="Attacks generated")
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
            llm_config = cm = self.config_manager.get_llm_config()
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
    # GET /api/attacks
    # ------------------------------------------------------------------
    def _handle_get_attacks(self, params, query, body):
        """查询攻击结果列表."""
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

        limit = int(query.get("limit", "100"))

        where_clause = " WHERE " + " AND ".join(conditions) if conditions else ""
        sql = (
            "SELECT a.id, r.method, r.path, a.status, a.response_code, "
            "a.vulnerability_score, a.llm_verification_result, a.payload_description, a.verified "
            "FROM attack_queue a "
            "JOIN raw_requests r ON a.original_request_id = r.id" +
            where_clause +
            " ORDER BY a.verified DESC, a.id DESC LIMIT ?"
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
            })

        return self._ok({"attacks": attacks, "total": len(attacks)})

    # ------------------------------------------------------------------
    # GET /api/attacks/{id}
    # ------------------------------------------------------------------
    def _handle_get_attack_detail(self, params, query, body):
        """查询单个攻击详情."""
        db = self.db_manager
        if not db:
            return self._error("Database not available")

        attack_id = params["id"]
        sql = (
            "SELECT a.id, r.method, r.path, r.host, r.url, a.status, a.response_code, "
            "a.vulnerability_score, a.llm_verification_result, a.payload_description, a.verified, "
            "a.executed_request_data, a.attack_response, r.request_data, r.response_data "
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
            "original_request": row[13] if row[13] else "",
            "original_response": row[14] if row[14] else "",
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
                "SELECT DISTINCT param_value, endpoint, user_identifier "
                "FROM parameter_pool WHERE param_key = ? AND location = ? "
                "ORDER BY id DESC LIMIT 20"
            )
            rows = db.fetch_all(sql, [key, loc])
        else:
            sql = (
                "SELECT DISTINCT param_value, endpoint, user_identifier "
                "FROM parameter_pool WHERE param_key = ? "
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


# ----------------------------------------------------------------------------
# Jython HttpHandler 包装
# ----------------------------------------------------------------------------
try:
    from com.sun.net.httpserver import HttpHandler, HttpExchange

    class _JythonHandler(HttpHandler):
        """
        Jython 的 HttpHandler 实现.
        将 Java HttpExchange 转换为 Python 方法调用.
        """

        def __init__(self, api_service):
            self._api = api_service

        def handle(self, exchange):
            """处理 HTTP 请求."""
            try:
                self._process(exchange)
            except Exception as e:
                print("[API] Handler error: " + str(e))
                try:
                    error = json.dumps({"status": "error", "message": str(e)})
                    exchange.sendResponseHeaders(500, len(error))
                    os = exchange.getResponseBody()
                    os.write(error)
                    os.close()
                except:
                    pass

        def _process(self, exchange):
            """实际请求处理逻辑."""
            method = exchange.getRequestMethod()
            uri = exchange.getRequestURI()
            path = uri.getPath()
            query_str = uri.getQuery() or ""

            # 解析 query params
            query_params = {}
            if query_str:
                for pair in query_str.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        query_params[k] = v

            # 读取 body
            body = None
            if method in ("POST", "PUT", "DELETE"):
                in_stream = exchange.getRequestBody()
                body_bytes = in_stream.read()
                in_stream.close()
                if body_bytes:
                    try:
                        body = json.loads(body_bytes)
                    except:
                        body = {}

            # 调用核心路由
            status, response = self._api.handle_request(method, path, query_params, body)
            response_bytes = json.dumps(response)

            # 发送响应
            exchange.getResponseHeaders().set("Content-Type", "application/json")
            exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*")
            exchange.sendResponseHeaders(status, len(response_bytes))
            out = exchange.getResponseBody()
            out.write(response_bytes)
            out.close()

except ImportError:
    _JythonHandler = None
