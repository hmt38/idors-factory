#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
IDORs Factory API 单元测试.

在 CPython 环境运行: python -m pytest tests/test_api.py -v
或: python tests/test_api.py

测试覆盖:
  1. ConfigManager: get/set/get_bool/get_llm_config/get_blacklist_set/users/match_replace_rules
  2. ApiService: 路由分发/handle_request 核心方法
"""

import os
import sys
import json
import sqlite3
import unittest

# 将项目根目录加入 sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


# ----------------------------------------------------------------------------
# MockDatabaseManager — 用 sqlite3 内存数据库模拟 DatabaseManager
# ----------------------------------------------------------------------------
class MockDatabaseManager(object):
    """模拟 DatabaseManager, 用 sqlite3 :memory: 数据库."""

    def __init__(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = None
        self.extender = None
        self._init_tables()

    def _init_tables(self):
        """创建所有需要的表."""
        c = self.conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, identify_string TEXT, headers_text TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS match_replace_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, rule_type TEXT, match_text TEXT, replace_text TEXT)")
        c.execute("""CREATE TABLE IF NOT EXISTS raw_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT, method TEXT, host TEXT, url TEXT, path TEXT,
            query_params TEXT, body TEXT, headers TEXT, user_identifier TEXT,
            is_analyzed INTEGER DEFAULT 0, request_data BLOB, response_data BLOB,
            response_headers TEXT, response_body BLOB,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS parameter_pool (
            id INTEGER PRIMARY KEY AUTOINCREMENT, api_signature TEXT,
            param_name TEXT, param_value TEXT, location TEXT,
            user_identifier TEXT, risk_score INTEGER DEFAULT 0,
            llm_analysis_result TEXT,
            UNIQUE(api_signature, param_name, user_identifier)
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS attack_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT, original_request_id INTEGER,
            target_user TEXT, payload_description TEXT, request_data TEXT,
            status TEXT DEFAULT 'PENDING', response_data TEXT, response_code INTEGER,
            vulnerability_score INTEGER DEFAULT 0, llm_verification_result TEXT,
            verified BOOLEAN DEFAULT 0, executed_request_data TEXT,
            ai_verification_result TEXT, ai_verified BOOLEAN DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        c.execute("CREATE TABLE IF NOT EXISTS api_metadata (api_signature TEXT PRIMARY KEY, is_sensitive BOOLEAN, risk_reason TEXT, analyzed_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        self.conn.commit()

    def fetch_all(self, query, params=None, retries=1):
        """执行 SELECT 查询, 返回行列表."""
        try:
            c = self.conn.cursor()
            if params:
                c.execute(query, params)
            else:
                c.execute(query)
            rows = c.fetchall()
            c.close()
            return rows if rows is not None else []
        except Exception as e:
            print("[MockDB] fetch_all error: " + str(e))
            return None

    def execute_query(self, query, params=None, commit=True, retries=1):
        """执行 INSERT/UPDATE/DELETE, 返回 True/False."""
        try:
            c = self.conn.cursor()
            if params:
                c.execute(query, params)
            else:
                c.execute(query)
            self.conn.commit()
            c.close()
            return True
        except Exception as e:
            print("[MockDB] execute_query error: " + str(e))
            return False

    def clear_all_data(self):
        """清空流量/攻击/参数数据, 保留 config/users/rules."""
        try:
            c = self.conn.cursor()
            c.execute("DELETE FROM attack_queue")
            c.execute("DELETE FROM parameter_pool")
            c.execute("DELETE FROM raw_requests")
            c.execute("DELETE FROM api_metadata")
            try:
                c.execute("DELETE FROM sqlite_sequence")
            except Exception:
                pass  # sqlite_sequence 可能不存在
            self.conn.commit()
            c.close()
            return True
        except Exception as e:
            print("[MockDB] clear_all_data error: " + str(e))
            return False


# ----------------------------------------------------------------------------
# MockExtender — 模拟 extender 对象
# ----------------------------------------------------------------------------
class MockExtender(object):
    """模拟 extender, 提供 ApiService 所需的属性."""

    def __init__(self, db_manager):
        self.db_manager = db_manager
        self._callbacks = None
        self._helpers = None
        self.extractor = None
        self.attack_engine = None
        self.scheduler = None
        self.intercept = 0


# ----------------------------------------------------------------------------
# MockAttackEngine — 模拟 AttackEngine (用于 prune/ai_verify/ai_create_poc 测试)
# ----------------------------------------------------------------------------
class MockAttackEngine(object):
    """模拟 AttackEngine 的三个 AI 辅助方法."""

    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.prune_calls = []
        self.verify_calls = []
        self.create_poc_calls = []

    def prune_attacks(self, llm_config=None, limit=50, score_threshold=30):
        """模拟剪枝: 获取 PENDING 攻击, 返回剪枝结果."""
        self.prune_calls.append({
            "llm_config": llm_config,
            "limit": limit,
            "score_threshold": score_threshold,
        })
        rows = self.db_manager.fetch_all(
            "SELECT id, payload_description FROM attack_queue WHERE status = 'PENDING' LIMIT ?",
            [int(limit)],
        )
        if not rows:
            return {"total": 0, "pruned": 0, "remaining": 0, "details": [], "pruned_ids": []}

        total = len(rows)
        pruned_ids = []
        details = []
        for row in rows:
            aid = row[0]
            desc = row[1] or ""
            # 简单启发式: 包含 "99999" 的视为低价值
            should_prune = "99999" in desc
            score = 20 if should_prune else 70
            details.append({
                "attack_id": aid,
                "score": score,
                "reason": "test heuristic",
                "pruned": should_prune,
                "payload": desc,
            })
            if should_prune:
                pruned_ids.append(aid)

        for aid in pruned_ids:
            self.db_manager.execute_query(
                "DELETE FROM attack_queue WHERE id = ?",
                [aid],
            )

        return {
            "total": total,
            "pruned": len(pruned_ids),
            "remaining": total - len(pruned_ids),
            "pruned_ids": pruned_ids,
            "details": details,
        }

    def ai_verify_attack(self, attack_id, llm_config=None, callbacks=None, helpers=None, extra_context=None):
        """模拟 AI 验证: 返回一个 VULNERABLE 结果."""
        self.verify_calls.append({
            "attack_id": attack_id,
            "llm_config": llm_config,
            "extra_context": extra_context,
        })
        result = {
            "result": "VULNERABLE",
            "confidence": 0.95,
            "reason": "Mock AI verified: business data returned",
            "verified": True,
            "source": "ai_agent",
        }
        ai_result_str = json.dumps(result)
        self.db_manager.execute_query(
            "UPDATE attack_queue SET ai_verification_result = ?, ai_verified = 1, status = ? WHERE id = ?",
            [ai_result_str, "VULNERABLE", attack_id],
        )
        return {
            "attack_id": attack_id,
            "ai_result": result,
            "new_status": "VULNERABLE",
            "payload": "",
        }

    def ai_create_poc(self, request_id, modifications=None, llm_config=None, target_user=None):
        """模拟 AI POC 生成: 基于 modifications 创建攻击条目."""
        self.create_poc_calls.append({
            "request_id": request_id,
            "modifications": modifications,
            "llm_config": llm_config,
            "target_user": target_user,
        })

        if not modifications:
            # 模拟 LLM 生成的修改
            modifications = [
                {
                    "param": "user_id",
                    "original_value": "10086",
                    "new_value": "10087",
                    "location": "QUERY",
                    "reason": "AI: swap to user 2",
                }
            ]

        created_ids = []
        for mod in modifications:
            param_name = mod.get("param", "")
            new_value = mod.get("new_value", "")
            location = mod.get("location", "QUERY")
            reason = mod.get("reason", "")
            desc = "[AI] Swap {} ({}): ?->{} | {}".format(location, param_name, new_value, reason)

            self.db_manager.execute_query(
                "INSERT INTO attack_queue (original_request_id, target_user, payload_description, request_data, status, vulnerability_score) VALUES (?, ?, ?, ?, 'PENDING', 40)",
                [request_id, target_user or "AI-Generated", desc, "{}", ],
            )
            rows = self.db_manager.fetch_all("SELECT last_insert_rowid() as id")
            if rows:
                created_ids.append(rows[0][0])

        return {
            "generated": len(created_ids),
            "attack_ids": created_ids,
            "modifications": modifications,
        }


# ----------------------------------------------------------------------------
# 测试用例
# ----------------------------------------------------------------------------
class TestConfigManager(unittest.TestCase):
    """ConfigManager 单元测试."""

    @classmethod
    def setUpClass(cls):
        """所有测试前重置单例."""
        from api.config_manager import ConfigManager
        ConfigManager._instance = None

    def setUp(self):
        """每个测试前创建新的 ConfigManager."""
        from api.config_manager import ConfigManager
        ConfigManager._instance = None
        self.db = MockDatabaseManager()
        self.cm = ConfigManager(self.db)

    def test_01_get_default(self):
        """测试读取默认值."""
        self.assertEqual(self.cm.get("blacklist_params"), "limit,offset")
        # 默认开启 LLM, 但只启用 analyze_result
        self.assertTrue(self.cm.get_bool("enable_llm"))
        self.assertEqual(self.cm.get("llm_model"), "gpt-3.5-turbo")
        # 默认关闭 extract_params / generate_values / identify_risk
        self.assertFalse(self.cm.get_bool("llm_extract_params"))
        self.assertFalse(self.cm.get_bool("llm_generate_values"))
        self.assertFalse(self.cm.get_bool("llm_identify_risk"))
        # analyze_result 默认开启
        self.assertTrue(self.cm.get_bool("llm_analyze_result"))
        # enabled = enable_llm AND analyze_result => True
        config = self.cm.get_llm_config()
        self.assertTrue(config["enabled"])
        self.assertTrue(config["analyze_result"])
        self.assertFalse(config["extract_params"])

    def test_02_set_and_get(self):
        """测试设置和读取配置."""
        self.cm.set("llm_base_url", "https://api.deepseek.com/v1")
        self.assertEqual(self.cm.get("llm_base_url"), "https://api.deepseek.com/v1")

        self.cm.set_bool("enable_llm", True)
        self.assertTrue(self.cm.get_bool("enable_llm"))

        self.cm.set_int("autorize_intercept", 1)
        self.assertEqual(self.cm.get_int("autorize_intercept"), 1)

    def test_03_persistence(self):
        """测试配置持久化到 DB."""
        self.cm.set("llm_api_key", "sk-test-12345678")
        # 从 DB 直接读取验证
        rows = self.db.fetch_all("SELECT value FROM config WHERE key = ?", ["llm_api_key"])
        self.assertIsNotNone(rows)
        self.assertEqual(rows[0][0], "sk-test-12345678")

    def test_04_get_llm_config(self):
        """测试获取 LLM 配置 dict."""
        self.cm.set_bool("enable_llm", True)
        self.cm.set_bool("llm_analyze_result", True)
        self.cm.set("llm_base_url", "https://api.test.com")
        self.cm.set("llm_api_key", "sk-test12345678")
        config = self.cm.get_llm_config()
        self.assertTrue(config["enabled"])
        self.assertEqual(config["base_url"], "https://api.test.com")
        self.assertTrue(config["verify_ssl"])

    def test_05_get_blacklist_set(self):
        """测试获取黑名单 set."""
        self.cm.set("blacklist_params", "limit,offset,page,size")
        bl = self.cm.get_blacklist_set()
        self.assertIn("limit", bl)
        self.assertIn("page", bl)
        self.assertEqual(len(bl), 4)

    def test_06_save_and_get_user(self):
        """测试保存和读取用户."""
        self.cm.save_user(1, "User 1", "Cookie: session=hmt1", "Header: X-User=1")
        user = self.cm.get_user_by_id(1)
        self.assertIsNotNone(user)
        self.assertEqual(user["name"], "User 1")
        self.assertEqual(user["identify_string"], "Cookie: session=hmt1")

    def test_07_match_replace_rules(self):
        """测试 Match/Replace 规则."""
        rule_id = self.cm.save_match_replace_rule(1, "Header Add/Set:", "Cookie", "session=hmt1")
        self.assertIsNotNone(rule_id)
        rules = self.cm.get_match_replace_rules(1)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["match_text"], "Cookie")

    def test_08_upsert_header(self):
        """测试 header upsert 语义."""
        # 新增
        self.cm.upsert_user_header(1, "X-Token", "abc123")
        rules = self.cm.get_match_replace_rules(1)
        self.assertEqual(len(rules), 1)

        # 更新 (不新增)
        self.cm.upsert_user_header(1, "X-Token", "xyz789")
        rules = self.cm.get_match_replace_rules(1)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["replace_text"], "xyz789")

    def test_09_version_numbers(self):
        """测试版本号自增."""
        v1 = self.cm.get_config_version()
        self.cm.set("blacklist_params", "test")
        v2 = self.cm.get_config_version()
        self.assertGreater(v2, v1)

        self.cm.notify_attacks_changed()
        self.assertGreater(self.cm.get_attacks_version(), 0)


class TestApiService(unittest.TestCase):
    """ApiService 路由分发和 handler 测试."""

    @classmethod
    def setUpClass(cls):
        from api.config_manager import ConfigManager
        ConfigManager._instance = None

    def setUp(self):
        from api.config_manager import ConfigManager
        from api.http_server import ApiService
        ConfigManager._instance = None
        self.db = MockDatabaseManager()
        self.cm = ConfigManager(self.db)
        self.extender = MockExtender(self.db)
        self.extender.attack_engine = MockAttackEngine(self.db)
        self.api = ApiService(self.extender)

    def _request(self, method, path, body=None, query=None):
        """辅助方法: 调用 handle_request."""
        if query is None:
            query = {}
        status, resp = self.api.handle_request(method, path, query, body)
        return status, resp

    def test_01_status(self):
        """GET /api/status."""
        status, resp = self._request("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(resp["status"], "ok")
        self.assertTrue(resp["data"]["running"])

    def test_02_get_config(self):
        """GET /api/config."""
        status, resp = self._request("GET", "/api/config")
        self.assertEqual(status, 200)
        self.assertIn("llm", resp["data"])
        self.assertIn("users", resp["data"])
        self.assertIn("blacklist_params", resp["data"])

    def test_03_put_llm_config(self):
        """PUT /api/config/llm."""
        status, resp = self._request("PUT", "/api/config/llm", body={
            "enable": True,
            "base_url": "https://api.test.com",
            "api_key": "sk-test12345678",
            "model": "gpt-4",
        })
        self.assertEqual(status, 200)
        # 验证写入
        self.assertTrue(self.cm.get_bool("enable_llm"))
        self.assertEqual(self.cm.get("llm_model"), "gpt-4")

    def test_04_put_blacklist(self):
        """PUT /api/config/blacklist."""
        status, resp = self._request("PUT", "/api/config/blacklist", body={
            "params": "limit,offset,page"
        })
        self.assertEqual(status, 200)
        self.assertIn("page", self.cm.get_blacklist_set())

    def test_05_put_user_identify(self):
        """PUT /api/config/user/1/identify."""
        status, resp = self._request("PUT", "/api/config/user/1/identify", body={
            "identify_string": "Cookie: session=hmt1"
        })
        self.assertEqual(status, 200)
        user = self.cm.get_user_by_id(1)
        self.assertIsNotNone(user)
        self.assertEqual(user["identify_string"], "Cookie: session=hmt1")

    def test_06_upsert_header(self):
        """POST /api/user/1/header."""
        status, resp = self._request("POST", "/api/user/1/header", body={
            "key": "X-Token", "value": "abc123"
        })
        self.assertEqual(status, 200)
        rules = self.cm.get_match_replace_rules(1)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["match_text"], "X-Token")

    def test_07_upsert_cookie(self):
        """POST /api/user/1/cookie."""
        status, resp = self._request("POST", "/api/user/1/cookie", body={
            "value": "session=hmt1"
        })
        self.assertEqual(status, 200)
        rules = self.cm.get_match_replace_rules(1)
        self.assertEqual(len(rules), 1)

    def test_08_delete_header(self):
        """DELETE /api/user/1/header/X-Token."""
        # 先创建
        self.cm.upsert_user_header(1, "X-Token", "abc123")
        # 删除
        status, resp = self._request("DELETE", "/api/user/1/header/X-Token")
        self.assertEqual(status, 200)
        rules = self.cm.get_match_replace_rules(1)
        self.assertEqual(len(rules), 0)

    def test_09_recommend(self):
        """POST /api/recommend."""
        # 先写入测试数据
        self.db.execute_query(
            "INSERT INTO parameter_pool (api_signature, param_name, param_value, location, user_identifier) VALUES (?, ?, ?, ?, ?)",
            ["/api/users/10086", "user_id", "10086", "QUERY", "User 2"]
        )
        status, resp = self._request("POST", "/api/recommend", body={
            "key": "user_id", "location": "Query"
        })
        self.assertEqual(status, 200)
        recs = resp["data"]["recommendations"]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["value"], "10086")

    def test_10_recommend_apply(self):
        """POST /api/recommend/apply."""
        status, resp = self._request("POST", "/api/recommend/apply", body={
            "user_id": 1, "key": "user_id", "value": "10086", "location": "Query"
        })
        self.assertEqual(status, 200)
        rules = self.cm.get_match_replace_rules(1)
        self.assertEqual(len(rules), 1)

    def test_11_get_attacks(self):
        """GET /api/attacks - 验证返回包含 ai_verified 字段."""
        # 先写入测试数据
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path) VALUES (?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/1", "/api/users/1"]
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (id, original_request_id, status, response_code, vulnerability_score, verified, ai_verified, ai_verification_result) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [1, 1, "VULNERABLE", 200, 85, 0, 1, '{"result":"VULNERABLE","confidence":0.95}']
        )
        status, resp = self._request("GET", "/api/attacks")
        self.assertEqual(status, 200)
        attacks = resp["data"]["attacks"]
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0]["status"], "VULNERABLE")
        self.assertTrue(attacks[0]["ai_verified"])
        self.assertIn("ai_verification_result", attacks[0])

    def test_12_get_attack_detail(self):
        """GET /api/attacks/1 - 验证返回包含 ai_verification 和 request_data 字段."""
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path, headers, body, response_headers, response_body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/1", "/api/users/1", '["GET /api/users/1 HTTP/1.1"]', "", '["HTTP/1.1 200 OK"]', '{"data":"ok"}']
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (id, original_request_id, status, response_code, ai_verified, ai_verification_result, request_data) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [1, 1, "VULNERABLE", 200, 1, '{"result":"VULNERABLE"}', '{"method":"GET"}']
        )
        status, resp = self._request("GET", "/api/attacks/1")
        self.assertEqual(status, 200)
        self.assertEqual(resp["data"]["status"], "VULNERABLE")
        self.assertTrue(resp["data"]["ai_verified"])
        self.assertIn("ai_verification_result", resp["data"])
        self.assertIn("request_data", resp["data"])
        self.assertIn("original_request_headers", resp["data"])
        self.assertIn("original_response_body", resp["data"])

    def test_13_404_not_found(self):
        """测试未知路由返回 404."""
        status, resp = self._request("GET", "/api/unknown")
        self.assertEqual(status, 404)

    def test_14_action_autorize(self):
        """POST /api/action/autorize."""
        status, resp = self._request("POST", "/api/action/autorize", body={"on": True})
        self.assertEqual(status, 200)
        self.assertEqual(self.cm.get_int("autorize_intercept"), 1)

    def test_15_action_auto_idor(self):
        """POST /api/action/auto-idor."""
        status, resp = self._request("POST", "/api/action/auto-idor", body={"enable": True})
        self.assertEqual(status, 200)
        self.assertTrue(self.cm.get_bool("auto_idor_enabled"))

    # ------------------------------------------------------------------
    # Feature 1: AI 剪枝 - 删除攻击
    # ------------------------------------------------------------------
    def test_16_delete_attack(self):
        """DELETE /api/attacks/{id} - 删除单个攻击."""
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path) VALUES (?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/1", "/api/users/1"]
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (id, original_request_id, status) VALUES (?, ?, ?)",
            [1, 1, "PENDING"]
        )
        status, resp = self._request("DELETE", "/api/attacks/1")
        self.assertEqual(status, 200)
        self.assertEqual(resp["data"]["deleted_id"], 1)
        # 确认已删除
        rows = self.db.fetch_all("SELECT id FROM attack_queue WHERE id = ?", [1])
        self.assertEqual(len(rows), 0)

    def test_17_delete_attack_not_found(self):
        """DELETE /api/attacks/999 - 不存在的攻击返回 404."""
        status, resp = self._request("DELETE", "/api/attacks/999")
        self.assertEqual(status, 404)

    def test_18_delete_attack_sent_blocked(self):
        """DELETE /api/attacks/{id} - 不允许删除 SENT 状态的攻击."""
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path) VALUES (?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/1", "/api/users/1"]
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (id, original_request_id, status) VALUES (?, ?, ?)",
            [1, 1, "SENT"]
        )
        status, resp = self._request("DELETE", "/api/attacks/1")
        self.assertEqual(status, 400)

    def test_19_prune_attacks(self):
        """POST /api/action/prune-attacks - AI 剪枝."""
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path) VALUES (?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/1", "/api/users/1"]
        )
        # 插入 3 个 PENDING 攻击, 其中 1 个包含 99999 (低价值)
        self.db.execute_query(
            "INSERT INTO attack_queue (original_request_id, status, payload_description) VALUES (?, ?, ?)",
            [1, "PENDING", "Swap user_id: 1->99999"]
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (original_request_id, status, payload_description) VALUES (?, ?, ?)",
            [1, "PENDING", "Swap user_id: 1->2"]
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (original_request_id, status, payload_description) VALUES (?, ?, ?)",
            [1, "PENDING", "Swap order_id: 100->200"]
        )
        status, resp = self._request("POST", "/api/action/prune-attacks", body={
            "limit": 50,
            "score_threshold": 30,
            "use_llm": False,  # 使用启发式 (MockAttackEngine)
        })
        self.assertEqual(status, 200)
        data = resp["data"]
        self.assertEqual(data["total"], 3)
        self.assertEqual(data["pruned"], 1)
        self.assertEqual(data["remaining"], 2)
        self.assertEqual(len(data["pruned_ids"]), 1)

    # ------------------------------------------------------------------
    # Feature 2: AI 越权验证
    # ------------------------------------------------------------------
    def test_20_ai_verify_attack(self):
        """POST /api/action/ai-verify - AI 越权验证."""
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path, headers, body, response_headers, response_body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/1", "/api/users/1", '["GET / HTTP/1.1"]', "", '["HTTP/1.1 200 OK"]', '{"id":1}']
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (id, original_request_id, status, executed_request_data, response_data, payload_description) VALUES (?, ?, ?, ?, ?, ?)",
            [1, 1, "SENT", "GET /api/users/2 HTTP/1.1", "HTTP/1.1 200 OK\n\n{\"id\":2}", "Swap user_id: 1->2"]
        )
        status, resp = self._request("POST", "/api/action/ai-verify", body={
            "attack_id": 1,
            "extra_context": "This is a sensitive API that returns user profile data",
        })
        self.assertEqual(status, 200)
        data = resp["data"]
        self.assertEqual(data["attack_id"], 1)
        self.assertEqual(data["ai_result"]["result"], "VULNERABLE")
        self.assertEqual(data["new_status"], "VULNERABLE")
        # 验证数据库已回写
        rows = self.db.fetch_all(
            "SELECT ai_verified, ai_verification_result, status FROM attack_queue WHERE id = ?",
            [1]
        )
        self.assertTrue(bool(rows[0][0]))
        self.assertIn("VULNERABLE", rows[0][1])
        self.assertEqual(rows[0][2], "VULNERABLE")

    def test_21_ai_verify_already_verified(self):
        """POST /api/action/ai-verify - 已验证过的攻击返回已有结果."""
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path) VALUES (?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/1", "/api/users/1"]
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (id, original_request_id, ai_verified, ai_verification_result) VALUES (?, ?, ?, ?)",
            [1, 1, 1, '{"result":"SAFE","confidence":0.9}']
        )
        status, resp = self._request("POST", "/api/action/ai-verify", body={
            "attack_id": 1,
        })
        self.assertEqual(status, 200)
        self.assertTrue(resp["data"]["already_verified"])

    def test_22_ai_verify_force_reverify(self):
        """POST /api/action/ai-verify - force_reverify=true 强制重新验证."""
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path, headers, body, response_headers, response_body) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/1", "/api/users/1", '["GET / HTTP/1.1"]', "", '["HTTP/1.1 200 OK"]', '{"id":1}']
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (id, original_request_id, ai_verified, ai_verification_result, status, executed_request_data, response_data) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [1, 1, 1, '{"result":"SAFE"}', "SENT", "GET /api/users/2", "HTTP/1.1 200 OK\n\n{\"id\":2}"]
        )
        status, resp = self._request("POST", "/api/action/ai-verify", body={
            "attack_id": 1,
            "force_reverify": True,
        })
        self.assertEqual(status, 200)
        self.assertNotIn("already_verified", resp["data"])
        self.assertEqual(resp["data"]["ai_result"]["result"], "VULNERABLE")

    def test_23_ai_verify_missing_attack_id(self):
        """POST /api/action/ai-verify - 缺少 attack_id 返回 400."""
        status, resp = self._request("POST", "/api/action/ai-verify", body={})
        self.assertEqual(status, 400)

    # ------------------------------------------------------------------
    # Feature 3: AI POC 生成
    # ------------------------------------------------------------------
    def test_24_ai_generate_poc_with_modifications(self):
        """POST /api/action/ai-generate-poc - 带手动 modifications."""
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path, headers, query_params, body, user_identifier) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/10086", "/api/users/10086",
             '["GET /api/users/10086 HTTP/1.1"]', '{"user_id":"10086"}', "", "User 1"]
        )
        status, resp = self._request("POST", "/api/action/ai-generate-poc", body={
            "request_id": 1,
            "modifications": [
                {
                    "param": "user_id",
                    "original_value": "10086",
                    "new_value": "10087",
                    "location": "QUERY",
                    "reason": "swap to user 2",
                }
            ],
            "target_user": "User 2",
        })
        self.assertEqual(status, 200)
        data = resp["data"]
        self.assertEqual(data["generated"], 1)
        self.assertEqual(len(data["attack_ids"]), 1)
        # 验证攻击已入队
        rows = self.db.fetch_all(
            "SELECT status, target_user, payload_description FROM attack_queue WHERE original_request_id = ?",
            [1]
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "PENDING")
        self.assertEqual(rows[0][1], "User 2")
        self.assertIn("user_id", rows[0][2])

    def test_25_ai_generate_poc_auto_generate(self):
        """POST /api/action/ai-generate-poc - 不传 modifications, 使用 MockAttackEngine 自动生成."""
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path, headers, query_params, body, user_identifier) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/10086", "/api/users/10086",
             '["GET /api/users/10086 HTTP/1.1"]', '{"user_id":"10086"}', "", "User 1"]
        )
        status, resp = self._request("POST", "/api/action/ai-generate-poc", body={
            "request_id": 1,
            "use_llm": False,  # MockAttackEngine 会生成默认 modifications
        })
        self.assertEqual(status, 200)
        data = resp["data"]
        self.assertEqual(data["generated"], 1)
        self.assertEqual(data["modifications"][0]["param"], "user_id")

    def test_26_ai_generate_poc_missing_request_id(self):
        """POST /api/action/ai-generate-poc - 缺少 request_id 返回 400."""
        status, resp = self._request("POST", "/api/action/ai-generate-poc", body={
            "modifications": [{"param": "user_id", "new_value": "10087", "location": "QUERY"}],
        })
        self.assertEqual(status, 400)

    def test_27_get_attacks_filter_ai_verified(self):
        """GET /api/attacks?ai_verified=true - 过滤 AI 验证过的攻击."""
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path) VALUES (?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/1", "/api/users/1"]
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (id, original_request_id, status, ai_verified) VALUES (?, ?, ?, ?)",
            [1, 1, "VULNERABLE", 1]
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (id, original_request_id, status, ai_verified) VALUES (?, ?, ?, ?)",
            [2, 1, "SENT", 0]
        )
        status, resp = self._request("GET", "/api/attacks", query={"ai_verified": "true"})
        self.assertEqual(status, 200)
        attacks = resp["data"]["attacks"]
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0]["id"], 1)
        self.assertTrue(attacks[0]["ai_verified"])

    # ------------------------------------------------------------------
    # 流量自动识别 + 缓存刷新 + AI agent 自定义 header
    # ------------------------------------------------------------------
    def test_28_auto_detect_user_identifier(self):
        """测试 auto_detect_user_identifier 自动检测常见认证 headers."""
        from helpers.traffic_identity import auto_detect_user_identifier
        # Cookie 优先级最高
        headers_str = "GET / HTTP/1.1\nHost: example.com\nCookie: session=abc123"
        result = auto_detect_user_identifier(headers_str)
        self.assertIsNotNone(result)
        self.assertIn("auto:Cookie:", result)
        self.assertIn("abc123", result)

        # X-Auth-Token
        headers_str2 = "GET / HTTP/1.1\nX-Auth-Token: token_xyz789"
        result2 = auto_detect_user_identifier(headers_str2)
        self.assertIsNotNone(result2)
        self.assertIn("auto:X-Auth-Token:", result2)

        # Authorization
        headers_str3 = "GET / HTTP/1.1\nAuthorization: Bearer jwt_token_here"
        result3 = auto_detect_user_identifier(headers_str3)
        self.assertIsNotNone(result3)
        self.assertIn("auto:Authorization:", result3)

        # 无认证 header
        headers_str4 = "GET / HTTP/1.1\nHost: example.com\nUser-Agent: test"
        result4 = auto_detect_user_identifier(headers_str4)
        self.assertIsNone(result4)

    def test_29_refresh_traffic_identity(self):
        """POST /api/action/refresh-traffic-identity - 刷新缓存流量的用户标识."""
        # 1. 先插入一条 auto: 检测的缓存流量
        cookie_val = "session=eyJ1c2VyIjoiYWdlbnQxIn0.test"
        headers_json = json.dumps([
            "GET /api/profile HTTP/1.1",
            "Host: test.com",
            "Cookie: " + cookie_val,
        ])
        self.db.execute_query(
            "INSERT INTO raw_requests (method, host, url, path, headers, user_identifier) VALUES (?, ?, ?, ?, ?, ?)",
            ["GET", "test.com", "http://test.com/api/profile", "/api/profile",
             headers_json, "auto:Cookie:" + cookie_val[:40]]
        )
        # 2. 配置 user-identify 映射
        self.cm.save_user(1, "User 1", "Cookie: " + cookie_val, "")

        # 3. 调用刷新
        status, resp = self._request("POST", "/api/action/refresh-traffic-identity", body={})
        self.assertEqual(status, 200)
        data = resp["data"]
        self.assertGreaterEqual(data["total_cached"], 1)
        self.assertGreaterEqual(data["refreshed"], 1)

        # 4. 验证 DB 已更新
        rows = self.db.fetch_all(
            "SELECT user_identifier FROM raw_requests WHERE headers LIKE ?",
            ["%" + cookie_val + "%"]
        )
        self.assertIsNotNone(rows)
        self.assertEqual(rows[0][0], "User 1")

    def test_30_refresh_identity_dry_run(self):
        """POST /api/action/refresh-traffic-identity - dry_run 不实际更新."""
        cookie_val = "session=dry_run_test"
        headers_json = json.dumps([
            "GET /api/data HTTP/1.1",
            "Cookie: " + cookie_val,
        ])
        self.db.execute_query(
            "INSERT INTO raw_requests (method, host, url, path, headers, user_identifier) VALUES (?, ?, ?, ?, ?, ?)",
            ["GET", "test.com", "http://test.com/api/data", "/api/data",
             headers_json, "auto:Cookie:" + cookie_val[:40]]
        )
        self.cm.save_user(1, "User 1", "Cookie: " + cookie_val, "")

        status, resp = self._request("POST", "/api/action/refresh-traffic-identity", body={
            "dry_run": True
        })
        self.assertEqual(status, 200)
        self.assertTrue(resp["data"]["dry_run"])
        self.assertGreaterEqual(resp["data"]["refreshed"], 1)
        # dry_run 不应实际更新
        rows = self.db.fetch_all(
            "SELECT user_identifier FROM raw_requests WHERE user_identifier LIKE 'auto:%' AND headers LIKE ?",
            ["%" + cookie_val + "%"]
        )
        self.assertIsNotNone(rows)
        self.assertTrue(rows[0][0].startswith("auto:"))

    def test_31_refresh_identity_no_mappings(self):
        """POST /api/action/refresh-traffic-identity - 无映射配置时返回 0."""
        status, resp = self._request("POST", "/api/action/refresh-traffic-identity", body={})
        self.assertEqual(status, 200)
        self.assertEqual(resp["data"]["total_cached"], 0)

    def test_32_ai_agent_replace_existing_header(self):
        """POST /api/user/1/header - AI agent 自定义已存在的 header (upsert 替换)."""
        # 先添加一个 header
        self.cm.upsert_user_header(1, "Authorization", "Bearer old_token")
        rules = self.cm.get_match_replace_rules(1)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["replace_text"], "Bearer old_token")

        # AI agent 替换已存在的同名 header
        status, resp = self._request("POST", "/api/user/1/header", body={
            "key": "Authorization", "value": "Bearer new_hijacked_token"
        })
        self.assertEqual(status, 200)
        # 验证是 upsert (不新增, 而是更新)
        rules = self.cm.get_match_replace_rules(1)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["replace_text"], "Bearer new_hijacked_token")
        self.assertEqual(rules[0]["match_text"], "Authorization")

    def test_33_llm_default_only_analyze_result(self):
        """测试 LLM 默认配置: 只开启 analyze_result, 其他 LLM 功能默认关闭."""
        # 新建 ConfigManager 验证默认值
        from api.config_manager import ConfigManager
        ConfigManager._instance = None
        fresh_db = MockDatabaseManager()
        fresh_cm = ConfigManager(fresh_db)
        config = fresh_cm.get_llm_config()
        # enabled = enable_llm(true) AND analyze_result(true) => true
        self.assertTrue(config["enabled"])
        self.assertTrue(config["analyze_result"])
        # 其他 LLM 功能默认关闭
        self.assertFalse(config["extract_params"])
        self.assertFalse(config["generate_values"])
        self.assertFalse(config["identify_risk"])

    # ------------------------------------------------------------------
    # DB 清理 + Autorize 开关控制
    # ------------------------------------------------------------------
    def test_34_clear_db(self):
        """POST /api/action/clear-db - 清空数据库 (保留 config/users)."""
        # 先插入一些数据
        self.db.execute_query(
            "INSERT INTO raw_requests (method, host, url, path, headers, user_identifier) VALUES (?, ?, ?, ?, ?, ?)",
            ["GET", "test.com", "http://test.com/api", "/api", "[]", "User 1"]
        )
        self.db.execute_query(
            "INSERT INTO parameter_pool (api_signature, param_name, param_value, location, user_identifier) VALUES (?, ?, ?, ?, ?)",
            ["sig_test", "id", "123", "QUERY", "User 1"]
        )
        # 确认数据存在
        rows = self.db.fetch_all("SELECT COUNT(*) FROM raw_requests")
        self.assertGreater(rows[0][0], 0)
        rows = self.db.fetch_all("SELECT COUNT(*) FROM parameter_pool")
        self.assertGreater(rows[0][0], 0)

        # 调用 clear-db
        status, resp = self._request("POST", "/api/action/clear-db", body={})
        self.assertEqual(status, 200)
        self.assertIn("cleared_tables", resp["data"])

        # 确认流量/参数已清空
        rows = self.db.fetch_all("SELECT COUNT(*) FROM raw_requests")
        self.assertEqual(rows[0][0], 0)
        rows = self.db.fetch_all("SELECT COUNT(*) FROM parameter_pool")
        self.assertEqual(rows[0][0], 0)
        rows = self.db.fetch_all("SELECT COUNT(*) FROM attack_queue")
        self.assertEqual(rows[0][0], 0)

        # 确认 config/users 仍然保留
        users = self.cm.get_users()
        self.assertIsNotNone(users)

    def test_35_autorize_on_off(self):
        """POST /api/action/autorize - 控制开关 on/off."""
        # 开启
        status, resp = self._request("POST", "/api/action/autorize", body={"on": True})
        self.assertEqual(status, 200)
        self.assertIn("on", resp["message"].lower())
        # 验证配置已更新
        self.assertEqual(self.cm.get_int("autorize_intercept"), 1)

        # 关闭
        status, resp = self._request("POST", "/api/action/autorize", body={"on": False})
        self.assertEqual(status, 200)
        self.assertIn("off", resp["message"].lower())
        # 验证配置已更新
        self.assertEqual(self.cm.get_int("autorize_intercept"), 0)

    def test_36_clear_db_preserves_config(self):
        """POST /api/action/clear-db - 清空后 LLM 配置仍然保留."""
        # 设置一个 LLM 配置
        self.cm.set("enable_llm", "true")
        self.cm.set("llm_model", "glm-5.2")

        # 清空 DB
        status, resp = self._request("POST", "/api/action/clear-db", body={})
        self.assertEqual(status, 200)

        # 确认配置仍然保留
        self.assertEqual(self.cm.get("enable_llm"), "true")
        self.assertEqual(self.cm.get("llm_model"), "glm-5.2")


# ----------------------------------------------------------------------------
# 运行测试
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    unittest.main(verbosity=2)
