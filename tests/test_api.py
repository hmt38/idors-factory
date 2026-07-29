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
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS parameter_pool (
            id INTEGER PRIMARY KEY AUTOINCREMENT, raw_request_id INTEGER,
            param_key TEXT, param_value TEXT, location TEXT, endpoint TEXT,
            user_identifier TEXT, is_exclusive BOOLEAN DEFAULT 0,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS attack_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT, original_request_id INTEGER,
            attack_type TEXT, status TEXT DEFAULT 'PENDING', response_code INTEGER,
            vulnerability_score INTEGER DEFAULT 0, llm_verification_result TEXT,
            payload_description TEXT, verified BOOLEAN DEFAULT 0,
            executed_request_data BLOB, attack_response BLOB,
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

    def execute_query(self, query, params=None):
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
        self.assertFalse(self.cm.get_bool("enable_llm"))
        self.assertEqual(self.cm.get("llm_model"), "gpt-3.5-turbo")

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
            "INSERT INTO parameter_pool (raw_request_id, param_key, param_value, location, endpoint, user_identifier) VALUES (?, ?, ?, ?, ?, ?)",
            [1, "user_id", "10086", "QUERY", "/api/users/10086", "User 2"]
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
        """GET /api/attacks."""
        # 先写入测试数据
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path) VALUES (?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/1", "/api/users/1"]
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (id, original_request_id, status, response_code, vulnerability_score, verified) VALUES (?, ?, ?, ?, ?, ?)",
            [1, 1, "VULNERABLE", 200, 85, 0]
        )
        status, resp = self._request("GET", "/api/attacks")
        self.assertEqual(status, 200)
        attacks = resp["data"]["attacks"]
        self.assertEqual(len(attacks), 1)
        self.assertEqual(attacks[0]["status"], "VULNERABLE")

    def test_12_get_attack_detail(self):
        """GET /api/attacks/1."""
        self.db.execute_query(
            "INSERT INTO raw_requests (id, method, host, url, path) VALUES (?, ?, ?, ?, ?)",
            [1, "GET", "test.com", "http://test.com/api/users/1", "/api/users/1"]
        )
        self.db.execute_query(
            "INSERT INTO attack_queue (id, original_request_id, status, response_code) VALUES (?, ?, ?, ?)",
            [1, 1, "VULNERABLE", 200]
        )
        status, resp = self._request("GET", "/api/attacks/1")
        self.assertEqual(status, 200)
        self.assertEqual(resp["data"]["status"], "VULNERABLE")

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


# ----------------------------------------------------------------------------
# 运行测试
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    unittest.main(verbosity=2)
