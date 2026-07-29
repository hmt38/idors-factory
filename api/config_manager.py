#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ConfigManager - IDORs Factory 的配置真相源 (Single Source of Truth).

职责:
  1. 持有所有配置项 (LLM, 用户标识, 开关, 黑名单等) 的内存缓存
  2. 写时持久化到 DB config/users/match_replace_rules 表
  3. 维护内存版本号 (AtomicLong) 供 GUI Timer 按需刷新
  4. 提供线程安全的 get/set 接口 (ReentrantLock)
  5. 双入口同步: API 写 -> GUI 刷新; GUI 写 -> ConfigManager 持久化

使用方式:
  cm = ConfigManager(db_manager)
  cm.set("enable_llm", True)          # 写 DB + 更新缓存 + 自增版本号
  val = cm.get("enable_llm")          # 从内存缓存读 (不查 DB)
  cm.get_llm_config()                 # 返回 dict, 便于业务层使用
  cm.get_blacklist_set()              # 返回 set, 便于黑名单判断
"""

import json

try:
    from java.util.concurrent.atomic import AtomicLong
    from java.util.concurrent.locks import ReentrantLock
except ImportError:
    # CPython fallback for unit testing
    class AtomicLong(object):
        def __init__(self, val=0):
            self._val = val
        def get(self):
            return self._val
        def incrementAndGet(self):
            self._val += 1
            return self._val
        def set(self, val):
            self._val = val

    class ReentrantLock(object):
        def __init__(self):
            pass
        def lock(self):
            pass
        def unlock(self):
            pass


# ----------------------------------------------------------------------------
# 默认配置值
# 首次启动时写入 DB, 后续从 DB 加载
# ----------------------------------------------------------------------------
DEFAULTS = {
    "blacklist_params": "limit,offset",
    "enable_llm": "false",
    "llm_base_url": "https://api.openai.com/v1",
    "llm_api_key": "",
    "llm_model": "gpt-3.5-turbo",
    "llm_disable_ssl_verification": "false",
    "llm_extract_params": "true",
    "llm_generate_values": "true",
    "llm_identify_risk": "true",
    "llm_analyze_result": "true",
    "auto_idor_enabled": "false",
    "autorize_intercept": "0",
    "header_fuzz_keys": "X-User-Id,X-Domain-Id,Authorization,Cookie",
    "ignore_304": "false",
    "prevent_304": "false",
    "intercept_requests_from_repeater": "false",
    "do_unauthorized_request": "true",
    "replace_query_param": "false",
    "auto_scroll": "false",
}

# 布尔型配置键 (存储为 "true"/"false" 字符串)
BOOL_KEYS = frozenset([
    "enable_llm", "llm_disable_ssl_verification", "llm_extract_params",
    "llm_generate_values", "llm_identify_risk", "llm_analyze_result",
    "auto_idor_enabled", "ignore_304", "prevent_304",
    "intercept_requests_from_repeater", "do_unauthorized_request",
    "replace_query_param", "auto_scroll",
])


class ConfigManager(object):
    """
    配置管理器单例.
    所有配置的唯真相源: agent (API) 和 用户 (GUI) 都通过此对象读写配置.
    """

    _instance = None

    def __new__(cls, db_manager=None):
        if cls._instance is None:
            cls._instance = object.__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_manager=None):
        if self._initialized and db_manager is None:
            return
        self._initialized = True

        self._db = db_manager
        self._cache = {}          # 配置键值对内存缓存
        self._lock = ReentrantLock()
        self._config_version = AtomicLong(0)
        self._attacks_version = AtomicLong(0)
        self._users_version = AtomicLong(0)
        self._extender = None     # GUI 同步回调 (可选)

        # 从 DB 加载配置; 若 DB 无记录则用默认值填充
        self._load_from_db()

    # ------------------------------------------------------------------
    # 内部: DB 读写
    # ------------------------------------------------------------------
    def _load_from_db(self):
        """启动时从 config 表加载所有键值到内存缓存."""
        self._lock.lock()
        try:
            rows = self._db.fetch_all("SELECT key, value FROM config")
            if rows:
                for row in rows:
                    key = row[0]
                    value = row[1]
                    self._cache[key] = value
            # 用默认值补全缺失的键
            for k, v in DEFAULTS.items():
                if k not in self._cache:
                    self._cache[k] = v
                    self._db.execute_query(
                        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                        [k, v],
                    )
            print("[ConfigManager] Loaded {} config keys from DB".format(len(self._cache)))
        except Exception as e:
            print("[ConfigManager] Error loading from DB: " + str(e))
            # 降级: 用默认值
            self._cache = dict(DEFAULTS)
        finally:
            self._lock.unlock()

    def _save_config_to_db(self, key, value):
        """将单个配置项写入 DB (INSERT OR REPLACE)."""
        try:
            self._db.execute_query(
                "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                [key, str(value)],
            )
        except Exception as e:
            print("[ConfigManager] Error saving config '{}': {}".format(key, str(e)))

    # ------------------------------------------------------------------
    # 公开: 通用 get/set
    # ------------------------------------------------------------------
    def get(self, key, default=None):
        """读取配置项 (从内存缓存, 不查 DB)."""
        self._lock.lock()
        try:
            val = self._cache.get(key, default)
            if val is not None:
                return str(val)
            return None
        finally:
            self._lock.unlock()

    def set(self, key, value):
        """
        设置配置项.
        写 DB + 更新缓存 + 自增版本号 + (可选) 同步 GUI.
        """
        self._lock.lock()
        try:
            val_str = str(value)
            self._cache[key] = val_str
            self._save_config_to_db(key, val_str)
            self._config_version.incrementAndGet()
            # 同步到 GUI (如果在 EDT 外则 invokeLater)
            self._sync_key_to_gui(key, val_str)
        finally:
            self._lock.unlock()

    # ------------------------------------------------------------------
    # 公开: 类型化访问器
    # ------------------------------------------------------------------
    def get_bool(self, key, default=False):
        """读取布尔型配置."""
        val = self.get(key)
        if val is None:
            return default
        return val.lower() in ("true", "1", "yes", "on")

    def set_bool(self, key, value):
        """设置布尔型配置."""
        self.set(key, "true" if value else "false")

    def get_int(self, key, default=0):
        """读取整型配置."""
        val = self.get(key)
        if val is None:
            return default
        try:
            return int(val)
        except ValueError:
            return default

    def set_int(self, key, value):
        """设置整型配置."""
        self.set(key, str(int(value)))

    # ------------------------------------------------------------------
    # 公开: LLM 配置 (业务层常用)
    # ------------------------------------------------------------------
    def get_llm_config(self):
        """
        返回 LLM 配置 dict, 供 AttackEngine / Extractor 使用.
        {
            "enabled": bool,          # enable_llm AND llm_analyze_result
            "base_url": str,
            "api_key": str,
            "model": str,
            "verify_ssl": bool,
            "extract_params": bool,
            "generate_values": bool,
            "identify_risk": bool,
            "analyze_result": bool,
        }
        """
        enable = self.get_bool("enable_llm")
        analyze = self.get_bool("llm_analyze_result")
        return {
            "enabled": enable and analyze,
            "base_url": self.get("llm_base_url", ""),
            "api_key": self.get("llm_api_key", ""),
            "model": self.get("llm_model", ""),
            "verify_ssl": not self.get_bool("llm_disable_ssl_verification"),
            "extract_params": self.get_bool("llm_extract_params", True),
            "generate_values": self.get_bool("llm_generate_values", True),
            "identify_risk": self.get_bool("llm_identify_risk", True),
            "analyze_result": analyze,
        }

    # ------------------------------------------------------------------
    # 公开: 黑名单参数
    # ------------------------------------------------------------------
    def get_blacklist_set(self):
        """返回黑名单参数 set, 供 Extractor / Attacker 判断参数是否跳过."""
        text = self.get("blacklist_params", "")
        if not text:
            return set()
        return set(p.strip() for p in text.split(",") if p.strip())

    # ------------------------------------------------------------------
    # 公开: 用户配置 (users 表)
    # ------------------------------------------------------------------
    def get_users(self):
        """
        返回用户列表.
        [{"id": 1, "name": "User 1", "identify_string": "...", "headers_text": "..."}]
        """
        rows = self._db.fetch_all(
            "SELECT id, name, identify_string, headers_text FROM users ORDER BY id"
        )
        if not rows:
            return []
        result = []
        for row in rows:
            result.append({
                "id": row[0],
                "name": row[1] if row[1] else "",
                "identify_string": row[2] if row[2] else "",
                "headers_text": row[3] if row[3] else "",
            })
        return result

    def save_user(self, user_id, name, identify_string, headers_text):
        """保存或更新用户配置 (INSERT OR REPLACE)."""
        self._db.execute_query(
            "INSERT OR REPLACE INTO users (id, name, identify_string, headers_text) VALUES (?, ?, ?, ?)",
            [int(user_id), name, identify_string, headers_text],
        )
        self._users_version.incrementAndGet()
        self._sync_users_to_gui()

    def get_user_by_id(self, user_id):
        """返回单个用户配置 dict."""
        rows = self._db.fetch_all(
            "SELECT id, name, identify_string, headers_text FROM users WHERE id = ?",
            [int(user_id)],
        )
        if not rows:
            return None
        row = rows[0]
        return {
            "id": row[0],
            "name": row[1] if row[1] else "",
            "identify_string": row[2] if row[2] else "",
            "headers_text": row[3] if row[3] else "",
        }

    # ------------------------------------------------------------------
    # 公开: Match/Replace 规则 (match_replace_rules 表)
    # ------------------------------------------------------------------
    def get_match_replace_rules(self, user_id):
        """
        返回指定用户的 Match/Replace 规则列表.
        [{"id": 1, "user_id": 1, "rule_type": "Header Add/Set:", "match_text": "...", "replace_text": "..."}]
        """
        rows = self._db.fetch_all(
            "SELECT id, user_id, rule_type, match_text, replace_text FROM match_replace_rules WHERE user_id = ? ORDER BY id",
            [int(user_id)],
        )
        if not rows:
            return []
        result = []
        for row in rows:
            result.append({
                "id": row[0],
                "user_id": row[1],
                "rule_type": row[2] if row[2] else "",
                "match_text": row[3] if row[3] else "",
                "replace_text": row[4] if row[4] else "",
            })
        return result

    def save_match_replace_rule(self, user_id, rule_type, match_text, replace_text, rule_id=None):
        """
        新增或更新 Match/Replace 规则.
        rule_id 为 None 时新增 (AUTOINCREMENT), 否则更新.
        返回 rule_id.
        """
        if rule_id is not None:
            self._db.execute_query(
                "UPDATE match_replace_rules SET user_id=?, rule_type=?, match_text=?, replace_text=? WHERE id=?",
                [int(user_id), rule_type, match_text, replace_text, int(rule_id)],
            )
            return rule_id
        else:
            self._db.execute_query(
                "INSERT INTO match_replace_rules (user_id, rule_type, match_text, replace_text) VALUES (?, ?, ?, ?)",
                [int(user_id), rule_type, match_text, replace_text],
            )
            # 查询最新插入的 id
            rows = self._db.fetch_all(
                "SELECT id FROM match_replace_rules WHERE user_id=? ORDER BY id DESC LIMIT 1",
                [int(user_id)],
            )
            if rows:
                self._users_version.incrementAndGet()
                return rows[0][0]
            return None

    def delete_match_replace_rule(self, rule_id):
        """删除 Match/Replace 规则."""
        self._db.execute_query(
            "DELETE FROM match_replace_rules WHERE id=?",
            [int(rule_id)],
        )
        self._users_version.incrementAndGet()

    # ------------------------------------------------------------------
    # 公开: 用户 header/cookie upsert (R2 需求)
    # ------------------------------------------------------------------
    def upsert_user_header(self, user_id, key, value):
        """
        为指定用户新增或更新 header (upsert 语义).
        实现方式: 在 match_replace_rules 表中写入一条 "Header Add/Set:" 规则.
        如果已存在同 key 的规则则更新, 否则新增.
        """
        rules = self.get_match_replace_rules(user_id)
        for rule in rules:
            if rule["rule_type"] == "Header Add/Set:" and rule["match_text"] == key:
                # 更新已有规则
                return self.save_match_replace_rule(
                    user_id, "Header Add/Set:", key, value, rule["id"]
                )
        # 新增规则
        return self.save_match_replace_rule(user_id, "Header Add/Set:", key, value)

    def upsert_user_cookie(self, user_id, key, value):
        """
        为指定用户新增或更新 cookie.
        实现方式: 在 headers_text 中更新 Cookie 行, 或写入 Header Add/Set: Cookie.
        简化处理: 写入 "Header Add/Set: Cookie" 规则, match="Cookie", replace=value.
        """
        # 如果已有 Cookie header 规则, 更新; 否则新增
        rules = self.get_match_replace_rules(user_id)
        for rule in rules:
            if rule["rule_type"] == "Header Add/Set:" and rule["match_text"].lower() == "cookie":
                return self.save_match_replace_rule(
                    user_id, "Header Add/Set:", "Cookie", value, rule["id"]
                )
        return self.save_match_replace_rule(user_id, "Header Add/Set:", "Cookie", value)

    # ------------------------------------------------------------------
    # 公开: 版本号 (GUI Timer 用)
    # ------------------------------------------------------------------
    def get_config_version(self):
        """返回配置变更版本号 (long)."""
        return self._config_version.get()

    def get_attacks_version(self):
        """返回攻击结果变更版本号 (long)."""
        return self._attacks_version.get()

    def get_users_version(self):
        """返回用户/规则变更版本号 (long)."""
        return self._users_version.get()

    def notify_attacks_changed(self):
        """攻击结果有变化时调用 (execute_attack / generate_attacks 后)."""
        self._attacks_version.incrementAndGet()

    def notify_config_changed(self):
        """配置有变化时调用."""
        self._config_version.incrementAndGet()

    # ------------------------------------------------------------------
    # 公开: GUI 同步 (可选, extender 存在时生效)
    # ------------------------------------------------------------------
    def set_extender(self, extender):
        """注入 extender 引用, 用于 GUI 同步."""
        self._extender = extender

    def _sync_key_to_gui(self, key, value):
        """将单个配置项同步到 GUI 组件 (如果 extender 存在)."""
        ext = self._extender
        if not ext:
            return
        try:
            from javax.swing import SwingUtilities
        except ImportError:
            SwingUtilities = None

        def update():
            self._do_sync_key_to_gui(ext, key, value)

        if SwingUtilities:
            SwingUtilities.invokeLater(update)
        else:
            update()

    def _do_sync_key_to_gui(self, ext, key, value):
        """在 EDT 上执行实际的 GUI 组件更新."""
        try:
            # LLM 配置
            if key == "llm_base_url" and hasattr(ext, "llmBaseUrl"):
                ext.llmBaseUrl.setText(value)
            elif key == "llm_api_key" and hasattr(ext, "llmApiKey"):
                ext.llmApiKey.setText(value)
            elif key == "llm_model" and hasattr(ext, "llmModel"):
                ext.llmModel.setText(value)
            elif key in BOOL_KEYS:
                self._sync_bool_to_gui(ext, key, value == "true")
            elif key == "blacklist_params" and hasattr(ext, "blacklistParams"):
                ext.blacklistParams.setText(value)
        except Exception as e:
            print("[ConfigManager] GUI sync error for '{}': {}".format(key, str(e)))

    def _sync_bool_to_gui(self, ext, key, checked):
        """将布尔配置同步到 GUI 复选框."""
        mapping = {
            "enable_llm": "enableLlm",
            "llm_disable_ssl_verification": "llmDisableSslVerification",
            "llm_extract_params": "llmExtractParams",
            "llm_generate_values": "llmGenerateValues",
            "llm_identify_risk": "llmIdentifyRisk",
            "llm_analyze_result": "llmAnalyzeResult",
            "auto_idor_enabled": "autoIdorEnabled",
            "ignore_304": "ignore304",
            "prevent_304": "prevent304",
            "intercept_requests_from_repeater": "interceptRequestsfromRepeater",
            "do_unauthorized_request": "doUnauthorizedRequest",
            "replace_query_param": "replaceQueryParam",
            "auto_scroll": "autoScroll",
        }
        attr = mapping.get(key)
        if attr and hasattr(ext, attr):
            ext.__getattribute__(attr).setSelected(checked)

    def _sync_users_to_gui(self):
        """用户配置变化时同步到 GUI (如果 extender 存在)."""
        ext = self._extender
        if not ext or not hasattr(ext, "userTab"):
            return
        try:
            from javax.swing import SwingUtilities
            SwingUtilities.invokeLater(lambda: self._do_sync_users_to_gui(ext))
        except ImportError:
            self._do_sync_users_to_gui(ext)

    def _do_sync_users_to_gui(self, ext):
        """在 EDT 上同步用户配置到 GUI."""
        # TODO: 阶段1.4 实现 GUI 用户面板的双向同步
        pass

    # ------------------------------------------------------------------
    # 公开: 从 GUI 读取配置到 ConfigManager (GUI -> ConfigManager)
    # ------------------------------------------------------------------
    def sync_from_gui(self, extender=None):
        """
        从 GUI 组件读取当前配置, 写入 ConfigManager.
        用于用户在 GUI 上微调后, 将配置同步到真相源.
        """
        ext = extender or self._extender
        if not ext:
            return

        # LLM 文本配置
        if hasattr(ext, "llmBaseUrl"):
            self.set("llm_base_url", ext.llmBaseUrl.getText())
        if hasattr(ext, "llmApiKey"):
            self.set("llm_api_key", ext.llmApiKey.getText())
        if hasattr(ext, "llmModel"):
            self.set("llm_model", ext.llmModel.getText())
        if hasattr(ext, "blacklistParams"):
            self.set("blacklist_params", ext.blacklistParams.getText())

        # 布尔配置
        bool_mapping = {
            "enable_llm": "enableLlm",
            "llm_disable_ssl_verification": "llmDisableSslVerification",
            "llm_extract_params": "llmExtractParams",
            "llm_generate_values": "llmGenerateValues",
            "llm_identify_risk": "llmIdentifyRisk",
            "llm_analyze_result": "llmAnalyzeResult",
            "auto_idor_enabled": "autoIdorEnabled",
            "ignore_304": "ignore304",
            "prevent_304": "prevent304",
            "intercept_requests_from_repeater": "interceptRequestsfromRepeater",
            "do_unauthorized_request": "doUnauthorizedRequest",
            "replace_query_param": "replaceQueryParam",
            "auto_scroll": "autoScroll",
        }
        for config_key, gui_attr in bool_mapping.items():
            if hasattr(ext, gui_attr):
                self.set_bool(config_key, ext.__getattribute__(gui_attr).isSelected())

        print("[ConfigManager] Synced configuration from GUI")

    # ------------------------------------------------------------------
    # 公开: 将 ConfigManager 配置同步到 GUI (ConfigManager -> GUI)
    # ------------------------------------------------------------------
    def sync_to_gui(self, extender=None):
        """
        将 ConfigManager 的配置同步到 GUI 组件.
        用于 API 设置配置后, 刷新 GUI 显示.
        """
        ext = extender or self._extender
        if not ext:
            return

        try:
            from javax.swing import SwingUtilities
        except ImportError:
            SwingUtilities = None

        def update():
            self._do_sync_to_gui(ext)

        if SwingUtilities:
            SwingUtilities.invokeLater(update)
        else:
            update()

    def _do_sync_to_gui(self, ext):
        """在 EDT 上执行全量 GUI 同步."""
        # LLM 文本
        if hasattr(ext, "llmBaseUrl"):
            ext.llmBaseUrl.setText(self.get("llm_base_url", ""))
        if hasattr(ext, "llmApiKey"):
            ext.llmApiKey.setText(self.get("llm_api_key", ""))
        if hasattr(ext, "llmModel"):
            ext.llmModel.setText(self.get("llm_model", ""))
        if hasattr(ext, "blacklistParams"):
            ext.blacklistParams.setText(self.get("blacklist_params", ""))

        # 布尔
        bool_mapping = {
            "enable_llm": "enableLlm",
            "llm_disable_ssl_verification": "llmDisableSslVerification",
            "llm_extract_params": "llmExtractParams",
            "llm_generate_values": "llmGenerateValues",
            "llm_identify_risk": "llmIdentifyRisk",
            "llm_analyze_result": "llmAnalyzeResult",
            "auto_idor_enabled": "autoIdorEnabled",
            "ignore_304": "ignore304",
            "prevent_304": "prevent304",
            "intercept_requests_from_repeater": "interceptRequestsfromRepeater",
            "do_unauthorized_request": "doUnauthorizedRequest",
            "replace_query_param": "replaceQueryParam",
            "auto_scroll": "autoScroll",
        }
        for config_key, gui_attr in bool_mapping.items():
            if hasattr(ext, gui_attr):
                ext.__getattribute__(gui_attr).setSelected(self.get_bool(config_key))

        # autorize 开关
        intercept = self.get_int("autorize_intercept", 0)
        if hasattr(ext, "startButton"):
            if intercept == 1:
                ext.startButton.setText("Autorize is on")
                ext.startButton.setSelected(True)
            else:
                ext.startButton.setText("Autorize is off")
                ext.startButton.setSelected(False)

        print("[ConfigManager] Synced configuration to GUI")
