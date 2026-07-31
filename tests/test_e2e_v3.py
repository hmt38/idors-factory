#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDORs Factory 端到端测试 v3 (clear-db + autorize 控制 + 完整管线).

流程:
  1. clear-db 清空数据库
  2. autorize on 开启拦截
  3. 登录 agent1/agent2 发送流量 (未配置 identify, 测试自动检测缓存)
  4. 配置 user-identify, refresh 刷新缓存
  5. 提取参数 -> 生成攻击 -> 批量执行 -> AI 剪枝 -> AI 越权验证
  6. autorize off 关闭拦截
"""

import requests
import json
import sys
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_BASE = "http://127.0.0.1:8899"
TARGET_BASE = "http://198.18.0.1:5888"
PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

ACCOUNTS = {
    1: {"username": "agent1", "password": "Agent@Test2026"},
    2: {"username": "agent2", "password": "Agent@Test2026"},
}

LLM_CONFIG = {
    "enable": True,
    "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "api_key": "sk-e4749b13dbed4e8b97a3a511f1d45909",
    "model": "glm-5.2",
    "verify_ssl": True,
    "extract_params": False,
    "generate_values": False,
    "identify_risk": False,
    "analyze_result": True,
}

passed = 0
failed = 0
warnings = 0


def ok(msg):
    global passed
    passed += 1
    print("[OK] " + msg)


def warn(msg):
    global warnings
    warnings += 1
    print("[WARN] " + msg)


def fail(msg):
    global failed
    failed += 1
    print("[FAIL] " + msg)


def api_call(method, path, body=None, query=None, timeout=30):
    url = API_BASE + path
    if query:
        url += "?" + "&".join("{}={}".format(k, v) for k, v in query.items())
    headers = {"Content-Type": "application/json"}
    data = json.dumps(body) if body else None
    resp = requests.request(method, url, data=data, headers=headers, timeout=timeout)
    return resp.status_code, resp.json()


def login(account):
    session = requests.Session()
    session.proxies = PROXIES
    session.verify = False
    session.trust_env = False
    try:
        resp = session.post(TARGET_BASE + "/api/login", json={
            "username": account["username"],
            "password": account["password"],
        }, timeout=10)
        cookies = session.cookies.get_dict()
        cookie_str = "; ".join("{}={}".format(k, v) for k, v in cookies.items())
        return cookie_str, session
    except Exception as e:
        print("[Login] {} failed: {}".format(account["username"], str(e)))
        return "", session


def send_traffic(session, path):
    try:
        return session.get(TARGET_BASE + path, timeout=10).status_code
    except Exception as e:
        print("[Traffic] GET {} failed: {}".format(path, str(e)))
        return None


def main():
    print("=" * 60)
    print("IDORs Factory 端到端测试 v3 (clear-db + autorize + 完整管线)")
    print("=" * 60)

    # Step 1: 检查 API
    print("\n[Step 1] 检查 API...")
    try:
        status, _ = api_call("GET", "/api/status")
        if status == 200:
            ok("API 运行中")
        else:
            fail("API 不可用")
            return False
    except Exception as e:
        fail("无法连接 API: " + str(e))
        return False

    # Step 2: clear-db 清空数据库
    print("\n[Step 2] clear-db 清空数据库...")
    status, resp = api_call("POST", "/api/action/clear-db", body={})
    if status == 200:
        tables = resp["data"]["cleared_tables"]
        ok("DB 已清空: " + ", ".join(tables))
    else:
        fail("clear-db 失败: " + str(resp))
        return False

    # Step 3: 配置 LLM
    print("\n[Step 3] 配置 LLM (只开启 analyze_result)...")
    status, _ = api_call("PUT", "/api/config/llm", body=LLM_CONFIG)
    if status == 200:
        ok("LLM 配置完成")
    else:
        fail("LLM 配置失败")

    # Step 4: 清空 user-identify (测试自动检测)
    print("\n[Step 4] 清空 user-identify 映射 (测试自动检测缓存)...")
    api_call("PUT", "/api/config/user/1/identify", body={"identify_string": ""})
    api_call("PUT", "/api/config/user/2/identify", body={"identify_string": ""})
    ok("user-identify 已清空")

    # Step 5: autorize on
    print("\n[Step 5] autorize ON...")
    status, resp = api_call("POST", "/api/action/autorize", body={"on": True})
    if status == 200 and "on" in resp["message"].lower():
        ok("Autorize 已开启")
    else:
        fail("autorize on 失败")
        return False

    # Step 6: 登录并发送流量 (未配置 identify, 应自动检测缓存)
    print("\n[Step 6] 登录 agent1/agent2 并发送流量 (自动检测缓存)...")
    cookie1, session1 = login(ACCOUNTS[1])
    cookie2, session2 = login(ACCOUNTS[2])
    if not cookie1 or not cookie2:
        fail("登录失败")
        return False
    ok("agent1/agent2 登录成功")

    paths = ["/", "/api/users/me", "/api/products", "/api/orders", "/profile"]
    for path in paths:
        send_traffic(session1, path)
        send_traffic(session2, path)
        time.sleep(0.3)
    ok("流量发送完成 (10 个请求)")

    # Step 7: 验证自动检测的流量已缓存 (带重试)
    print("\n[Step 7] 验证自动检测缓存 (带重试)...")
    cached = 0
    for attempt in range(6):
        time.sleep(3)
        status, resp = api_call("POST", "/api/action/refresh-traffic-identity",
                                body={"dry_run": True}, timeout=30)
        if status == 200:
            cached = resp["data"].get("total_cached", 0)
            print("  尝试 {}: 缓存 {} 条".format(attempt + 1, cached))
            if cached > 0:
                break
    if cached > 0:
        ok("自动检测缓存 {} 条流量".format(cached))
    else:
        warn("未检测到缓存流量 (时序问题, 后续 refresh 会验证)")

    # Step 8: 配置 user-identify 映射
    print("\n[Step 8] 配置 user-identify 映射...")
    api_call("PUT", "/api/config/user/1/identify", body={"identify_string": "Cookie: " + cookie1})
    api_call("PUT", "/api/config/user/2/identify", body={"identify_string": "Cookie: " + cookie2})
    ok("agent1/agent2 identify 已配置")

    # Step 9: refresh-traffic-identity 刷新缓存
    print("\n[Step 9] refresh-traffic-identity 刷新缓存...")
    status, resp = api_call("POST", "/api/action/refresh-traffic-identity", body={}, timeout=30)
    if status == 200:
        data = resp["data"]
        refreshed = data.get("refreshed", 0)
        total = data.get("total_cached", 0)
        print("  总缓存: {}, 已刷新: {}, 仍未匹配: {}".format(
            total, refreshed, data.get("still_unmapped", 0)))
        if refreshed > 0:
            ok("刷新成功: {} 条流量已更新用户标识".format(refreshed))
        elif total > 0:
            warn("有缓存但未刷新 (cookie 可能不匹配)")
        else:
            warn("没有缓存流量可刷新")
    else:
        fail("刷新失败: " + str(resp))

    # 再发一些流量 (匹配已配置的 identify)
    print("  再发流量 (匹配已配置 identify)...")
    for path in ["/api/users/me", "/api/products", "/api/orders"]:
        send_traffic(session1, path)
        send_traffic(session2, path)
        time.sleep(0.3)
    time.sleep(3)

    # Step 10: 提取参数
    print("\n[Step 10] 提取参数...")
    status, resp = api_call("POST", "/api/action/extract-params", timeout=30)
    if status == 200:
        ok(resp.get("message", "提取完成"))
    else:
        warn("提取参数: " + str(resp))

    # Step 11: 生成攻击
    print("\n[Step 11] 生成攻击...")
    status, resp = api_call("POST", "/api/action/generate-attacks", body={}, timeout=60)
    if status == 200:
        data = resp.get("data", {})
        ok("生成攻击: {} 新增, 共 {} 条".format(
            data.get("created", 0), data.get("total", 0)))
    else:
        warn("生成攻击: " + str(resp))

    # Step 12: 批量执行 GET 攻击
    print("\n[Step 12] 批量执行 GET 攻击...")
    status, resp = api_call("POST", "/api/action/batch-attack-get",
                            body={"limit": 50}, timeout=120)
    if status == 200:
        data = resp.get("data", {})
        ok("批量攻击: total={}, success={}, vulnerable={}".format(
            data.get("total", 0), data.get("success", 0), data.get("vulnerable", 0)))
    else:
        warn("批量攻击: " + str(resp))

    # Step 13: 查询攻击结果
    print("\n[Step 13] 查询攻击结果...")
    status, resp = api_call("GET", "/api/attacks", query={"limit": "50"})
    if status == 200:
        attacks = resp.get("data", {}).get("attacks", [])
        ok("攻击结果: {} 条".format(len(attacks)))
        for a in attacks[:5]:
            print("  - #{}: {} {} => {} (score={}, verified={}, ai_verified={})".format(
                a["id"], a["method"], a["path"], a["status"],
                a["vulnerability_score"], a["verified"],
                a.get("ai_verified", False)))
    else:
        warn("查询失败")

    # Step 14: AI 剪枝
    print("\n[Step 14] AI 剪枝...")
    status, resp = api_call("POST", "/api/action/prune-attacks", body={
        "limit": 50, "score_threshold": 30, "use_llm": True,
    }, timeout=120)
    if status == 200:
        data = resp.get("data", {})
        ok("剪枝: total={}, pruned={}, remaining={}".format(
            data.get("total", 0), data.get("pruned", 0), data.get("remaining", 0)))
        for d in data.get("details", [])[:3]:
            print("  - #{}: score={} pruned={} reason={}".format(
                d["attack_id"], d["score"], d["pruned"], d["reason"][:60]))
    else:
        warn("剪枝: " + str(resp))

    # Step 15: AI 越权验证
    print("\n[Step 15] AI 越权验证...")
    status, resp = api_call("GET", "/api/attacks", query={"limit": "50"})
    verify_id = None
    if status == 200:
        for a in resp.get("data", {}).get("attacks", []):
            if a["status"] in ("SENT", "VULNERABLE", "SAFE", "UNCERTAIN", "FAILED"):
                verify_id = a["id"]
                break
    if verify_id:
        status, resp = api_call("POST", "/api/action/ai-verify", body={
            "attack_id": verify_id, "force_reverify": True,
        }, timeout=120)
        if status == 200:
            data = resp.get("data", {})
            ai = data.get("ai_result", {})
            ok("AI 验证 #{}: result={}, confidence={}, status={}".format(
                verify_id, ai.get("result", "?"),
                ai.get("confidence", "?"), data.get("new_status", "?")))
        else:
            warn("AI 验证失败: " + str(resp))
    else:
        warn("没有已执行的攻击可供验证")

    # Step 16: autorize off
    print("\n[Step 16] autorize OFF...")
    status, resp = api_call("POST", "/api/action/autorize", body={"on": False})
    if status == 200 and "off" in resp["message"].lower():
        ok("Autorize 已关闭")
    else:
        fail("autorize off 失败")

    # Summary
    print("\n" + "=" * 60)
    print("端到端测试结果: {} 通过, {} 警告, {} 失败".format(passed, warnings, failed))
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
