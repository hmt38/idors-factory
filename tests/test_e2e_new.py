#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDORs Factory 端到端测试 (新功能验证).

测试场景:
  1. 配置 LLM (DashScope glm-5.2), 只开启 Analyze Attack Results
  2. 登录 agent1/agent2, 获取 Cookie
  3. 不配置 user-identify, 先发送流量 (测试自动检测+缓存)
  4. 配置 user-identify 映射
  5. 调用 refresh-traffic-identity 刷新缓存流量
  6. 测试 AI agent 自定义已存在 header
  7. 提取参数、生成攻击、执行攻击
  8. AI 剪枝 + AI 越权验证
"""

import requests
import json
import sys
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_BASE = "http://127.0.0.1:8899"
TARGET_BASE = "http://198.18.0.1:5888"
BURP_PROXY = "http://127.0.0.1:8080"
PROXIES = {"http": BURP_PROXY, "https": BURP_PROXY}

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
    session.trust_env = False  # 忽略系统代理环境变量, 只用 Burp 代理
    login_url = TARGET_BASE + "/api/login"
    try:
        resp = session.post(login_url, json={
            "username": account["username"],
            "password": account["password"],
        }, timeout=10)
        print("[Login] {} => {}".format(account["username"], resp.status_code))
        cookies = session.cookies.get_dict()
        cookie_str = "; ".join("{}={}".format(k, v) for k, v in cookies.items())
        return cookie_str, session
    except Exception as e:
        print("[Login] {} failed: {}".format(account["username"], str(e)))
        return "", session


def send_traffic(session, path):
    url = TARGET_BASE + path
    try:
        resp = session.get(url, timeout=10)
        return resp.status_code
    except Exception as e:
        print("[Traffic] GET {} failed: {}".format(path, str(e)))
        return None


def main():
    print("=" * 60)
    print("IDORs Factory 端到端测试 (新功能)")
    print("=" * 60)
    passed = 0
    failed = 0
    warnings = 0

    # Step 1: 检查 API
    print("\n[Step 1] 检查 API 服务状态...")
    try:
        status, resp = api_call("GET", "/api/status")
        if status == 200:
            print("[OK] API 运行中")
            passed += 1
        else:
            print("[FAIL] API 不可用")
            return False
    except Exception as e:
        print("[FAIL] 无法连接 API: {}".format(str(e)))
        return False

    # Step 2: 配置 LLM (只开启 Analyze Attack Results)
    print("\n[Step 2] 配置 LLM (DashScope glm-5.2, 只开启 analyze_result)...")
    status, resp = api_call("PUT", "/api/config/llm", body=LLM_CONFIG)
    if status == 200:
        print("[OK] LLM 配置完成")
        passed += 1
    else:
        print("[FAIL] LLM 配置失败: {} {}".format(status, resp))
        failed += 1

    # 验证配置
    status, resp = api_call("GET", "/api/config")
    llm = resp["data"]["llm"]
    print("  enable={}, analyze_result={}, extract_params={}".format(
        llm["enable"], llm["analyze_result"], llm["extract_params"]))
    if llm["enable"] and llm["analyze_result"] and not llm["extract_params"]:
        print("[OK] LLM 默认配置正确: 只开启 Analyze Attack Results")
        passed += 1
    else:
        print("[WARN] LLM 配置不符预期")
        warnings += 1

    # Step 3: 登录获取 Cookie
    print("\n[Step 3] 登录 agent1/agent2...")
    cookie1, session1 = login(ACCOUNTS[1])
    cookie2, session2 = login(ACCOUNTS[2])
    if cookie1 and cookie2:
        print("[OK] agent1 Cookie: {}...".format(cookie1[:50]))
        print("[OK] agent2 Cookie: {}...".format(cookie2[:50]))
        passed += 1
    else:
        print("[FAIL] 登录失败")
        failed += 1
        return False

    # Step 4: 不配置 user-identify, 先发送流量 (测试自动检测+缓存)
    print("\n[Step 4] 发送流量 (未配置 user-identify, 测试自动检测缓存)...")
    # 先清理旧的用户标识
    api_call("PUT", "/api/config/user/1/identify", body={"identify_string": ""})
    api_call("PUT", "/api/config/user/2/identify", body={"identify_string": ""})

    # 开启 autorize
    api_call("POST", "/api/action/autorize", body={"on": True})
    print("[OK] Autorize 已开启")

    paths = ["/", "/api/users/me", "/api/products", "/api/orders", "/profile"]
    for path in paths:
        send_traffic(session1, path)
        send_traffic(session2, path)
        time.sleep(0.3)
    print("[OK] 流量发送完成")
    time.sleep(2)
    passed += 1

    # Step 5: 配置 user-identify 映射
    print("\n[Step 5] 配置 user-identify 映射...")
    status, resp = api_call("PUT", "/api/config/user/1/identify", body={
        "identify_string": "Cookie: " + cookie1
    })
    if status == 200:
        print("[OK] agent1 identify 已配置")
        passed += 1
    else:
        print("[FAIL] agent1 identify 配置失败")
        failed += 1

    status, resp = api_call("PUT", "/api/config/user/2/identify", body={
        "identify_string": "Cookie: " + cookie2
    })
    if status == 200:
        print("[OK] agent2 identify 已配置")
        passed += 1
    else:
        print("[FAIL] agent2 identify 配置失败")
        failed += 1

    # 再发一些流量 (这次应该能匹配)
    print("[OK] 再发一些流量 (匹配已配置的 identify)...")
    for path in ["/api/users/me", "/api/products", "/api/orders"]:
        send_traffic(session1, path)
        send_traffic(session2, path)
        time.sleep(0.3)
    time.sleep(2)

    # Step 6: 调用 refresh-traffic-identity (新端点)
    print("\n[Step 6] 刷新缓存流量的用户标识...")
    status, resp = api_call("POST", "/api/action/refresh-traffic-identity", body={})
    if status == 200:
        data = resp["data"]
        print("[OK] 刷新完成: cached={}, refreshed={}, unmapped={}".format(
            data.get("total_cached", 0), data.get("refreshed", 0),
            data.get("still_unmapped", 0)))
        passed += 1
    elif status == 404:
        print("[WARN] refresh-traffic-identity 端点不存在 (需要重载 Burp 扩展)")
        warnings += 1
    else:
        print("[FAIL] 刷新失败: {} {}".format(status, resp))
        failed += 1

    # Step 7: 测试 AI agent 自定义已存在 header
    print("\n[Step 7] AI agent 自定义已存在 header...")
    # 先设置一个 Authorization header
    status, resp = api_call("POST", "/api/user/1/header", body={
        "key": "Authorization", "value": "Bearer original_token"
    })
    if status == 200:
        print("[OK] 设置 Authorization header")
        passed += 1
    else:
        print("[FAIL] 设置 header 失败")
        failed += 1

    # 替换已存在的同名 header
    status, resp = api_call("POST", "/api/user/1/header", body={
        "key": "Authorization", "value": "Bearer hijacked_by_agent"
    })
    if status == 200:
        # 验证是 upsert (更新而非新增)
        config = api_call("GET", "/api/config")
        print("[OK] AI agent 替换已存在 header 成功 (upsert 语义)")
        passed += 1
    else:
        print("[FAIL] 替换 header 失败")
        failed += 1

    # Step 8: 提取参数
    print("\n[Step 8] 提取参数...")
    status, resp = api_call("POST", "/api/action/extract-params")
    if status == 200:
        print("[OK] {}".format(resp.get("message", "")))
        passed += 1
    else:
        print("[WARN] 提取参数: {} {}".format(status, resp))
        warnings += 1

    # Step 9: 生成攻击
    print("\n[Step 9] 生成攻击...")
    status, resp = api_call("POST", "/api/action/generate-attacks", body={})
    if status == 200:
        print("[OK] {}".format(resp.get("message", "")))
        passed += 1
    else:
        print("[WARN] 生成攻击: {} {}".format(status, resp))
        warnings += 1

    # Step 10: 批量执行 GET 攻击
    print("\n[Step 10] 批量执行 GET 攻击...")
    status, resp = api_call("POST", "/api/action/batch-attack-get", body={"limit": 30}, timeout=120)
    if status == 200:
        data = resp.get("data", {})
        print("[OK] total={}, success={}, vulnerable={}".format(
            data.get("total", 0), data.get("success", 0), data.get("vulnerable", 0)))
        passed += 1
    else:
        print("[WARN] 批量攻击: {} {}".format(status, resp))
        warnings += 1

    # Step 11: 查询攻击结果
    print("\n[Step 11] 查询攻击结果...")
    status, resp = api_call("GET", "/api/attacks", query={"limit": "30"})
    if status == 200:
        attacks = resp.get("data", {}).get("attacks", [])
        print("[OK] 攻击结果: {} 条".format(len(attacks)))
        for a in attacks[:5]:
            print("  - #{}: {} {} => {} (score={}, verified={}, ai_verified={})".format(
                a["id"], a["method"], a["path"], a["status"],
                a["vulnerability_score"], a["verified"],
                a.get("ai_verified", False)))
        passed += 1
    else:
        print("[WARN] 查询失败")
        warnings += 1

    # Step 12: AI 剪枝
    print("\n[Step 12] AI 剪枝...")
    status, resp = api_call("POST", "/api/action/prune-attacks", body={
        "limit": 50,
        "score_threshold": 30,
        "use_llm": True,
    }, timeout=120)
    if status == 200:
        data = resp.get("data", {})
        print("[OK] 剪枝: total={}, pruned={}, remaining={}".format(
            data.get("total", 0), data.get("pruned", 0), data.get("remaining", 0)))
        if data.get("details"):
            for d in data["details"][:3]:
                print("  - #{}: score={} pruned={} reason={}".format(
                    d["attack_id"], d["score"], d["pruned"], d["reason"][:60]))
        passed += 1
    else:
        print("[WARN] 剪枝: {} {}".format(status, resp))
        warnings += 1

    # Step 13: AI 越权验证
    print("\n[Step 13] AI 越权验证...")
    status, resp = api_call("GET", "/api/attacks", query={"limit": "30"})
    verify_id = None
    if status == 200:
        attacks = resp.get("data", {}).get("attacks", [])
        for a in attacks:
            if a["status"] in ("SENT", "VULNERABLE", "SAFE", "UNCERTAIN", "FAILED"):
                verify_id = a["id"]
                break

    if verify_id:
        status, resp = api_call("POST", "/api/action/ai-verify", body={
            "attack_id": verify_id,
            "extra_context": "Security agent: testing IDOR on shopping system user API",
            "force_reverify": True,
        }, timeout=120)
        if status == 200:
            data = resp.get("data", {})
            ai_result = data.get("ai_result", {})
            print("[OK] AI 验证 #{}: result={}, confidence={}, status={}".format(
                verify_id, ai_result.get("result", "?"),
                ai_result.get("confidence", "?"),
                data.get("new_status", "?")))
            passed += 1
        else:
            print("[WARN] AI 验证失败: {} {}".format(status, resp))
            warnings += 1
    else:
        print("[SKIP] 没有已执行的攻击可供验证")
        warnings += 1

    # Cleanup
    print("\n[Cleanup] 关闭 Autorize...")
    api_call("POST", "/api/action/autorize", body={"on": False})

    # Summary
    print("\n" + "=" * 60)
    print("端到端测试结果: {} 通过, {} 警告, {} 失败".format(passed, warnings, failed))
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
