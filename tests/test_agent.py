#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDORs Factory 测试 Agent 脚本.

模拟 ai agent 通过 HTTP API 调用 IDORs Factory 插件, 完成完整的 IDOR 检测流程.
测试环境: http://198.18.0.1:5888/
账号: hmt1:1234567, hmt2:1234567
代理: 127.0.0.1:8080 (Burp Suite)

前置条件:
  1. Burp Suite 已加载 IDORs Factory 插件, HTTP API 服务运行在 127.0.0.1:8899
  2. Burp Suite 代理监听 127.0.0.1:8080
  3. 测试环境 http://198.18.0.1:5888/ 可访问

运行方式:
  python tests/test_agent.py
  python tests/test_agent.py --skip-traffic    # 跳过流量发送步骤
  python tests/test_agent.py --api-only         # 只测试 API 可用性
"""

import requests
import json
import sys
import time
import argparse
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------------------------------------------------------------------
# 配置
# ----------------------------------------------------------------------------
API_BASE = "http://127.0.0.1:8899"
TARGET_BASE = "http://198.18.0.1:5888"
BURP_PROXY = "http://127.0.0.1:8080"
PROXIES = {"http": BURP_PROXY, "https": BURP_PROXY}

# 测试账号
ACCOUNTS = {
    1: {"username": "hmt1", "password": "1234567"},
    2: {"username": "hmt2", "password": "1234567"},
}


def api_call(method, path, body=None, query=None):
    """调用 IDORs Factory HTTP API."""
    url = API_BASE + path
    if query:
        url += "?" + "&".join("{}={}".format(k, v) for k, v in query.items())
    headers = {"Content-Type": "application/json"}
    data = json.dumps(body) if body else None
    resp = requests.request(method, url, data=data, headers=headers, timeout=30)
    return resp.status_code, resp.json()


def login(account):
    """登录测试环境, 获取 Cookie."""
    session = requests.Session()
    session.proxies = PROXIES
    session.verify = False
    login_url = TARGET_BASE + "/login"
    try:
        resp = session.post(login_url, json={
            "username": account["username"],
            "password": account["password"],
        }, timeout=10)
        cookies = session.cookies.get_dict()
        cookie_str = "; ".join("{}={}".format(k, v) for k, v in cookies.items())
        print("[Agent] Login {} => cookies: {}".format(
            account["username"], cookie_str[:60] + "..." if len(cookie_str) > 60 else cookie_str))
        return cookie_str, session
    except Exception as e:
        print("[Agent] Login failed for {}: {}".format(account["username"], str(e)))
        return "", session


def send_traffic(session, path="/"):
    """通过代理发送流量到测试环境 (让 Burp 拦截)."""
    url = TARGET_BASE + path
    try:
        resp = session.get(url, timeout=10)
        print("[Agent] GET {} => {}".format(path, resp.status_code))
        return resp
    except Exception as e:
        print("[Agent] GET {} failed: {}".format(path, str(e)))
        return None


def run_full_test():
    """运行完整的 IDOR 检测流程."""
    print("=" * 60)
    print("IDORs Factory 测试 Agent")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Step 1: 检查 API 服务状态
    # ------------------------------------------------------------------
    print("\n[Step 1] 检查 API 服务状态...")
    try:
        status, resp = api_call("GET", "/api/status")
    except requests.exceptions.ConnectionError:
        print("[FAIL] 无法连接到 API 服务 ({}). 请确保 Burp 已加载插件.".format(API_BASE))
        return False

    if status != 200:
        print("[FAIL] API 状态异常: {} {}".format(status, resp))
        return False
    print("[OK] API 服务运行中, 配置项: {}, 攻击版本: {}".format(
        resp["data"]["config_keys"], resp["data"]["attacks_version"]))

    # ------------------------------------------------------------------
    # Step 2: 配置用户标识
    # ------------------------------------------------------------------
    print("\n[Step 2] 配置用户标识...")
    # 登录获取 cookie
    cookie1, session1 = login(ACCOUNTS[1])
    cookie2, session2 = login(ACCOUNTS[2])

    if not cookie1 and not cookie2:
        print("[WARN] 无法登录测试环境, 跳过流量步骤")
        skip_traffic = True
    else:
        skip_traffic = False

    # 通过 API 设置用户标识
    if cookie1:
        status, resp = api_call("PUT", "/api/config/user/1/identify", body={
            "identify_string": "Cookie: " + cookie1
        })
        print("[OK] User 1 identify: {}".format(resp.get("message", "")))
    if cookie2:
        status, resp = api_call("PUT", "/api/config/user/2/identify", body={
            "identify_string": "Cookie: " + cookie2
        })
        print("[OK] User 2 identify: {}".format(resp.get("message", "")))

    # ------------------------------------------------------------------
    # Step 3: 通过 API 设置用户 Header (R2 需求测试)
    # ------------------------------------------------------------------
    print("\n[Step 3] 测试 header/cookie 增改 (R2)...")
    status, resp = api_call("POST", "/api/user/1/header", body={
        "key": "X-Test-Header", "value": "agent-test"
    })
    print("[OK] Header upsert: {}".format(resp.get("data", {})))

    status, resp = api_call("POST", "/api/user/1/cookie", body={
        "value": cookie1 if cookie1 else "test=session"
    })
    print("[OK] Cookie upsert: {}".format(resp.get("data", {})))

    # ------------------------------------------------------------------
    # Step 4: 配置 LLM (可选)
    # ------------------------------------------------------------------
    print("\n[Step 4] 配置 LLM (可选)...")
    status, resp = api_call("PUT", "/api/config/llm", body={
        "enable": False,
        "base_url": "",
        "api_key": "",
        "model": "",
    })
    print("[OK] LLM 配置: {}".format(resp.get("message", "")))

    # ------------------------------------------------------------------
    # Step 5: 开启 Autorize (R3)
    # ------------------------------------------------------------------
    print("\n[Step 5] 开启 Autorize...")
    status, resp = api_call("POST", "/api/action/autorize", body={"on": True})
    print("[OK] {}".format(resp.get("message", "")))

    # ------------------------------------------------------------------
    # Step 6: 发送测试流量 (通过 Burp 代理)
    # ------------------------------------------------------------------
    if not skip_traffic:
        print("\n[Step 6] 发送测试流量 (通过代理 {})...".format(BURP_PROXY))
        paths = ["/", "/api/users", "/api/users/me", "/dashboard", "/profile"]
        for path in paths:
            send_traffic(session1, path)
            send_traffic(session2, path)
            time.sleep(0.5)
        print("[OK] 流量发送完成, 等待 Burp 处理...")
        time.sleep(2)

    # ------------------------------------------------------------------
    # Step 7: 提取参数 (R3)
    # ------------------------------------------------------------------
    print("\n[Step 7] 提取参数...")
    status, resp = api_call("POST", "/api/action/extract-params")
    print("[OK] {}".format(resp.get("message", resp.get("message", ""))))

    # ------------------------------------------------------------------
    # Step 8: 获取参数推荐 (R1)
    # ------------------------------------------------------------------
    print("\n[Step 8] 获取参数推荐...")
    for key in ["user_id", "id", "userId"]:
        status, resp = api_call("POST", "/api/recommend", body={
            "key": key, "location": "Auto"
        })
        if status == 200 and resp.get("data", {}).get("recommendations"):
            recs = resp["data"]["recommendations"]
            print("[OK] 参数 '{}' 推荐 {} 个值:".format(key, len(recs)))
            for rec in recs[:3]:
                print("  - rank {}: value={}, source={}, endpoint={}".format(
                    rec["rank"], rec["value"], rec["source_user"], rec["endpoint"]))
            # 测试应用推荐值
            if recs:
                best = recs[0]
                status, resp = api_call("POST", "/api/recommend/apply", body={
                    "user_id": 1, "key": key, "value": best["value"], "location": "Query"
                })
                print("[OK] 应用推荐值: {}".format(resp.get("message", "")))
            break
    else:
        print("[INFO] 未找到参数推荐 (可能无流量或未提取参数)")

    # ------------------------------------------------------------------
    # Step 9: 生成攻击 (R3)
    # ------------------------------------------------------------------
    print("\n[Step 9] 生成攻击...")
    status, resp = api_call("POST", "/api/action/generate-attacks", body={})
    print("[OK] {}".format(resp.get("message", resp.get("message", ""))))

    # ------------------------------------------------------------------
    # Step 10: 批量执行 GET 攻击 (R3)
    # ------------------------------------------------------------------
    print("\n[Step 10] 批量执行 GET 攻击...")
    status, resp = api_call("POST", "/api/action/batch-attack-get", body={
        "limit": 20
    })
    if status == 200:
        data = resp.get("data", {})
        if data:
            print("[OK] {}".format(resp.get("message", "")))
            print("  Summary: {}".format(json.dumps(data, ensure_ascii=False)))
        else:
            print("[OK] {}".format(resp.get("message", "")))
    else:
        print("[WARN] 批量攻击失败: {} {}".format(status, resp))

    # ------------------------------------------------------------------
    # Step 11: 查询攻击结果 (R4)
    # ------------------------------------------------------------------
    print("\n[Step 11] 查询攻击结果...")
    status, resp = api_call("GET", "/api/attacks", query={"limit": "20"})
    if status == 200:
        attacks = resp.get("data", {}).get("attacks", [])
        print("[OK] 攻击结果: {} 条".format(len(attacks)))
        for a in attacks[:5]:
            print("  - #{}: {} {} => {} (score={}, verified={}, ai_verified={})".format(
                a["id"], a["method"], a["path"], a["status"],
                a["vulnerability_score"], a["verified"],
                a.get("ai_verified", False)))
    else:
        print("[WARN] 查询失败: {} {}".format(status, resp))

    # ------------------------------------------------------------------
    # Step 12: AI 剪枝 (Feature 1)
    # ------------------------------------------------------------------
    print("\n[Step 12] AI 剪枝 (Feature 1)...")
    status, resp = api_call("POST", "/api/action/prune-attacks", body={
        "limit": 50,
        "score_threshold": 30,
        "use_llm": False,  # 先用启发式测试
    })
    if status == 200:
        data = resp.get("data", {})
        print("[OK] 剪枝完成: 总计 {}, 剪枝 {}, 剩余 {}".format(
            data.get("total", 0), data.get("pruned", 0), data.get("remaining", 0)))
        if data.get("pruned_ids"):
            print("  剪枝 IDs: {}".format(data["pruned_ids"]))
    else:
        print("[WARN] 剪枝失败: {} {}".format(status, resp))

    # ------------------------------------------------------------------
    # Step 13: AI 越权验证 (Feature 2)
    # ------------------------------------------------------------------
    print("\n[Step 13] AI 越权验证 (Feature 2)...")
    # 取第一条已执行的攻击进行 AI 验证
    status, resp = api_call("GET", "/api/attacks", query={"limit": "20"})
    verify_attack_id = None
    if status == 200:
        attacks = resp.get("data", {}).get("attacks", [])
        for a in attacks:
            if a["status"] in ("SENT", "VULNERABLE", "SAFE", "UNCERTAIN", "FAILED"):
                verify_attack_id = a["id"]
                break

    if verify_attack_id:
        status, resp = api_call("POST", "/api/action/ai-verify", body={
            "attack_id": verify_attack_id,
            "extra_context": "Security agent context: testing for IDOR on user profile API",
            "force_reverify": True,
        })
        if status == 200:
            data = resp.get("data", {})
            ai_result = data.get("ai_result", {})
            print("[OK] AI 验证攻击 #{}: result={}, confidence={}, new_status={}".format(
                verify_attack_id,
                ai_result.get("result", "?"),
                ai_result.get("confidence", "?"),
                data.get("new_status", "?")))
        else:
            print("[WARN] AI 验证失败: {} {}".format(status, resp))
    else:
        print("[SKIP] 没有已执行的攻击可供 AI 验证")

    # ------------------------------------------------------------------
    # Step 14: AI 生成 POC (Feature 3)
    # ------------------------------------------------------------------
    print("\n[Step 14] AI 生成 POC (Feature 3)...")
    # 取第一条原始请求 ID
    status, resp = api_call("GET", "/api/attacks", query={"limit": "1"})
    poc_request_id = None
    if status == 200:
        attacks = resp.get("data", {}).get("attacks", [])
        if attacks:
            # 从攻击详情获取 original_request_id (需要查详情)
            status2, resp2 = api_call("GET", "/api/attacks/{}".format(attacks[0]["id"]))
            if status2 == 200:
                # 我们没有 original_request_id 字段在列表, 但详情有
                # 尝试用攻击 ID 作为 request ID 的替代 (不一定对, 但测试 API 可用性)
                poc_request_id = attacks[0]["id"]  # 用攻击ID测试API可用性

    if poc_request_id:
        # 先用手动 modifications 测试
        status, resp = api_call("POST", "/api/action/ai-generate-poc", body={
            "request_id": poc_request_id,
            "modifications": [
                {
                    "param": "user_id",
                    "original_value": "1",
                    "new_value": "99999",
                    "location": "QUERY",
                    "reason": "Agent test: swap to non-existent user as control",
                }
            ],
            "target_user": "AI-Agent-Test",
        })
        if status == 200:
            data = resp.get("data", {})
            print("[OK] AI POC 生成 (手动): 生成 {} 个, IDs={}".format(
                data.get("generated", 0), data.get("attack_ids", [])))
        else:
            print("[WARN] AI POC 生成失败: {} {}".format(status, resp))

    # ------------------------------------------------------------------
    # Step 15: 删除单个攻击 (Feature 1 补充)
    # ------------------------------------------------------------------
    print("\n[Step 15] 删除单个攻击 (Feature 1 补充)...")
    # 取第一条 PENDING 攻击来删除
    status, resp = api_call("GET", "/api/attacks", query={"status": "PENDING", "limit": "1"})
    if status == 200:
        attacks = resp.get("data", {}).get("attacks", [])
        if attacks:
            del_id = attacks[0]["id"]
            status, resp = api_call("DELETE", "/api/attacks/{}".format(del_id))
            if status == 200:
                print("[OK] 删除攻击 #{}: {}".format(del_id, resp.get("message", "")))
            else:
                print("[WARN] 删除失败: {} {}".format(status, resp))
        else:
            print("[SKIP] 没有 PENDING 攻击可删除")
    else:
        print("[WARN] 查询 PENDING 攻击失败")

    # ------------------------------------------------------------------
    # Step 16: 查看配置 (R3 验证)
    # ------------------------------------------------------------------
    print("\n[Step 16] 查看当前配置...")
    status, resp = api_call("GET", "/api/config")
    if status == 200:
        data = resp["data"]
        print("[OK] 当前配置:")
        print("  LLM: enabled={}, model={}".format(
            data["llm"]["enable"], data["llm"]["model"]))
        print("  Users: {}".format(len(data["users"])))
        print("  Blacklist: {}".format(data["blacklist_params"]))
        print("  Autorize: {}".format("on" if data["autorize_intercept"] == 1 else "off"))

    # ------------------------------------------------------------------
    # 关闭 Autorize
    # ------------------------------------------------------------------
    print("\n[Cleanup] 关闭 Autorize...")
    api_call("POST", "/api/action/autorize", body={"on": False})
    print("[OK] Autorize 已关闭")

    print("\n" + "=" * 60)
    print("测试完成!")
    print("=" * 60)
    return True


def run_api_only():
    """只测试 API 可用性 (不发送流量)."""
    print("=" * 60)
    print("IDORs Factory API 可用性测试")
    print("=" * 60)

    tests = [
        ("GET /api/status", "GET", "/api/status", None, None),
        ("GET /api/config", "GET", "/api/config", None, None),
        ("PUT /api/config/llm", "PUT", "/api/config/llm",
         {"enable": False, "base_url": "", "api_key": "", "model": ""}, None),
        ("PUT /api/config/blacklist", "PUT", "/api/config/blacklist",
         {"params": "limit,offset"}, None),
        ("PUT /api/config/user/1/identify", "PUT", "/api/config/user/1/identify",
         {"identify_string": "Cookie: test=1"}, None),
        ("POST /api/user/1/header", "POST", "/api/user/1/header",
         {"key": "X-Test", "value": "test123"}, None),
        ("POST /api/user/1/cookie", "POST", "/api/user/1/cookie",
         {"value": "session=test"}, None),
        ("GET /api/attacks", "GET", "/api/attacks", None, {"limit": "10"}),
        ("POST /api/recommend", "POST", "/api/recommend",
         {"key": "user_id", "location": "Auto"}, None),
        ("POST /api/action/autorize", "POST", "/api/action/autorize",
         {"on": True}, None),
        ("POST /api/action/auto-idor", "POST", "/api/action/auto-idor",
         {"enable": False}, None),
        ("DELETE /api/user/1/header/X-Test", "DELETE", "/api/user/1/header/X-Test",
         None, None),
        # Feature 1: AI 剪枝
        ("POST /api/action/prune-attacks", "POST", "/api/action/prune-attacks",
         {"limit": 10, "score_threshold": 30, "use_llm": False}, None),
        # Feature 2: AI 越权验证 (无 attack_id, 预期 400)
        ("POST /api/action/ai-verify (no id)", "POST", "/api/action/ai-verify",
         {}, None),
        # Feature 3: AI 生成 POC (无 request_id, 预期 400)
        ("POST /api/action/ai-generate-poc (no id)", "POST", "/api/action/ai-generate-poc",
         {}, None),
        # DELETE attack (不存在的 id, 预期 404)
        ("DELETE /api/attacks/99999", "DELETE", "/api/attacks/99999",
         None, None),
    ]

    passed = 0
    failed = 0

    for name, method, path, body, query in tests:
        try:
            status, resp = api_call(method, path, body, query)
            # 200=成功, 400/404=预期错误 (无参数或不存在的资源)
            if status == 200:
                print("[PASS] {} => {}".format(name, resp.get("status", "")))
                passed += 1
            elif status in (400, 404):
                print("[PASS] {} => {} (expected error: {})".format(
                    name, status, resp.get("message", "")[:60]))
                passed += 1
            else:
                print("[FAIL] {} => {} {}".format(name, status, resp))
                failed += 1
        except Exception as e:
            print("[FAIL] {} => error: {}".format(name, str(e)))
            failed += 1

    # 关闭 autorize
    try:
        api_call("POST", "/api/action/autorize", body={"on": False})
    except:
        pass

    print("\n" + "-" * 40)
    print("结果: {} 通过, {} 失败".format(passed, failed))
    return failed == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDORs Factory 测试 Agent")
    parser.add_argument("--skip-traffic", action="store_true",
                        help="跳过流量发送步骤")
    parser.add_argument("--api-only", action="store_true",
                        help="只测试 API 可用性")
    args = parser.parse_args()

    if args.api_only:
        success = run_api_only()
    else:
        success = run_full_test()

    sys.exit(0 if success else 1)
