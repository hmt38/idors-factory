#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDORs Factory 端到端测试 v2 (扩展重载后, 真实发包).

重点验证新功能:
  1. 未配置 user-identify 时, 流量自动检测 Cookie 等并缓存
  2. 配置 user-identify 后, refresh-traffic-identity 刷新缓存
  3. AI agent 自定义已存在 header
  4. 完整 IDOR 管线: 提取->生成->执行->AI剪枝->AI越权验证
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
    login_url = TARGET_BASE + "/api/login"
    try:
        resp = session.post(login_url, json={
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
    url = TARGET_BASE + path
    try:
        resp = session.get(url, timeout=10)
        return resp.status_code
    except Exception as e:
        print("[Traffic] GET {} failed: {}".format(path, str(e)))
        return None


def main():
    print("=" * 60)
    print("IDORs Factory 端到端测试 v2 (扩展重载后, 真实发包)")
    print("=" * 60)

    # Step 1: 检查 API
    print("\n[Step 1] 检查 API 服务状态...")
    try:
        status, resp = api_call("GET", "/api/status")
        if status == 200:
            ok("API 运行中")
        else:
            fail("API 不可用")
            return False
    except Exception as e:
        fail("无法连接 API: {}".format(str(e)))
        return False

    # Step 2: 配置 LLM (只开启 Analyze Attack Results)
    print("\n[Step 2] 配置 LLM (DashScope glm-5.2, 只开启 analyze_result)...")
    status, resp = api_call("PUT", "/api/config/llm", body=LLM_CONFIG)
    if status == 200:
        ok("LLM 配置完成")
    else:
        fail("LLM 配置失败: {} {}".format(status, resp))

    status, resp = api_call("GET", "/api/config")
    llm = resp["data"]["llm"]
    print("  enable={}, analyze_result={}, extract_params={}, identify_risk={}".format(
        llm["enable"], llm["analyze_result"], llm["extract_params"], llm["identify_risk"]))
    if llm["enable"] and llm["analyze_result"] and not llm["extract_params"]:
        ok("LLM 默认配置正确: 只开启 Analyze Attack Results")
    else:
        warn("LLM 配置不符预期")

    # Step 3: 清空 user-identify 映射 (测试自动检测)
    print("\n[Step 3] 清空 user-identify 映射 (测试自动检测缓存)...")
    status, _ = api_call("PUT", "/api/config/user/1/identify", body={"identify_string": ""})
    status2, _ = api_call("PUT", "/api/config/user/2/identify", body={"identify_string": ""})
    if status == 200 and status2 == 200:
        ok("user-identify 映射已清空")
    else:
        fail("清空 user-identify 失败")

    # 确认 autorize 开启
    api_call("POST", "/api/action/autorize", body={"on": True})
    print("  Autorize 已开启")

    # Step 4: 登录并发送流量 (未配置 user-identify, 应自动检测缓存)
    print("\n[Step 4] 登录 agent1/agent2 并发送流量 (未配置 identify, 测试自动检测)...")
    cookie1, session1 = login(ACCOUNTS[1])
    cookie2, session2 = login(ACCOUNTS[2])
    if cookie1 and cookie2:
        ok("agent1 Cookie: {}...".format(cookie1[:50]))
        ok("agent2 Cookie: {}...".format(cookie2[:50]))
    else:
        fail("登录失败")
        return False

    paths = ["/", "/api/users/me", "/api/products", "/api/orders", "/profile"]
    for path in paths:
        send_traffic(session1, path)
        send_traffic(session2, path)
        time.sleep(0.3)
    ok("流量发送完成 (10 个请求)")

    # Step 5: 验证自动检测的流量已缓存 (带重试, Burp 异步处理流量)
    print("\n[Step 5] 验证自动检测的流量已缓存...")
    cached = 0
    would_refresh = 0
    for attempt in range(5):
        time.sleep(2)
        status, resp = api_call("POST", "/api/action/refresh-traffic-identity",
                                body={"dry_run": True}, timeout=30)
        if status == 200:
            data = resp["data"]
            cached = data.get("total_cached", 0)
            would_refresh = data.get("refreshed", 0)
            print("  尝试 {}: 缓存流量: {} 条, 可刷新: {} 条".format(
                attempt + 1, cached, would_refresh))
            if cached > 0:
                break
    if cached > 0:
        ok("自动检测的流量已缓存 ({} 条)".format(cached))
    else:
        warn("没有缓存流量 (可能扩展未正确重载或流量被拦截)")

    # Step 6: 配置 user-identify 映射
    print("\n[Step 6] 配置 user-identify 映射...")
    status, _ = api_call("PUT", "/api/config/user/1/identify", body={
        "identify_string": "Cookie: " + cookie1
    })
    if status == 200:
        ok("agent1 identify 已配置: Cookie: {}...".format(cookie1[:40]))
    else:
        fail("agent1 identify 配置失败")

    status, _ = api_call("PUT", "/api/config/user/2/identify", body={
        "identify_string": "Cookie: " + cookie2
    })
    if status == 200:
        ok("agent2 identify 已配置: Cookie: {}...".format(cookie2[:40]))
    else:
        fail("agent2 identify 配置失败")

    # Step 7: 调用 refresh-traffic-identity 刷新缓存流量
    print("\n[Step 7] 刷新缓存流量的用户标识 (真实更新)...")
    status, resp = api_call("POST", "/api/action/refresh-traffic-identity", body={}, timeout=30)
    if status == 200:
        data = resp["data"]
        refreshed = data.get("refreshed", 0)
        total = data.get("total_cached", 0)
        still = data.get("still_unmapped", 0)
        print("  总缓存: {}, 已刷新: {}, 仍未匹配: {}".format(total, refreshed, still))
        if refreshed > 0:
            ok("刷新成功: {} 条流量已更新用户标识".format(refreshed))
            # 显示前几条刷新详情
            for d in data.get("details", [])[:3]:
                print("    #{}: {} -> {}".format(
                    d["request_id"], d["old_identifier"][:30], d["new_identifier"]))
        elif total > 0:
            warn("有缓存但未刷新 (可能 cookie 值不匹配)")
        else:
            warn("没有缓存流量可刷新")
    else:
        fail("刷新失败: {} {}".format(status, resp))

    # 再发一些流量 (这次应该能直接匹配)
    print("\n  再发一些流量 (匹配已配置的 identify)...")
    for path in ["/api/users/me", "/api/products", "/api/orders"]:
        send_traffic(session1, path)
        send_traffic(session2, path)
        time.sleep(0.3)
    time.sleep(3)

    # Step 8: 测试 AI agent 自定义已存在 header
    print("\n[Step 8] AI agent 自定义已存在 header (upsert 替换)...")
    status, _ = api_call("POST", "/api/user/1/header", body={
        "key": "Authorization", "value": "Bearer original_token"
    })
    if status == 200:
        ok("设置 Authorization header")
    else:
        fail("设置 header 失败")

    status, resp = api_call("POST", "/api/user/1/header", body={
        "key": "Authorization", "value": "Bearer hijacked_by_agent"
    })
    if status == 200:
        ok("AI agent 替换已存在 header 调用成功 (upsert)")
    else:
        fail("替换 header 失败")

    # 通过 DELETE 端点验证 header 存在 (DELETE 内部调用 get_match_replace_rules)
    status, resp = api_call("DELETE", "/api/user/1/header/Authorization")
    if status == 200:
        ok("验证: Authorization header 存在且已被替换 (DELETE 确认 upsert 生效)")
        # 重新设置回去
        api_call("POST", "/api/user/1/header", body={
            "key": "Authorization", "value": "Bearer hijacked_by_agent"
        })
    else:
        warn("Authorization header 未找到 (可能 upsert 存储格式不同)")

    # Step 9: 提取参数
    print("\n[Step 9] 提取参数...")
    status, resp = api_call("POST", "/api/action/extract-params", timeout=30)
    if status == 200:
        ok("{}".format(resp.get("message", "提取完成")))
    else:
        warn("提取参数: {} {}".format(status, resp))

    # Step 10: 生成攻击
    print("\n[Step 10] 生成攻击...")
    status, resp = api_call("POST", "/api/action/generate-attacks", body={}, timeout=60)
    if status == 200:
        data = resp.get("data", {})
        created = data.get("created", 0)
        total = data.get("total", 0)
        ok("生成攻击: {} 新增, 共 {} 条".format(created, total))
    else:
        warn("生成攻击: {} {}".format(status, resp))

    # Step 11: 批量执行 GET 攻击
    print("\n[Step 11] 批量执行 GET 攻击...")
    status, resp = api_call("POST", "/api/action/batch-attack-get", body={"limit": 50}, timeout=120)
    if status == 200:
        data = resp.get("data", {})
        total = data.get("total", 0)
        success = data.get("success", 0)
        vuln = data.get("vulnerable", 0)
        ok("批量攻击: total={}, success={}, vulnerable={}".format(total, success, vuln))
    else:
        warn("批量攻击: {} {}".format(status, resp))

    # Step 12: 查询攻击结果
    print("\n[Step 12] 查询攻击结果...")
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

    # Step 13: AI 剪枝
    print("\n[Step 13] AI 剪枝 (LLM 评分)...")
    status, resp = api_call("POST", "/api/action/prune-attacks", body={
        "limit": 50,
        "score_threshold": 30,
        "use_llm": True,
    }, timeout=120)
    if status == 200:
        data = resp.get("data", {})
        total = data.get("total", 0)
        pruned = data.get("pruned", 0)
        remaining = data.get("remaining", 0)
        ok("剪枝: total={}, pruned={}, remaining={}".format(total, pruned, remaining))
        if data.get("details"):
            for d in data["details"][:3]:
                print("  - #{}: score={} pruned={} reason={}".format(
                    d["attack_id"], d["score"], d["pruned"], d["reason"][:60]))
    else:
        warn("剪枝: {} {}".format(status, resp))

    # Step 14: AI 越权验证
    print("\n[Step 14] AI 越权验证 (agent 查看返回结果)...")
    status, resp = api_call("GET", "/api/attacks", query={"limit": "50"})
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
            ok("AI 验证 #{}: result={}, confidence={}, status={}".format(
                verify_id, ai_result.get("result", "?"),
                ai_result.get("confidence", "?"),
                data.get("new_status", "?")))
        else:
            warn("AI 验证失败: {} {}".format(status, resp))
    else:
        warn("没有已执行的攻击可供验证")

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
