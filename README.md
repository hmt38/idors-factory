# IDORs Factory Agent 使用文档

> 本文档指导 AI agent 通过 HTTP API 调用 IDORs Factory 插件，完成 IDOR 漏洞检测的全流程。

---

## 一、前置条件

| 条件 | 说明 |
|------|------|
| Burp Suite | 已加载 IDORs Factory 插件，输出窗口显示 `[API] HTTP server started on 0.0.0.0:8899` |
| API 地址 | `http://<burp_host>:8899`（默认 0.0.0.0:8899，可远程访问） |
| Burp 代理 | `127.0.0.1:8080`（用于拦截 agent 发出的流量） |
| 测试账号 | hmt1:1234567 / hmt2:1234567 |

**验证 API 可用：**
```bash
curl http://127.0.0.1:8899/api/status
# {"status":"ok","data":{"running":true,"db_connected":true,...}}
```

---

## 二、API 端点清单

### 配置类

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/config` | 读取全部配置（LLM、用户、黑名单、开关） |
| PUT | `/api/config/llm` | 设置 LLM 配置 |
| PUT | `/api/config/user/{id}/identify` | 设置用户标识字符串 |
| PUT | `/api/config/blacklist` | 设置黑名单参数 |

### 动作类（按钮）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/action/autorize` | 开关 Autorize 拦截 |
| POST | `/api/action/extract-params` | 提取参数 |
| POST | `/api/action/generate-attacks` | 生成攻击 |
| POST | `/api/action/execute-attack` | 执行单个选定攻击 |
| POST | `/api/action/batch-attack-get` | 批量执行 GET 攻击 |
| POST | `/api/action/auto-idor` | 开关 Auto IDOR 定时循环 |

### 参数推荐类

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/recommend` | 获取参数推荐值 |
| POST | `/api/recommend/apply` | 应用推荐值到用户规则 |

### Header/Cookie 增改类

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/user/{id}/header` | 新增/更新用户 Header |
| POST | `/api/user/{id}/cookie` | 新增/更新用户 Cookie |
| DELETE | `/api/user/{id}/header/{key}` | 删除用户 Header |

### 结果查询类

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/attacks` | 查询攻击结果列表 |
| GET | `/api/attacks/{id}` | 查询单个攻击详情 |
| GET | `/api/status` | 服务状态检查 |

---

## 三、典型工作流（12 步）

```
 1. 配置用户标识          PUT  /api/config/user/1/identify
 2. 配置用户标识          PUT  /api/config/user/2/identify
 3. 配置 LLM（可选）      PUT  /api/config/llm
 4. 开启 Autorize        POST /api/action/autorize {"on": true}
 5. 发送流量（通过代理）   curl -x http://127.0.0.1:8080 http://target/api/users/me
 6. 提取参数             POST /api/action/extract-params
 7. 获取参数推荐          POST /api/recommend
 8. 应用推荐值            POST /api/recommend/apply
 9. 生成攻击             POST /api/action/generate-attacks
10. 执行单个攻击          POST /api/action/execute-attack {"attack_id": 1}
11. 批量执行 GET 攻击    POST /api/action/batch-attack-get {"limit": 50}
12. 查询结果             GET  /api/attacks
```

---

## 四、curl 示例

### 1. 配置用户标识

```bash
# 用户1标识（从登录获取的 Cookie）
curl -X PUT http://127.0.0.1:8899/api/config/user/1/identify \
  -H "Content-Type: application/json" \
  -d '{"identify_string": "Cookie: session=hmt1_token"}'

# 用户2标识
curl -X PUT http://127.0.0.1:8899/api/config/user/2/identify \
  -H "Content-Type: application/json" \
  -d '{"identify_string": "Cookie: session=hmt2_token"}'
```

### 2. 配置 LLM

```bash
curl -X PUT http://127.0.0.1:8899/api/config/llm \
  -H "Content-Type: application/json" \
  -d '{
    "enable": true,
    "base_url": "https://api.openai.com/v1",
    "api_key": "sk-xxx",
    "model": "gpt-4",
    "verify_ssl": true
  }'
```

### 3. 开启 Autorize

```bash
curl -X POST http://127.0.0.1:8899/api/action/autorize \
  -H "Content-Type: application/json" \
  -d '{"on": true}'
```

### 4. 发送流量（通过 Burp 代理）

```bash
# 用用户1的 Cookie 访问目标
curl -x http://127.0.0.1:8080 \
  -H "Cookie: session=hmt1_token" \
  http://198.18.0.1:5888/api/users/me

# 用用户2的 Cookie 访问目标
curl -x http://127.0.0.1:8080 \
  -H "Cookie: session=hmt2_token" \
  http://198.18.0.1:5888/api/users/me
```

### 5. 提取参数

```bash
curl -X POST http://127.0.0.1:8899/api/action/extract-params
```

### 6. 获取参数推荐

```bash
curl -X POST http://127.0.0.1:8899/api/recommend \
  -H "Content-Type: application/json" \
  -d '{"key": "user_id", "location": "Auto"}'
```

响应示例：
```json
{
  "status": "ok",
  "data": {
    "recommendations": [
      {"rank": 1, "key": "user_id", "value": "10086", "source_user": "User 2", "endpoint": "/api/users/10086", "score": 100}
    ]
  }
}
```

### 7. 应用推荐值

```bash
curl -X POST http://127.0.0.1:8899/api/recommend/apply \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "key": "user_id", "value": "10086", "location": "Query"}'
```

### 8. 新增/更新 Header

```bash
curl -X POST http://127.0.0.1:8899/api/user/1/header \
  -H "Content-Type: application/json" \
  -d '{"key": "X-Domain-Id", "value": "12345"}'
```

### 9. 生成攻击

```bash
curl -X POST http://127.0.0.1:8899/api/action/generate-attacks \
  -H "Content-Type: application/json" \
  -d '{}'
```

### 10. 执行单个攻击

```bash
curl -X POST http://127.0.0.1:8899/api/action/execute-attack \
  -H "Content-Type: application/json" \
  -d '{"attack_id": 1}'
```

### 11. 批量执行 GET 攻击

```bash
curl -X POST http://127.0.0.1:8899/api/action/batch-attack-get \
  -H "Content-Type: application/json" \
  -d '{"limit": 50}'
```

### 12. 查询攻击结果

```bash
# 查询所有漏洞
curl "http://127.0.0.1:8899/api/attacks?status=VULNERABLE&limit=20"

# 查询单条详情
curl http://127.0.0.1:8899/api/attacks/1
```

### 13. 关闭 Autorize

```bash
curl -X POST http://127.0.0.1:8899/api/action/autorize \
  -H "Content-Type: application/json" \
  -d '{"on": false}'
```

---

## 五、响应格式

所有响应为统一 JSON 格式：

```json
{
  "status": "ok",       // "ok" 或 "error"
  "data": {},           // 数据（成功时）
  "message": "..."      // 提示信息
}
```

错误响应：
```json
{
  "status": "error",
  "message": "Missing 'attack_id' in body"
}
```

---

## 六、测试

### 单元测试（不需要 Burp）

```bash
python tests/test_api.py
# 24 tests, all passing
```

### API 可用性测试（需要 Burp 运行插件）

```bash
python tests/test_agent.py --api-only
```

### 端到端测试（需要 Burp + 测试环境）

```bash
python tests/test_agent.py
```

端到端测试自动完成：登录获取 Cookie → 配置用户标识 → 设置 Header → 开启 Autorize → 发送流量 → 提取参数 → 获取推荐 → 生成攻击 → 批量执行 → 查询结果。

---

## 七、注意事项

1. **API Key 掩码**：`GET /api/config` 返回的 `api_key` 为掩码格式（如 `sk-t****5678`），写入时传完整 key。
2. **GUI 双入口**：API 操作会实时同步到 GUI，用户也可在 GUI 上手动操作，两者共享同一配置。
3. **无认证**：API 服务无认证，监听 0.0.0.0，请确保网络环境安全。
4. **Jython 2.7**：插件代码为 Jython 2.7 语法，API 响应中字符串为 unicode（`u'wal'`）。
5. **端口占用**：如果重启插件遇到 `Address already in use`，在 Burp 中 Unload 再 Load 插件。
