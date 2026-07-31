# IDORs Factory — AI Agent 操作指南

> **目标读者**：AI agent（非人类）。本文档提供从零开始操作 IDORs Factory 的完整指南。
> 阅读本文档后，agent 应能独立完成 IDOR 漏洞检测的全流程。

---

## 一、概念速览

| 术语 | 含义 |
|------|------|
| **IDOR** | Insecure Direct Object Reference，越权漏洞。用户 A 通过修改请求参数（如 `order_id=10`）访问用户 B 的数据 |
| **Autorize** | Burp 插件，自动将 User 1 的请求用 User 2 的身份重发，对比响应判断是否存在越权 |
| **IDORs Factory** | 本插件，在 Autorize 基础上增加参数提取、攻击生成、LLM 分析、AI 辅助剪枝/验证/生成 POC |
| **raw_requests** | 数据库表，存储通过 Burp 代理的原始流量 |
| **attack_queue** | 数据库表，存储生成的攻击条目及其执行结果 |
| **PENDING** | 攻击尚未执行 |
| **CHECKING_SKIPPED** | 攻击已执行，Autorize 跳过了自动判定 |
| **VULNERABLE** | 攻击已执行，判定为存在越权 |
| **ai_verified** | 攻击被 AI 越权 agent 验证过，优先级高于普通 verified |

---

## 二、前置条件

| 条件 | 说明 |
|------|------|
| Burp Suite | 已加载 IDORs Factory 插件，输出窗口显示 `[API] HTTP server started on 0.0.0.0:8899` |
| API 地址 | `http://<burp_host>:8899`（默认 0.0.0.0:8899，可远程访问） |
| Burp 代理 | `127.0.0.1:8080`（用于拦截 agent 发出的流量） |
| 测试账号 | 需两个不同权限的账号（User 1 和 User 2），用于越权对比 |

**验证 API 可用：**
```bash
curl http://127.0.0.1:8899/api/status
# 预期: {"status":"ok","data":{"running":true,"db_connected":true,...}}
```

---

## 三、数据模型

### raw_requests 表（原始流量）

| 字段 | 说明 |
|------|------|
| `id` | 请求 ID，后续生成攻击时引用 |
| `method` | HTTP 方法（GET/POST/...） |
| `path` | 请求路径（如 `/api/shop/order/detail`） |
| `headers` | 请求头（JSON 数组） |
| `body` | 请求体 |
| `response_headers` | 响应头 |
| `response_body` | 响应体 |
| `user_identifier` | 用户标识（如 "User 1"，未配置映射时为 `auto:Cookie:xxx` 自动检测值） |

### attack_queue 表（攻击队列）

| 字段 | 说明 |
|------|------|
| `id` | 攻击 ID |
| `original_request_id` | 关联的 raw_requests.id |
| `target_user` | 目标用户（如 "User 2"） |
| `payload_description` | 攻击描述（如 `Swap QUERY (order_id): 10->30`） |
| `request_data` | 生成的攻击请求（BLOB，执行前填充） |
| `executed_request_data` | 实际发出的请求报文（BLOB，执行后填充） |
| `status` | PENDING / CHECKING_SKIPPED / VULNERABLE |
| `response_data` | 攻击响应报文（BLOB） |
| `response_code` | HTTP 响应码 |
| `verified` | LLM 自动验证结果 |
| `ai_verified` | **AI 越权 agent 验证结果（高优先级）** |
| `ai_verification_result` | AI 验证详情（JSON） |
| `llm_verification_result` | LLM 自动验证详情 |
| `vulnerability_score` | 漏洞评分 |

---

## 四、API 端点清单

### 配置类

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/config` | 读取全部配置（LLM、用户、黑名单、开关） |
| PUT | `/api/config/llm` | 设置 LLM 配置 |
| PUT | `/api/config/user/{id}/identify` | 设置用户标识 + 自定义 Header |
| PUT | `/api/config/blacklist` | 设置黑名单参数 |

### 动作类

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/action/autorize` | 开关 Autorize 拦截 |
| POST | `/api/action/clear-db` | 清空数据库（流量/攻击/参数，保留 config/users） |
| POST | `/api/action/refresh-traffic-identity` | 刷新缓存流量的用户标识（auto: → 已配置用户名） |
| POST | `/api/action/extract-params` | 从 raw_requests 提取可变参数 |
| POST | `/api/action/generate-attacks` | 基于提取的参数生成攻击 |
| POST | `/api/action/execute-attack` | 执行单个攻击 |
| POST | `/api/action/batch-attack-get` | 批量执行 GET 攻击 |
| POST | `/api/action/auto-idor` | 开关 Auto IDOR 定时循环 |
| POST | `/api/action/prune-attacks` | **AI 剪枝**：LLM 打分，删除低价值 POC |
| POST | `/api/action/ai-verify` | **AI 越权验证**：查看完整报文，深度判断 |
| POST | `/api/action/ai-generate-poc` | **AI 生成 POC**：修改 path/query/body/header 参数 |

### 参数推荐类

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/recommend` | 获取参数推荐值（LLM 或启发式） |
| POST | `/api/recommend/apply` | 应用推荐值到用户规则 |

### Header/Cookie 增删类

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/user/{id}/header` | 新增/更新用户 Header 规则 |
| POST | `/api/user/{id}/cookie` | 新增/更新用户 Cookie |
| DELETE | `/api/user/{id}/header/{key}` | 删除用户 Header 规则 |

### 结果查询类

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/attacks` | 攻击结果列表（含 `ai_verified` 字段） |
| GET | `/api/attacks/{id}` | 单个攻击详情（含完整报文） |
| DELETE | `/api/attacks/{id}` | 删除单个攻击（不允许删除已执行的） |
| GET | `/api/status` | 服务状态检查 |

---

## 五、完整工作流（从零开始）

> 每步标注 **前置条件** 和 **后置状态**，agent 可据此判断是否可跳过某步。

### 阶段 1：环境准备

#### 步骤 1：验证 API 可用

**前置**：Burp 已加载插件
**后置**：确认 API 服务正常

```bash
curl http://127.0.0.1:8899/api/status
# 预期: {"status":"ok","data":{"running":true}}
```

#### 步骤 2：获取两个用户的 Cookie

**前置**：有目标系统的两个账号
**后置**：得到 `cookie1`（User 1）和 `cookie2`（User 2）

```bash
# 登录 User 1，从 Set-Cookie 响应头获取 cookie
curl -v -X POST http://target/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"pass1"}'
# 提取 Set-Cookie 头中的 session 值

# 登录 User 2（用独立 session 避免冲突）
curl -v -X POST http://target/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user2","password":"pass2"}'
```

#### 步骤 3：配置用户标识 + 自定义 Header

**前置**：已获取两个用户的 Cookie
**后置**：插件知道如何识别 User 1 和 User 2，且攻击时会自动添加自定义 Header

```bash
# 配置 User 1：标识字符串 + 可选的自定义 Header
curl -X PUT http://127.0.0.1:8899/api/config/user/1/identify \
  -H "Content-Type: application/json" \
  -d '{
    "identify_string": "Cookie: session=user1_session_token",
    "headers_text": "X-User-Profile: user1_username"
  }'

# 配置 User 2
curl -X PUT http://127.0.0.1:8899/api/config/user/2/identify \
  -H "Content-Type: application/json" \
  -d '{
    "identify_string": "Cookie: session=user2_session_token",
    "headers_text": "X-User-Profile: user2_username"
  }'
```

> **`identify_string`**：用于识别流量属于哪个用户（通常是 Cookie 头）
> **`headers_text`**（可选）：用户特有的自定义 Header，攻击时会随 Cookie 一起交换。每行一个 Header，格式 `Header-Name: value`。多个 Header 用换行分隔。
>
> **流量自动检测**：未配置 `identify_string` 时，插件自动从 `Cookie` / `X-Auth-Token` / `Authorization` 等常见认证头中提取用户标识，以 `auto:Cookie:xxx` 格式缓存流量入库。后续配置好映射后，调用 `refresh-traffic-identity` 统一刷新。

#### 步骤 3.5：清空数据库（可选，用于重置环境）

**前置**：无
**后置**：流量/攻击/参数数据清空，config/users/rules 保留

```bash
curl -X POST http://127.0.0.1:8899/api/action/clear-db \
  -H "Content-Type: application/json" \
  -d '{}'
# 预期: {"status":"ok","data":{"cleared_tables":["attack_queue","parameter_pool","raw_requests","api_metadata","sqlite_sequence"]}}
```

#### 步骤 4：配置 LLM（可选但推荐）

**前置**：有 LLM API Key
**后置**：LLM 功能可用（AI 剪枝、AI 越权验证、参数推荐、风险识别、AI 生成 POC）

```bash
curl -X PUT http://127.0.0.1:8899/api/config/llm \
  -H "Content-Type: application/json" \
  -d '{
    "enable": true,
    "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "api_key": "sk-xxx",
    "model": "glm-5.2",
    "verify_ssl": true
  }'
```

> **默认配置**：LLM 默认开启，但只启用 `analyze_result`（AI 剪枝 + AI 越权验证）。
> `extract_params` / `generate_values` / `identify_risk` 默认关闭，避免无谓的 LLM 调用。
> 如需开启其他 LLM 功能，在 body 中设置对应字段为 `true`。
>
> 不配置 LLM 时：参数推荐用启发式，AI 剪枝用启发式打分，AI 越权验证仍可走启发式分析，AI 生成 POC 仅支持手动 modifications。

#### 步骤 5：设置黑名单（可选）

**前置**：无
**后置**：黑名单参数不会被提取为攻击目标

```bash
curl -X PUT http://127.0.0.1:8899/api/config/blacklist \
  -H "Content-Type: application/json" \
  -d '{"params": "limit,offset,page,size"}'
```

#### 步骤 6：开启 Autorize

**前置**：用户标识已配置
**后置**：通过 Burp 代理的流量会被 Autorize 拦截并处理

```bash
curl -X POST http://127.0.0.1:8899/api/action/autorize \
  -H "Content-Type: application/json" \
  -d '{"on": true}'
```

### 阶段 2：流量采集

#### 步骤 7：发送流量（通过 Burp 代理）

**前置**：Autorize 已开启
**后置**：raw_requests 表中有流量记录，流量被自动标记为 User 1 或 User 2

```bash
# 用 User 1 的 Cookie 通过 Burp 代理访问目标
curl -x http://127.0.0.1:8080 \
  -H "Cookie: session=user1_session_token" \
  -H "X-User-Profile: user1_username" \
  http://target/api/shop/order/detail?order_id=10

# 用 User 2 的 Cookie 发送
curl -x http://127.0.0.1:8080 \
  -H "Cookie: session=user2_session_token" \
  -H "X-User-Profile: user2_username" \
  http://target/api/shop/order/detail?order_id=20
```

> **关键**：流量必须经过 Burp 代理（`-x http://127.0.0.1:8080`），否则不会被捕获。
> 发送用户业务请求（查看订单、个人资料等），覆盖尽量多的 API 端点。

#### 步骤 7.5：刷新缓存流量的用户标识（可选）

**前置**：流量已采集，且在发送流量后才配置 `identify_string` 映射
**后置**：`auto:Cookie:xxx` 的临时标识更新为对应的用户名（如 "User 1"）

```bash
# 先用 dry_run 预览可刷新的缓存数量
curl -X POST http://127.0.0.1:8899/api/action/refresh-traffic-identity \
  -H "Content-Type: application/json" \
  -d '{"dry_run": true}'

# 实际刷新
curl -X POST http://127.0.0.1:8899/api/action/refresh-traffic-identity \
  -H "Content-Type: application/json" \
  -d '{}'
```

响应示例：
```json
{
  "status": "ok",
  "data": {
    "total_cached": 10,
    "refreshed": 10,
    "still_unmapped": 0,
    "details": [
      {"request_id": 5, "old_identifier": "auto:Cookie:eyJ1c2Vy...", "new_identifier": "User 1"}
    ]
  }
}
```

> 仅刷新 `user_identifier` 以 `auto:` 开头或为空的记录，已正确标识的流量不受影响。

### 阶段 3：攻击生成与执行

#### 步骤 8：提取参数

**前置**：raw_requests 中有流量
**后置**：parameter_pool 表填充可变参数（如 order_id, user_id 等）

```bash
curl -X POST http://127.0.0.1:8899/api/action/extract-params
# 预期: {"status":"ok","message":"Parameter extraction completed"}
```

#### 步骤 9：获取参数推荐

**前置**：参数已提取
**后置**：得到推荐的参数替换值

```bash
curl -X POST http://127.0.0.1:8899/api/recommend \
  -H "Content-Type: application/json" \
  -d '{"key": "order_id", "location": "Auto"}'
```

响应示例：
```json
{
  "status": "ok",
  "data": {
    "recommendations": [
      {
        "rank": 1,
        "key": "order_id",
        "value": "20",
        "source_user": "User 2",
        "endpoint": "/api/shop/order/detail",
        "score": 100
      }
    ]
  }
}
```

#### 步骤 10：应用推荐值

**前置**：有推荐结果
**后置**：推荐值写入用户规则，后续生成攻击时会使用

```bash
# 应用单条推荐
curl -X POST http://127.0.0.1:8899/api/recommend/apply \
  -H "Content-Type: application/json" \
  -d '{"user_id": 1, "key": "order_id", "value": "20", "location": "Query"}'

# 或应用全部推荐
curl -X POST http://127.0.0.1:8899/api/recommend/apply \
  -H "Content-Type: application/json" \
  -d '{"apply_all": true}'
```

#### 步骤 11：生成攻击

**前置**：参数已提取，推荐值已应用
**后置**：attack_queue 表中有 PENDING 状态的攻击

```bash
curl -X POST http://127.0.0.1:8899/api/action/generate-attacks
# 预期: {"status":"ok","message":"Attacks generated"}
```

#### 步骤 12：执行攻击

**前置**：有 PENDING 攻击
**后置**：攻击状态变为 CHECKING_SKIPPED 或 VULNERABLE，response_data 填充

```bash
# 批量执行 GET 攻击
curl -X POST http://127.0.0.1:8899/api/action/batch-attack-get \
  -H "Content-Type: application/json" \
  -d '{"limit": 50}'

# 或执行单个攻击
curl -X POST http://127.0.0.1:8899/api/action/execute-attack \
  -H "Content-Type: application/json" \
  -d '{"attack_id": 1}'
```

### 阶段 4：结果查询

#### 步骤 13：查询攻击结果

**前置**：攻击已执行
**后置**：获得攻击列表和判定结果

```bash
# 查询所有漏洞
curl "http://127.0.0.1:8899/api/attacks?status=VULNERABLE&limit=20"

# 过滤 AI 验证过的攻击（高优先级）
curl "http://127.0.0.1:8899/api/attacks?ai_verified=true&limit=20"

# 查询单条详情（含完整报文）
curl http://127.0.0.1:8899/api/attacks/1
```

攻击详情响应包含：
- `attack_request` / `attack_response`：fuzz 产生的报文
- `original_request_headers` / `original_request_body`：原始请求
- `original_response_headers` / `original_response_body`：原始响应
- `ai_verified` / `ai_verification_result`：AI 验证结果

### 阶段 5：AI 辅助流程（可选但推荐）

> 以下三个功能可按需调用，顺序不限。建议先生成 POC → 执行 → 剪枝 → 验证。

#### 步骤 A：AI 生成 POC（补充攻击）

**前置**：raw_requests 中有流量
**后置**：attack_queue 中新增 PENDING 攻击

```bash
# 方式 1：手动指定参数修改（推荐，节约 LLM 算力）
curl -X POST http://127.0.0.1:8899/api/action/ai-generate-poc \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": 1,
    "modifications": [
      {
        "param": "order_id",
        "original_value": "10",
        "new_value": "11",
        "location": "QUERY",
        "reason": "swap to another user order"
      },
      {
        "param": "X-User-Profile",
        "original_value": "user1_username",
        "new_value": "user2_username",
        "location": "HEADER",
        "reason": "swap header to impersonate user 2"
      }
    ],
    "target_user": "User 2"
  }'

# 方式 2：LLM 自动生成修改建议
curl -X POST http://127.0.0.1:8899/api/action/ai-generate-poc \
  -H "Content-Type: application/json" \
  -d '{"request_id": 1, "use_llm": true}'
```

响应示例：
```json
{
  "status": "ok",
  "data": {
    "generated": 3,
    "attack_ids": [47, 48, 49],
    "modifications": [
      {"param": "order_id", "new_value": "30", "location": "QUERY", "reason": "Cross-user swap..."}
    ]
  }
}
```

> 支持 `QUERY` / `PATH` / `BODY` / `HEADER` 四种位置。
> **策略**：先用步骤 11 机器生成一批攻击，再用本接口让 AI 补充遗漏的参数交换。

#### 步骤 B：AI 剪枝（删除低价值 POC）

**前置**：有 PENDING 攻击
**后置**：低分 PENDING 攻击被删除，减少执行负担

```bash
curl -X POST http://127.0.0.1:8899/api/action/prune-attacks \
  -H "Content-Type: application/json" \
  -d '{"limit": 50, "score_threshold": 30, "use_llm": true}'
```

响应示例：
```json
{
  "status": "ok",
  "data": {
    "total": 7, "pruned": 2, "remaining": 5,
    "pruned_ids": [49, 50],
    "details": [
      {"attack_id": 51, "score": 92, "reason": "classic IDOR swap...", "pruned": false},
      {"attack_id": 49, "score": 10, "reason": "non-existent resource...", "pruned": true}
    ]
  }
}
```

LLM 打分标准：
- 90-100：交换真实用户标识参数（高价值 IDOR）
- 60-89：交换数字 ID（可能是用户资源）
- 30-59：交换通用参数（分页、过滤）
- 0-29：重复或无意义攻击

> `use_llm=false` 时用启发式快速过滤，不调用 LLM。
> 剪枝使用参数化 DELETE，不影响自增序列和索引。

#### 步骤 C：AI 越权验证（深度判断）

**前置**：攻击已执行（非 PENDING）
**后置**：`ai_verified=true`，`ai_verification_result` 填充，状态可能升级为 VULNERABLE

```bash
curl -X POST http://127.0.0.1:8899/api/action/ai-verify \
  -H "Content-Type: application/json" \
  -d '{
    "attack_id": 40,
    "extra_context": "Security agent: testing IDOR on order detail API",
    "force_reverify": true
  }'
```

响应示例：
```json
{
  "status": "ok",
  "data": {
    "attack_id": 40,
    "ai_result": {
      "result": "VULNERABLE",
      "confidence": 0.9,
      "reason": "Attack response returns valid business data...",
      "verified": true,
      "source": "heuristic"
    },
    "new_status": "VULNERABLE"
  }
}
```

验证逻辑（两层）：
1. **启发式分析**（优先）：对比原始响应和攻击响应，检测是否返回业务数据。能判定时直接返回，不调 LLM
2. **LLM 深度分析**：启发式无法判定时，将完整报文（原始 + 攻击的 request & response）发给 LLM

> `source` 字段标识结果来源：`heuristic`（启发式）或 `llm`（LLM）。
> AI 验证结果**优先级高于** LLM 自动验证，在面板中以 `ai_verified` 标识。

#### 步骤 D：删除无意义攻击

```bash
curl -X DELETE http://127.0.0.1:8899/api/attacks/41
# 预期: {"status":"ok","message":"Attack 41 deleted"}
# 已执行的攻击（非 PENDING）不允许删除，返回 400
```

### 阶段 6：收尾

#### 步骤 14：关闭 Autorize

```bash
curl -X POST http://127.0.0.1:8899/api/action/autorize \
  -H "Content-Type: application/json" \
  -d '{"on": false}'
```

---

## 六、响应格式

所有响应为统一 JSON：

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

HTTP 状态码：
- `200`：成功
- `400`：参数错误
- `404`：资源不存在或路由未匹配
- `500`：服务器内部错误

---

## 七、注意事项

1. **API Key 掩码**：`GET /api/config` 返回的 `api_key` 为掩码格式（如 `sk-t****5678`），写入时传完整 key。
2. **headers_text 同步**：`PUT /api/config/user/{id}/identify` 设置 `headers_text` 后，会实时同步到 Burp GUI。重载插件后 GUI 状态可能丢失，需重新配置。
3. **GUI 双入口**：API 操作会实时同步到 GUI，用户也可在 GUI 上手动操作，两者共享同一配置。
4. **无认证**：API 服务无认证，监听 0.0.0.0，请确保网络环境安全。
5. **Jython 2.7**：插件代码为 Jython 2.7 语法，API 响应中字符串为 unicode（`u'wal'`）。
6. **端口占用**：如果重启插件遇到 `Address already in use`，在 Burp 中 Unload 再 Load 插件。
7. **BLOB 字段**：`executed_request_data`、`response_data` 等为 BLOB 类型，API 返回字符串形式。如果 API 返回空但数据库有值，可能是 BLOB 读取问题，可直接查库验证。
8. **流量自动检测**：未配置 `identify_string` 时，插件自动从 `Cookie` / `X-Auth-Token` / `Authorization` 等头提取 `auto:Cookie:xxx` 临时标识缓存流量。配置映射后调用 `refresh-traffic-identity` 刷新。
9. **Header upsert 语义**：`POST /api/user/{id}/header` 对同名 header 为替换（非新增），AI agent 可用此接口覆盖已存在的请求头。
10. **LLM 默认配置**：LLM 默认开启但只启用 `analyze_result`（AI 剪枝 + AI 越权验证），`extract_params` / `generate_values` / `identify_risk` 默认关闭。

---

## 八、测试

### 单元测试（不需要 Burp）

```bash
python tests/test_api.py
# 45 tests, all passing
```

### AI 功能端到端测试（需要 Burp + LLM 配置）

```bash
python tests/test_ai_features.py
```

测试三个 AI 辅助功能：剪枝打分、越权验证、POC 生成，含数据库回写验证。

### 端到端测试 v3（需要 Burp + 测试环境 + LLM）

```bash
python tests/test_e2e_v3.py
```

完整流程测试：clear-db 清空 → autorize on → 登录发流量 → 自动检测缓存 → refresh 刷新 → 提取参数 → 生成攻击 → 批量执行 → AI 剪枝 → AI 越权验证 → autorize off。

### API 可用性测试（需要 Burp 运行插件）

```bash
python tests/test_agent.py --api-only
```

### 端到端测试（需要 Burp + 测试环境）

```bash
python tests/test_agent.py
```

端到端测试自动完成：登录获取 Cookie → 配置用户标识 → 设置 Header → 开启 Autorize → 发送流量 → 提取参数 → 获取推荐 → 生成攻击 → 批量执行 → AI 剪枝 → AI 验证 → AI 生成 POC → 查询结果。

---

## 九、AI 辅助功能详解

三个 AI 辅助接口让外部 AI agent 介入 IDOR 检测流程，提升效率和准确度。

### Feature 1: AI 剪枝 — `POST /api/action/prune-attacks`

对 PENDING 状态的攻击进行价值评分，删除低价值 POC，减轻模型负担。

| 参数 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `limit` | int | 50 | 最多评分多少条 |
| `score_threshold` | int | 30 | 低于此分数则删除 |
| `use_llm` | bool | true | 是否使用 LLM 评分（false 用启发式） |

- 使用参数化 DELETE，不影响自增序列和索引
- LLM 打分：90-100 高价值 IDOR，60-89 中等，30-59 通用参数，0-29 无意义
- `use_llm=false` 时使用启发式规则快速过滤

### Feature 2: AI 越权验证 — `POST /api/action/ai-verify`

越权 AI agent 查看完整报文（fuzz 产生的 request/response + 原始 request/response），提供更精确的漏洞判断。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `attack_id` | int | 是 | 要验证的攻击 ID |
| `extra_context` | string | 否 | agent 提供的额外上下文信息 |
| `force_reverify` | bool | 否 | 强制重新验证（默认 false，已验证过则返回已有结果） |

- 结果写入 `ai_verification_result` 和 `ai_verified` 字段
- **优先级高于 LLM 自动验证**，在面板中以 `ai_verified` 标识
- 先走启发式分析（`_analyze_idor_with_heuristics`），若能判定则跳过 LLM 调用
- 启发式无法判定时，调用 LLM 进行深度分析
- 攻击详情接口返回完整报文供 agent 审查：
  - `attack_request` / `attack_response`：fuzz 产生的报文
  - `original_request_headers` / `original_request_body` / `original_response_headers` / `original_response_body`：原始报文

### Feature 3: AI 生成 POC — `POST /api/action/ai-generate-poc`

让 AI agent 介入 POC 生成过程，修改 path/query/body/header 参数。

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `request_id` | int | 是 | 原始请求 ID（raw_requests.id） |
| `modifications` | array | 否 | 手动指定参数修改（不传则 LLM 自动生成） |
| `target_user` | string | 否 | 目标用户标识 |
| `use_llm` | bool | 否 | modifications 为空时是否用 LLM 自动生成（默认 true） |

`modifications` 每项结构：
```json
{
  "param": "order_id",
  "original_value": "10",
  "new_value": "11",
  "location": "QUERY",
  "reason": "swap to another user order"
}
```

- 支持 `QUERY` / `PATH` / `BODY` / `HEADER` 四种位置
- 先依赖工具机器生成一部分，再让 AI agent 做小调整和补充，节约算力
- 生成的攻击状态为 PENDING，可直接进入执行队列
