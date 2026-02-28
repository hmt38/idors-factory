# IDOR 检测插件开发计划 (基于 Autorize)

## 1. 项目概览
本项目的目标是开发一个 Burp Suite 扩展插件，用于自动检测不安全的直接对象引用 (IDOR) 漏洞。与专注于重放并剔除/修改会话令牌的标准 Autorize 插件不同，本插件专注于两个已认证用户（用户 A 和用户 B）之间的**参数交换**。

## 2. 核心工作流
1.  **流量采集**: 被动监听来自用户 A（攻击者）和用户 B（受害者）的 HTTP 流量。
2.  **参数提取**: 解析并存储从捕获的请求中提取的参数（查询参数 Query、请求体 Body、路径 Path）。
3.  **攻击生成**: 通过将用户 A 的参数替换为用户 B 的值（反之亦然），针对相同的 API 端点自动生成攻击向量。
4.  **重放与分析**: 重放生成的请求并分析响应，以确定用户 A 是否成功访问了用户 B 的资源。

## 3. 架构与数据库设计

### 3.1 数据库 (SQLite)
插件将使用存储在插件目录中的本地 SQLite 数据库 (`autorize_idor.db`)。

**数据表:**
1.  `raw_requests`: 存储原始流量。
    *   `id`: 主键 (PK)
    *   `user`: 'A' 或 'B'
    *   `method`: GET, POST 等
    *   `host`: target.com
    *   `path`: /api/v1/user/123
    *   `path_template`: /api/v1/user/{id} (归一化路径)
    *   `headers`: JSON 格式
    *   `body`: 原始文本/字节
    *   `timestamp`: 捕获时间
    *   `processed`: 布尔值 (如果参数已被提取则为 True)

2.  `parameter_pool`: 存储提取的参数。
    *   `id`: 主键 (PK)
    *   `request_id`: 外键 (FK)，指向 raw_requests
    *   `api_signature`: method + host + path_template
    *   `param_name`: id, account_no 等
    *   `param_value`: 123, admin 等
    *   `param_location`: QUERY, BODY_JSON, PATH
    *   `user`: 'A' 或 'B'

3.  `attack_queue`: 存储生成的攻击请求。
    *   `id`: 主键 (PK)
    *   `original_request_id`: 外键 (FK) (被修改的基础请求，例如用户 A 的请求)
    *   `target_user`: 'B' (我们试图访问其数据的受害者)
    *   `payload_description`: "将 'id' 替换为用户 B 的值"
    *   `request_data`: 完整的 HTTP 请求数据块
    *   `status`: PENDING (待发送), SENT (已发送), CONFIRMED (需确认，针对危险方法)
    *   `response_data`: 完整的 HTTP 响应数据块
    *   `response_code`: HTTP 状态码
    *   `vulnerability_score`: 0-100 (IDOR 的可能性)

### 3.2 模块
*   **TrafficListener**: 挂钩 Burp 的 `IHttpListener`。根据配置的请求头/Cookie 识别用户 A/B。
*   **ParameterExtractor**:
    *   **Path**: 使用正则/启发式算法识别路径中的 ID（例如数字段、UUID）。
    *   **Query**: 标准 URL 解析。
    *   **Body**: JSON 解析器（初始范围）。
*   **AttackEngine**:
    *   通过 `api_signature` 匹配用户 A 和用户 B 的请求。
    *   生成排列组合：
        *   替换单个参数。
        *   替换所有参数。
*   **Replayer**: 执行请求。处理 "安全" (GET) 与 "不安全" (POST/DELETE) 的逻辑。
*   **Analyzer**: 将攻击响应与用户 A 的原始响应及用户 B 的原始响应进行对比。

## 4. 实施步骤

### 第一阶段：基础设施与流量采集
*   **目标**: 成功将用户 A 和用户 B 的流量记录到数据库中。
*   **UI**: 在 Autorize 中添加 "用户配置" 标签页。
    *   输入: `用户 A 标识符` (例如: "Cookie: sess=A")。
    *   输入: `用户 B 标识符` (例如: "Cookie: sess=B")。
*   **逻辑**:
    *   初始化 SQLite 数据库。
    *   实现 `IHttpListener`。
    *   检测用户身份。
    *   存储原始请求。

### 第二阶段：参数提取
*   **目标**: 填充 `parameter_pool`。
*   **逻辑**:
    *   实现 `PathNormalizer`: 将 `/users/101` 转换为 `/users/{id}`。
    *   实现 `Extractor`:
        *   从路径中提取 `101`。
        *   从查询参数中提取 `?q=search`。
        *   从请求体中提取 `{"role": "admin"}`。

### 第三阶段：攻击生成策略
*   **目标**: 创建智能攻击载荷。
*   **逻辑**:
    *   触发方式: 定时任务或 "生成攻击" 按钮。
    *   查找交集: 用户 A 和用户 B 都访问过的 API。
    *   对于每个 API:
        *   获取用户 A 的请求。
        *   查找用户 B 在*相同*参数下的值。
        *   构造新请求: 用户 A 的会话 + 用户 B 的 ID。

### 第四阶段：执行与分析
*   **目标**: 发送请求并标记漏洞。
*   **逻辑**:
    *   **安全模式**: 自动发送 GET 请求。
    *   **手动模式**: 将 POST/PUT/DELETE 请求加入队列等待用户批准。
    *   **检测**:
        *   如果状态码 == 200 且 内容 != 错误: 潜在的 IDOR。
        *   对比 Content-Length 和请求体相似度与用户 B 的实际响应。

## 5. UI 设计
*   **配置标签页 (Configuration Tab)**:
    *   用户 A/B 字符串配置。
    *   过滤器 (范围 Scope, 文件扩展名)。
    *   "自动发送安全请求" 复选框。
*   **IDOR 结果标签页 (IDOR Results Tab)**:
    *   表格显示: API 方法/路径, 被替换的参数, 状态码, 结果 (是否易受攻击?)。
    *   请求/响应查看器。

## 6. 下一步计划
1.  初始化数据库 (`db/database.py`)。
2.  在 `authorization.py` 中实现 `TrafficListener` 以捕获并标记流量。
