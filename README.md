# Autorize + IDOR Detection Plugin

本插件是在原版 Autorize 基础上进行的二次开发，新增了 **智能越权 (IDOR) 检测** 功能。它通过采集不同用户的流量，自动分析参数特征，并构造重放攻击来检测越权漏洞。

## 主要功能

1.  **多用户流量采集**: 自动识别并区分 User A（攻击者）和 User B（受害者）的流量。
2.  **智能参数提取**: 自动从流量中提取 URL 路径参数、Query 参数和 JSON Body 参数。
3.  **越权攻击重放**: 基于提取的参数，自动构造并发送越权探测请求。
4.  **智能结果分析**: 结合状态码分析与 LLM（大模型）辅助判断，准确识别越权漏洞。

## 安装指南

由于本插件使用了 SQLite 数据库来存储大量分析数据，在 Jython 环境下运行需要额外的 JDBC 驱动配置。

### 1. 环境要求
- **Burp Suite**: Professional 或 Community 版本。
- **Jython**: 版本 2.7.x (推荐 2.7.3)。

### 2. Jython 环境配置 (必须!)
如果您尚未在 Burp Suite 中配置 Python 环境，请按照以下步骤操作：

1.  **下载 Jython**:
    - 访问 [Jython 官网](https://www.jython.org/download) 下载 **Jython Standalone JAR** (例如 `jython-standalone-2.7.3.jar`)。
    - 将下载的 JAR 文件保存到您方便管理的目录中。

2.  **配置 Burp Python 环境**:
    - 在 Burp Suite 中，点击顶部菜单 **Extensions** (旧版为 Extender) -> **Extensions settings** (或 Options)。
    - 找到 **Python Environment** 设置区域。
    - 点击 **Select file**，选择刚才下载的 `jython-standalone-2.7.3.jar` 文件。

### 3. JDBC 驱动配置 (必须!)
由于 Jython 不包含 C 语言实现的 `sqlite3` 模块，我们需要使用 Java 的 JDBC 驱动。**本插件已内置该驱动，您无需额外下载。**

1.  **定位驱动文件**:
    - 插件目录下的 `lib` 文件夹中已包含 `sqlite-jdbc-3.42.0.0.jar`。
    - 路径示例: `E:\idors-tools\test\Autorize\lib`

2.  **配置 Burp Java 环境 (关键步骤)**:
    - 在 Burp Suite 中，点击顶部菜单 **Extensions** -> **Extensions settings**。
    - 找到 **Java Environment** 设置区域。
    - 在 **Folder for loading library JARs** (加载库 JAR 的文件夹) 中，点击 **Select folder**。
    - 选择本插件的 `lib` 目录：`E:\idors-tools\test\Autorize\lib`。
    - **重启 Burp Suite** (或重新加载插件) 以使更改生效。

### 4. 加载插件
1.  打开 Burp Suite -> **Extensions** -> **Add**。
2.  Extension type 选择 **Python**。
3.  Extension file 选择 `E:\idors-tools\test\Autorize\Autorize.py`。
4.  点击 Next，确保 Output 标签页没有报错。

## 使用说明

### 第一阶段：流量采集 (Traffic Collection)

1.  **配置用户标识**:
    - 加载插件后，进入 **Autorize** 标签页 -> **Users** 子标签页。
    - 添加用户（如 User A 和 User B），并分别配置他们的 Cookie/Token。
    - 确保在 Header配置中填写能唯一标识该用户的字符串（例如 Cookie 中的 `session=UserA`），以便插件自动归类流量。

2.  **生成流量**:
    - 打开浏览器，配置好 Burp 代理。
    - 登录 User A 账号，访问业务页面（如“个人中心”、“订单列表”）。
    - 登录 User B 账号，访问**相同**的业务页面。
    - 插件会自动检测流量并记录到数据库中。

### 第二阶段：参数提取 (Parameter Extraction)

1.  **自动提取**:
    - 插件会在后台自动分析采集到的流量。
    - 点击 **Configuration** -> **Extract Params** 按钮可手动触发提取。
    - 插件会识别 URL 路径参数（如 `/users/123` 中的 `123`）、Query 参数（`?id=123`）以及 JSON Body 中的参数。

### 第三阶段：攻击生成 (Attack Generation)

1.  **生成攻击**:
    - 切换到 **IDOR Attacks** 标签页。
    - 点击 **Generate Attacks** 按钮。
    - 插件会分析 User A 的请求，尝试将其中的敏感参数（如 ID）替换为 User B 的对应值。
    - 生成的攻击列表会显示在左侧表格中。

### 第四阶段：执行与检测 (Execution & Detection)

1.  **审查攻击列表**:
    - 在 **IDOR Attacks** 面板中查看生成的攻击向量。
    - **高危操作**（如 `POST`, `PUT`, `DELETE` 或包含 `delete`, `update` 等关键词的 API）会以 **红色高亮** 显示，提示需人工确认。

2.  **执行攻击**:
    - 选中一条或多条攻击记录。
    - 点击 **Execute Selected** 按钮。
    - 插件会重放请求：保持 User A 的 Session（Cookie/Header），但参数已替换为 User B 的值。

3.  **结果分析**:
    - **Diff 面板**: 在右侧详情区查看 **Diff** 标签页，清晰对比原始请求与攻击请求的差异。
    - **状态与颜色**:
        - **绿色 (SAFE)**: 攻击失败，目标安全。
        - **红色 (VULNERABLE)**: 攻击成功，存在越权漏洞（需开启 LLM）。
        - **黄色 (SENT)**: 请求已发送，等待检测或未开启智能分析。
    - **LLM 智能分析**:
        - 在 **Configuration** 中配置 LLM (OpenAI 兼容接口)。
        - 开启 LLM 后，插件会自动分析响应内容，判断是否存在越权。
