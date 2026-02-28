# Autorize + IDOR Detection Plugin

本插件是在原版 Autorize 基础上进行的二次开发，新增了 **智能越权 (IDOR) 检测** 功能。它通过采集不同用户的流量，自动分析参数特征，并构造重放攻击来检测越权漏洞。

## 主要功能

1.  **多用户流量采集**: 自动识别并区分 User A（攻击者）和 User B（受害者）的流量。
2.  **智能参数提取** (开发中): 自动从流量中提取 URL 路径参数、Query 参数和 JSON Body 参数。
3.  **越权攻击重放** (开发中): 基于提取的参数，自动构造并发送越权探测请求。

## 安装指南

由于本插件使用了 SQLite 数据库来存储大量分析数据，在 Jython 环境下运行需要额外的 JDBC 驱动配置。

### 1. 环境要求
- **Burp Suite**: Professional 或 Community 版本。
- **Jython**: 版本 2.7.x (推荐 2.7.3)。

### 2. 手动下载依赖与配置 (必须!)
由于 Jython 不包含 C 语言实现的 `sqlite3` 模块，我们需要使用 Java 的 JDBC 驱动，并将其手动添加到 Burp 的 Java 环境中。

1.  **下载驱动**: 请访问以下链接下载 `sqlite-jdbc` 的 JAR 包：
    - 下载地址: [sqlite-jdbc-3.42.0.0.jar](https://github.com/xerial/sqlite-jdbc/releases/download/3.42.0.0/sqlite-jdbc-3.42.0.0.jar)
    - 或者访问 Maven Central 搜索 `sqlite-jdbc` 下载最新版。

2.  **放置驱动**: 将下载好的 `.jar` 文件放入插件的 `lib` 目录中：
    ```
    E:\idors-tools\test\Autorize\lib\sqlite-jdbc-3.42.0.0.jar
    ```
    *(注: 如果 `lib` 目录不存在，请手动创建)*

3.  **配置 Burp Java 环境 (关键步骤)**:
    - 在 Burp Suite 中，点击顶部菜单 **Extensions** (旧版为 Extender) -> **Extensions settings** (或 Options)。
    - 找到 **Java Environment** 设置区域。
    - 在 **Folder for loading library JARs** (加载库 JAR 的文件夹) 中，点击 **Select folder**。
    - 选择本插件的 `lib` 目录：`E:\idors-tools\test\Autorize\lib`。
    - **重启 Burp Suite** (或重新加载插件) 以使更改生效。

### 3. 加载插件
1.  打开 Burp Suite -> **Extensions** -> **Add**。
2.  Extension type 选择 **Python**。
3.  Extension file 选择 `E:\idors-tools\test\Autorize\Autorize.py`。
4.  点击 Next，确保 Output 标签页没有报错。

## 使用说明

### 第一阶段：流量采集 (Traffic Collection)

目前插件已完成第一阶段开发，即**流量的自动识别与采集**。

1.  **配置用户标识**:
    - 加载插件后，进入 **Autorize** 标签页 -> **Configuration** 子标签页。
    - 找到 **"User Identification (String Match)"** 区域。
    - **User A Identification String**: 填入能标识 User A 的字符串（例如 Cookie 中的 `session=UserA`）。
    - **User B Identification String**: 填入能标识 User B 的字符串（例如 Cookie 中的 `session=UserB`）。

2.  **生成流量**:
    - 打开浏览器，配置好 Burp 代理。
    - 登录 User A 账号，访问业务页面（如“个人中心”、“订单列表”）。
    - 登录 User B 账号，访问**相同**的业务页面。

3.  **验证采集**:
    - 插件会自动检测流量。如果请求头包含上述配置的字符串，该请求会被自动记录到 `autorize_traffic.db` 数据库的 `raw_requests` 表中。
    - 您可以检查插件目录下的 `autorize_traffic.db` 文件大小是否增加，以确认数据是否写入成功。

## 后续开发计划

- **阶段二**: 实现参数提取算法，从 `raw_requests` 中提取出 ID、订单号等敏感参数存入 `parameter_pool`。
- **阶段三**: 实现攻击引擎，自动组合 User A 的身份凭证与 User B 的参数进行重放测试。
