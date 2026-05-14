# vulnmonitor
## 一、项目背景与目标

### 1.1 项目背景

随着网络安全威胁的日益复杂化，0day和1day漏洞的爆发频率持续上升，企业面临着前所未有的安全挑战。传统的漏洞管理方式存在以下痛点：

1. **信息分散**：漏洞情报散落在多个数据源（CISA、OSCS、厂商PSIRT、漏洞研究社区等），安全团队需要手动聚合多源信息
2. **响应滞后**：从漏洞披露到企业感知存在时间差，缺乏自动化监控和实时推送机制
3. **噪声干扰**：大量低价值漏洞信息淹没关键威胁，缺乏智能过滤和优先级排序
4. **验证困难**：缺少PoC/EXP的快速检索能力，影响漏洞风险评估和应急响应效率

参考业界成熟的漏洞情报聚合方案（如vuln-monitor、多源漏洞爬取工具），本项目旨在构建一套企业级漏洞情报监控系统，实现自动化采集、智能去重、精准过滤和实时告警。

### 1.2 项目目标

#### 核心目标
- **多源聚合**：整合17+权威数据源，覆盖厂商PSIRT、漏洞披露平台、Exploit数据库、在野利用情报等
- **智能过滤**：聚焦高价值漏洞（RCE、远程代码执行等），通过正则匹配和关键词规则过滤噪声
- **增量去重**：基于CVE ID + 漏洞名称 + 日期的双重去重机制，避免重复告警
- **实时推送**：支持Telegram、钉钉、邮件等多渠道告警推送，确保第一时间触达安全团队
- **可视化查询**：提供Web仪表盘和CLI双模式，支持多维度检索和统计分析

#### 量化指标
- 数据采集延迟：< 15分钟（从源发布到系统入库）
- 去重准确率：> 99%
- 误报率：< 5%
- 系统可用性：> 99.5%
- 支持并发数据源：≥ 20个

---

## 二、需求分析

### 2.1 功能性需求

#### 2.1.1 数据采集模块
- **数据源接入**：支持以下类型数据源
  - 厂商PSIRT：Fortinet、PaloAlto、Cisco、Microsoft MSRC等
  - 漏洞披露：ZDI、watchTowr、DailyCVE、CISA KEV
  - Exploit/PoC：Sploitus、GitHub、PoC-in-GitHub
  - 漏洞研究：Horizon3、Rapid7
  - 国内情报：奇安信威胁情报中心、长亭Rivers、微步在线ThreatBook、OSCS
- **采集策略**：支持定时轮询（默认每15分钟）、增量抓取、断点续传
- **数据解析**：自动提取CVE编号、漏洞标题、描述、严重等级、受影响产品、修复建议、参考链接

#### 2.1.2 数据处理模块
- **智能去重**：
  - 主键去重：基于CVE ID唯一标识
  - 辅助去重：漏洞名称 + 发布日期组合校验
  - TTL机制：60天自动清理过期记录
- **分类过滤**：
  - RCE聚焦：60+正则表达式匹配远程代码执行特征
  - 资产关键词：500+常见资产/产品关键词库
  - 排除规则：过滤XSS、CSRF、LPE、DoS等低优先级漏洞
- **质量评分**：根据数据完整性、来源权威性、在野利用情况计算漏洞优先级

#### 2.1.3 数据存储模块
- **数据库选型**：SQLite（WAL模式，支持并发读写）
- **表结构设计**：
  - `vulnerabilities`：漏洞主表（CVE、标题、描述、严重等级、来源、发布时间、推送状态）
  - `sources`：数据源配置表
  - `push_logs`：推送日志表
  - `stats`：统计汇总表
- **索引优化**：CVE字段唯一索引、时间范围索引、来源字段索引

#### 2.1.4 告警推送模块
- **推送渠道**：
  - Telegram Bot（优先推荐，支持Markdown格式）
  - 钉钉机器人（Webhook方式，适配企业内部通讯）
  - 企业微信机器人（Webhook方式，支持文本/卡片消息）
  - 飞书机器人（Webhook方式，支持富文本/交互式卡片）
  - 邮件通知（SMTP协议，支持HTML模板）
- **推送策略**：
  - 实时推送：新漏洞入库后立即推送
  - 批量汇总：每日/每周生成漏洞摘要报告
  - 限流控制：同一CVE跨源只推送一次，避免告警风暴
- **消息格式**：
  - 简洁版：CVE编号 + 标题 + 严重等级 + 来源
  - 详细版：包含描述、受影响产品、修复建议、参考链接
  - JSON格式：便于二次开发和API集成
- **渠道配置**：
  - Telegram：Bot Token + Chat ID
  - 钉钉：Webhook URL + 签名密钥（可选）
  - 企业微信：Webhook URL（群机器人）
  - 飞书：Webhook URL + 签名验证（可选）
  - 邮件：SMTP服务器 + 账号密码 + 收件人列表

#### 2.1.5 查询展示模块
- **Web仪表盘**：
  - 暖色卡片式布局，实时展示最新漏洞
  - 搜索过滤：按CVE、来源、关键词、时间范围筛选
  - 药丸式标签：快速切换数据源、推送状态、严重等级
  - 安全加固：CSP、X-Frame-Options、nosniff头，仅绑定localhost（SSH隧道访问）
- **CLI命令行**：
  - `fetch`：执行数据采集和推送
  - `query`：多格式查询（简表/详细/JSON）
  - `brief`：生成通知友好格式的摘要
  - `stats`：统计数据分析
  - `rebuild`：回填历史记录
- **AI交互**：集成Claude Code skill，支持自然语言查询（如"最近有什么新漏洞"、"查一下CVE-2026-1340"）

#### 2.1.6 PoC搜索模块
- **GitHub集成**：调用GitHub API搜索相关PoC/EXP代码
- **关键词匹配**：基于CVE编号、漏洞名称、受影响产品自动生成搜索词
- **结果展示**：返回仓库链接、Star数、最后更新时间，辅助漏洞验证

#### 2.1.7 报告生成模块
- **自动报告**：周期性生成Markdown格式漏洞周报/月报
- **内容结构**：漏洞概览、高危漏洞详情、趋势分析、处置建议
- **参考链接**：自动格式化官方公告、技术博客、PoC仓库链接

### 2.2 非功能性需求

#### 2.2.1 性能要求
- 单次采集耗时：< 5分钟（20个数据源并行）
- 查询响应时间：< 1秒（万级数据量）
- 推送延迟：< 30秒（从入库到送达）

#### 2.2.2 可靠性要求
- 文件锁机制：防止并发采集导致数据冲突
- 失败重试：网络异常自动重试3次，指数退避
- 日志轮转：保留最近30天日志，单文件最大10MB
- 健康检查：定时检测数据源可达性，异常告警

#### 2.2.3 安全性要求
- 配置加密：敏感信息（Token、API Key）加密存储
- 访问控制：Web仪表盘仅绑定127.0.0.1，强制SSH隧道
- 输入校验：所有用户输入进行 sanitization，防止注入攻击
- 依赖审计：定期扫描第三方库漏洞（pip audit）

#### 2.2.4 可维护性要求
- 模块化设计：采集器、处理器、推送器独立解耦
- 配置外置：环境变量 + YAML配置文件，支持动态调整
- 一键部署：提供deploy.sh脚本，自动安装依赖、配置systemd服务
- 文档完善：README、API文档、故障排查指南

---

## 三、技术架构设计

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                      用户交互层                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Web Dashboard│  │ CLI Tool │  │ AI Chat  │  │ API      │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      业务逻辑层                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ 数据采集  │→│ 数据处理  │→│ 告警推送  │→│ 报告生成  │   │
│  │ Collector│  │ Processor│  │ Notifier │  │ Reporter │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      数据存储层                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              SQLite (WAL Mode)                        │   │
│  │  vulnerabilities | sources | push_logs | stats        │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      外部数据源                               │
│  CISA | OSCS | 奇安信 | 长亭 | 微步 | ZDI | GitHub | ...    │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 技术栈选型

| 层级 | 技术选型 | 说明 |
|------|---------|------|
| **开发平台** | 秒悟（MiaoWu） | 低代码开发平台，快速构建企业级应用 |
| **后端语言** | Python 3.10+ | 丰富的安全生态库，快速开发 |
| **Web框架** | FastAPI + Waitress | 高性能异步API，生产级WSGI服务器 |
| **前端框架** | HTMX + Tailwind CSS | 轻量级交互，无需复杂JS框架 |
| **数据库** | SQLite (WAL模式) | 零配置，支持并发读写，适合单机部署 |
| **任务调度** | APScheduler | Python原生定时任务库 |
| **HTTP客户端** | httpx + aiohttp | 异步请求，支持并发采集 |
| **推送服务** | 多渠道SDK集成 | Telegram、钉钉、企业微信、飞书、邮件 |
| **配置管理** | pydantic-settings | 环境变量 + YAML配置，类型安全 |
| **日志系统** | loguru | 结构化日志，自动轮转 |
| **部署工具** | systemd + deploy.sh | Linux服务管理，一键部署 |

### 3.3 核心流程设计

#### 3.3.1 数据采集流程
```
1. 调度器触发采集任务（每15分钟）
2. 并行启动20+数据源采集器
3. 每个采集器：
   - 发送HTTP请求获取最新数据
   - 解析JSON/HTML/XML格式
   - 提取标准化字段（CVE、标题、描述等）
   - 写入临时缓冲区
4. 合并所有采集结果，进入处理队列
```

#### 3.3.2 数据处理流程
```
1. 去重检查：
   - 查询SQLite，检查CVE是否已存在
   - 若存在且推送过，跳过；若存在但未推送，更新信息
   - 若不存在，插入新记录
2. 分类过滤：
   - 应用60+正则表达式匹配RCE特征
   - 匹配500+资产关键词
   - 排除XSS/CSRF/LPE/DoS等低优先级漏洞
3. 质量评分：
   - 计算完整性得分（字段填充率）
   - 评估来源权威性（CISA > 厂商 > 社区）
   - 检查在野利用标记（CISA KEV加分）
4. 标记推送状态：pushed = False
```

#### 3.3.3 告警推送流程
```
1. 查询未推送的高价值漏洞（pushed = False AND score > threshold）
2. 生成推送消息（简洁版/详细版）
3. 并行发送到各渠道：
   - Telegram Bot API
   - 钉钉Webhook
   - 企业微信Webhook
   - 飞书Webhook
   - SMTP邮件
4. 更新推送状态：pushed = True，记录push_logs
5. 限流控制：同一CVE只推送一次
```

---

## 四、功能模块设计

### 4.1 模块划分

| 模块名称 | 职责描述 | 核心类/函数 |
|---------|---------|------------|
| **collector/** | 数据采集器 | `BaseCollector`、`CISACollector`、`GitHubCollector`... |
| **processor/** | 数据处理引擎 | `Deduplicator`、`FilterEngine`、`Scorer` |
| **storage/** | 数据持久化 | `DatabaseManager`、`VulnerabilityModel` |
| **notifier/** | 告警推送服务 | `TelegramNotifier`、`DingTalkNotifier`、`WeComNotifier`、`FeishuNotifier`、`EmailNotifier` |
| **web/** | Web仪表盘 | `FastAPI App`、`HTMX Templates` |
| **cli/** | 命令行工具 | `click Commands`、`query_handlers` |
| **reporter/** | 报告生成器 | `MarkdownReporter`、`WeeklyReportGenerator` |
| **poc_search/** | PoC搜索引擎 | `GitHubPoCFinder`、`KeywordExtractor` |
| **config/** | 配置管理 | `Settings`、`SourceConfig` |
| **utils/** | 工具函数 | `logger`、`retry_decorator`、`file_lock` |

### 4.2 数据库设计

#### 4.2.1 vulnerabilities表
```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE NOT NULL,          -- CVE编号（唯一索引）
    title TEXT NOT NULL,                   -- 漏洞标题
    description TEXT,                      -- 漏洞描述
    severity TEXT,                         -- 严重等级（Critical/High/Medium/Low）
    source TEXT NOT NULL,                  -- 数据来源（CISA_KEV/ZDI/GitHub...）
    publish_date DATETIME NOT NULL,        -- 发布时间
    affected_products TEXT,                -- 受影响产品
    fix_recommendation TEXT,               -- 修复建议
    references TEXT,                       -- 参考链接（JSON数组）
    poc_available BOOLEAN DEFAULT FALSE,   -- 是否有PoC
    kev_marked BOOLEAN DEFAULT FALSE,      -- 是否CISA KEV标记
    quality_score REAL DEFAULT 0.0,        -- 质量评分（0-100）
    pushed BOOLEAN DEFAULT FALSE,          -- 是否已推送
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_publish_date ON vulnerabilities(publish_date DESC);
CREATE INDEX idx_source ON vulnerabilities(source);
CREATE INDEX idx_pushed ON vulnerabilities(pushed);
```

#### 4.2.2 sources表
```sql
CREATE TABLE sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,             -- 数据源名称
    type TEXT NOT NULL,                    -- 类型（PSIRT/Disclosure/Exploit...）
    url TEXT NOT NULL,                     -- 数据源URL
    enabled BOOLEAN DEFAULT TRUE,          -- 是否启用
    crawl_interval INTEGER DEFAULT 15,     -- 采集间隔（分钟）
    last_crawl DATETIME,                   -- 最后采集时间
    status TEXT DEFAULT 'active'           -- 状态（active/error/disabled）
);
```

#### 4.2.3 push_logs表
```sql
CREATE TABLE push_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,     -- 关联漏洞ID
    channel TEXT NOT NULL,                 -- 推送渠道（telegram/dingtalk/wecom/feishu/email）
    message_preview TEXT,                  -- 消息预览
    status TEXT NOT NULL,                  -- 推送状态（success/failed）
    error_message TEXT,                    -- 错误信息
    pushed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(vulnerability_id) REFERENCES vulnerabilities(id)
);
```

### 4.3 API接口设计

#### 4.3.1 Web API（FastAPI）
```python
GET  /api/v1/vulnerabilities
  - 参数：cve_id, source, keyword, days, pushed, limit, offset
  - 返回：漏洞列表（分页）

GET  /api/v1/vulnerabilities/{cve_id}
  - 返回：单个漏洞详细信息

GET  /api/v1/stats
  - 返回：统计数据（总数、今日新增、各来源分布、严重等级分布）

POST /api/v1/fetch
  - 触发：手动执行数据采集

GET  /api/v1/sources
  - 返回：数据源配置列表

PUT  /api/v1/sources/{source_id}/toggle
  - 操作：启用/禁用数据源
```

#### 4.3.2 CLI命令（Click）
```bash
# 数据采集
python vuln_monitor.py fetch [--dry-run]

# 查询漏洞
python vuln_monitor.py query [--cve CVE-2026-1340] [--source CISA_KEV] 
                             [--keyword "Fortinet"] [--days 7] 
                             [--pushed] [--format json|table|markdown]

# 生成摘要
python vuln_monitor.py brief [--pushed] [--days 1]

# 统计分析
python vuln_monitor.py stats

# 回填历史
python vuln_monitor.py rebuild [--days 30]

# 配置管理
python vuln_monitor.py config show
python vuln_monitor.py config set TG_BOT_TOKEN <token>
```

---

## 五、开发路线图

### 5.1 阶段划分

#### 第一阶段：基础架构搭建（2周）
**目标**：完成核心框架、数据库设计、配置管理

| 任务 | 工期 | 交付物 |
|------|------|--------|
| 项目初始化 | 2天 | 目录结构、依赖管理、CI/CD配置 |
| 数据库设计与实现 | 3天 | SQLite schema、ORM模型、迁移脚本 |
| 配置管理系统 | 2天 | pydantic-settings集成、YAML配置模板 |
| 日志与异常处理 | 2天 | loguru配置、全局异常捕获、文件锁机制 |
| 基础采集器框架 | 3天 | BaseCollector抽象类、HTTP客户端封装 |
| 单元测试框架 | 2天 | pytest配置、覆盖率报告、Mock工具 |

#### 第二阶段：数据采集与处理（3周）
**目标**：实现17+数据源采集器、去重过滤引擎

| 任务 | 工期 | 交付物 |
|------|------|--------|
| CISA KEV采集器 | 2天 | CISA API对接、JSON解析 |
| 厂商PSIRT采集器 | 4天 | Fortinet/PaloAlto/Cisco/MSRC采集器 |
| 漏洞披露采集器 | 3天 | ZDI/watchTowr/DailyCVE采集器 |
| Exploit/PoC采集器 | 3天 | Sploitus/GitHub/PoC-in-GitHub采集器 |
| 国内情报采集器 | 4天 | 奇安信/长亭/微步/OSCS采集器 |
| 去重引擎 | 2天 | CVE主键去重、辅助去重逻辑 |
| 过滤引擎 | 3天 | 正则匹配、关键词库、排除规则 |
| 质量评分算法 | 2天 | 完整性评分、来源权重、KEV加分 |

#### 第三阶段：告警推送与查询（3周）
**目标**：实现多渠道推送、Web仪表盘、CLI工具

| 任务 | 工期 | 交付物 |
|------|------|--------|
| Telegram推送器 | 2天 | Bot API集成、Markdown格式化 |
| 钉钉推送器 | 2天 | Webhook集成、卡片消息格式 |
| 企业微信推送器 | 2天 | Webhook集成、文本/卡片消息适配 |
| 飞书推送器 | 2天 | Webhook集成、富文本/交互式卡片适配 |
| 邮件推送器 | 2天 | SMTP配置、HTML模板引擎 |
| 推送限流控制 | 1天 | 同一CVE去重推送、频率限制 |
| Web仪表盘后端 | 3天 | FastAPI路由、HTMX模板、实时搜索 |
| Web仪表盘前端 | 3天 | Tailwind CSS样式、卡片布局、过滤器 |
| CLI命令行工具 | 2天 | Click命令、多格式输出、参数校验 |

#### 第四阶段：高级功能与优化（2周）
**目标**：PoC搜索、报告生成、AI交互、性能优化

| 任务 | 工期 | 交付物 |
|------|------|--------|
| GitHub PoC搜索 | 2天 | GitHub API集成、关键词提取、结果排序 |
| 报告生成器 | 2天 | Markdown周报/月报、图表生成 |
| AI交互集成 | 2天 | Claude Code skill、自然语言查询 |
| 性能优化 | 2天 | 异步采集、连接池、缓存策略 |
| 安全加固 | 1天 | CSP头、输入校验、依赖审计 |
| 文档编写 | 1天 | README、API文档、部署指南 |

#### 第五阶段：测试与部署（1周）
**目标**：全面测试、一键部署脚本、生产环境上线

| 任务 | 工期 | 交付物 |
|------|------|--------|
| 集成测试 | 2天 | E2E测试用例、数据源连通性测试 |
| 压力测试 | 1天 | 并发采集测试、数据库性能测试 |
| 一键部署脚本 | 2天 | deploy.sh、uninstall.sh、systemd服务配置 |
| 监控告警 | 1天 | 健康检查端点、异常告警集成 |
| 生产部署 | 1天 | 服务器配置、SSL证书、备份策略 |

### 5.2 里程碑节点

| 里程碑 | 时间节点 | 验收标准 |
|--------|---------|---------|
| M1：基础架构完成 | 第2周末 | 数据库可用、配置加载正常、日志系统就绪 |
| M2：采集器全部实现 | 第5周末 | 17+数据源采集器通过单元测试、能成功抓取数据 |
| M3：推送与查询可用 | 第8周末 | Telegram/钉钉/企业微信/飞书推送成功、Web仪表盘可访问、CLI命令可用 |
| M4：高级功能完成 | 第10周末 | PoC搜索返回结果、报告生成正确、AI查询响应正常 |
| M5：正式上线 | 第11周末 | 生产环境稳定运行7天、无重大Bug、监控告警正常 |

---

## 六、资源估算

### 6.1 人力资源

| 角色 | 人数 | 职责 | 投入周期 |
|------|------|------|---------|
| 后端开发工程师 | 2人 | 采集器开发、数据处理、API实现 | 全程10周 |
| 前端开发工程师 | 1人 | Web仪表盘UI/UX、HTMX交互 | 第3-7周（5周） |
| DevOps工程师 | 1人 | 部署脚本、CI/CD、监控告警 | 第1-2周、第9-10周（4周） |
| 测试工程师 | 1人 | 单元测试、集成测试、压力测试 | 第6-10周（5周） |
| 产品经理 | 1人 | 需求梳理、进度跟踪、验收测试 | 全程10周（兼职） |

**合计**：6人（全职等效4.5人），总工时约 **490人天**

### 6.2 硬件资源

| 资源类型 | 配置要求 | 数量 | 说明 |
|---------|---------|------|------|
| 应用服务器 | 4核CPU / 8GB内存 / 100GB SSD | 1台 | 部署Python应用、SQLite数据库 |
| 备份服务器 | 2核CPU / 4GB内存 / 500GB HDD | 1台 | 每日数据库备份存储 |
| 网络带宽 | 10Mbps上行 | - | 支持20+数据源并发采集 |

**云成本估算**（以阿里云为例）：
- ECS实例（4核8G）：¥350/月
- 云盘（100GB ESSD）：¥50/月
- 流量包（500GB）：¥50/月
- **月度总成本**：约 **¥450/月**

### 6.3 软件资源

| 资源类型 | 名称 | 许可证 | 成本 |
|---------|------|--------|------|
| 操作系统 | Ubuntu 22.04 LTS | 开源 | 免费 |
| Python运行时 | Python 3.10+ | PSF License | 免费 |
| 第三方库 | FastAPI、httpx、loguru等 | MIT/Apache | 免费 |
| CI/CD工具 | GitHub Actions | 开源项目免费 | 免费 |
| 监控工具 | Prometheus + Grafana | AGPLv3 | 免费 |
| Telegram Bot API | Telegram Platform | 免费 | 免费 |
| 钉钉开放平台 | DingTalk API | 免费 | 免费 |
| 企业微信开放平台 | WeCom API | 免费 | 免费 |
| 飞书开放平台 | Feishu API | 免费 | 免费 |

**软件总成本**：**¥0**（全部采用开源/免费方案）

### 6.4 时间资源

| 阶段 | 工期 | 开始时间 | 结束时间 |
|------|------|---------|---------|
| 第一阶段 | 2周 | 2026-05-11 | 2026-05-24 |
| 第二阶段 | 3周 | 2026-05-25 | 2026-06-14 |
| 第三阶段 | 3周 | 2026-06-15 | 2026-07-05 |
| 第四阶段 | 2周 | 2026-07-06 | 2026-07-19 |
| 第五阶段 | 1周 | 2026-07-20 | 2026-07-26 |

**项目总周期**：**11周**（2026年5月11日 - 2026年7月26日）

---

## 七、风险管理

### 7.1 技术风险

| 风险项 | 概率 | 影响 | 应对措施 |
|--------|------|------|---------|
| 数据源API变更 | 中 | 高 | 建立API监控告警，采集器模块化便于快速适配 |
| 反爬虫机制 | 中 | 中 | 使用代理IP池、随机User-Agent、请求频率限制 |
| 数据库性能瓶颈 | 低 | 中 | WAL模式优化、定期VACUUM、必要时迁移PostgreSQL |
| 推送服务不可用 | 低 | 低 | 多通道冗余（Telegram+钉钉+企业微信+飞书+邮件）、失败重试机制 |
| 正则匹配误报 | 中 | 中 | 持续优化正则规则、人工审核样本集、A/B测试 |

### 7.2 管理风险

| 风险项 | 概率 | 影响 | 应对措施 |
|--------|------|------|---------|
| 需求变更 | 中 | 中 | 冻结核心需求范围，新功能纳入二期规划 |
| 人员流动 | 低 | 高 | 代码规范、文档完善、交叉培训 |
| 进度延期 | 中 | 中 | 每周站会跟踪进度、关键路径缓冲1周 |
| 预算超支 | 低 | 低 | 严格控制云资源使用、采用按需付费模式 |

### 7.3 合规风险

| 风险项 | 概率 | 影响 | 应对措施 |
|--------|------|------|---------|
| 数据源版权争议 | 低 | 高 | 仅采集公开情报、注明来源、遵守robots.txt |
| PoC代码滥用 | 低 | 高 | 免责声明、仅限内部使用、不主动传播EXP |
| 个人信息泄露 | 低 | 高 | 不采集个人隐私数据、配置加密存储、访问日志审计 |

---

## 八、预期成果

### 8.1 交付物清单

| 交付物 | 形式 | 说明 |
|--------|------|------|
| 源代码 | Git仓库 | 完整项目代码、单元测试、CI/CD配置 |
| 部署脚本 | Shell脚本 | deploy.sh、uninstall.sh、systemd服务配置 |
| 配置文件 | YAML模板 | config.example.yaml、环境变量示例 |
| 技术文档 | Markdown | README.md、API文档、架构设计文档 |
| 用户手册 | Markdown | 快速开始指南、FAQ、故障排查 |
| 测试报告 | HTML/PDF | 单元测试覆盖率、集成测试结果、压力测试报告 |
| 演示视频 | MP4 | 系统功能演示、部署流程演示 |

### 8.2 业务价值

#### 8.2.1 效率提升
- **情报获取时间缩短**：从小时级降至分钟级（< 15分钟）
- **人工筛选工作量减少**：自动化过滤降低90%噪声，安全分析师专注高价值漏洞
- **应急响应加速**：实时推送确保第一时间感知威胁，平均响应时间缩短50%

#### 8.2.2 风险控制
- **漏报率降低**：多源聚合覆盖全面，避免单一数据源遗漏
- **误报率可控**：智能过滤将误报率控制在5%以内
- **合规性增强**：自动化记录所有漏洞情报，满足等保/ISO27001审计要求

#### 8.2.3 成本节约
- **人力成本**：替代1-2名专职情报分析师，年节约人力成本约30-50万元
- **工具采购**：开源方案零许可费用，相比商业情报平台年节约10-20万元
- **运维成本**：单机部署，月度云成本仅450元

### 8.3 成功指标

| 指标 | 目标值 | 测量方式 |
|------|--------|---------|
| 数据采集覆盖率 | ≥ 95%（17+数据源） | 数据源连通性测试 |
| 去重准确率 | > 99% | 人工抽样验证 |
| 推送成功率 | > 98% | push_logs统计 |
| 系统可用性 | > 99.5% | uptime监控 |
| 用户满意度 | ≥ 4.5/5.0 | 安全团队调研 |
| 平均响应时间 | < 15分钟 | 从源发布到推送的时间差 |

---

## 九、后续规划

### 9.1 二期功能（2026年Q3-Q4）

- **机器学习增强**：基于历史数据训练漏洞优先级预测模型
- **资产关联**：与企业CMDB集成，自动匹配受影响资产
- **工单联动**：对接Jira/钉钉待办，自动生成处置工单
- **可视化大屏**：实时监控大屏，展示漏洞趋势、地域分布、TOP厂商
- **多租户支持**：支持多团队隔离，权限分级管理

### 9.2 三期功能（2027年Q1-Q2）

- **威胁狩猎集成**：与SIEM/SOAR平台对接，自动化响应剧本
- **漏洞验证沙箱**：集成漏洞验证环境，一键复现PoC
- **情报共享社区**：建立内部情报共享机制，跨团队协同
- **移动端APP**：iOS/Android应用，随时随地接收告警
- **国际化支持**：多语言界面，支持英文/日文/韩文

---

## 十、附录

### 10.1 参考文献

1. vuln-monitor项目：https://github.com/Knaithe/1DayNews
2. CISA Known Exploited Vulnerabilities：https://www.cisa.gov/known-exploited-vulnerabilities-catalog
3. 微步在线威胁情报平台：https://threatbook.io/
4. 长亭科技漏洞数据库：https://stack.chaitin.com/vulnerability
5. GitHub PoC搜索最佳实践

### 10.2 术语表

| 术语 | 解释 |
|------|------|
| 0day | 未公开补丁的漏洞，攻击者已掌握利用方法 |
| 1day | 已公开补丁但尚未广泛应用的漏洞 |
| RCE | Remote Code Execution，远程代码执行 |
| CVE | Common Vulnerabilities and Exposures，通用漏洞披露编号 |
| KEV | Known Exploited Vulnerabilities，已知在野利用漏洞 |
| PSIRT | Product Security Incident Response Team，产品安全事件响应团队 |
| PoC | Proof of Concept，概念验证代码 |
| EXP | Exploit，漏洞利用代码 |
| WAL | Write-Ahead Logging，SQLite预写式日志模式 |
