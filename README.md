# PyPiMeOps

[English](README.en.md) | 简体中文

**PyPiMeOps** 是一个**独立的服务器运维巡检 Web 应用**：面向单位部署的、对内/对外提供服务的各类应用，
通过「SSH 脚本 + Prometheus 指标」双通道采集服务器/虚拟机指标，按脚本内置的阈值与建议生成巡检报告，
可选接入大模型做进一步解读，并在异常时通过 SMTP / 钉钉告警。纯内网部署优先。

## 设计初衷与定位

- **独立运维 Web 应用**：面向单位内网/外网开放的**所有应用**，一台控制机集中巡检。
- **面向普通用户**：最终用户**不需要了解脚本，也不需要理解各项指标阈值**；阈值与“触发后的建议操作”由**内置脚本**给出，直接生成可读报告。
- **隔离而非替代**：**不引入大模型直接分析原始服务器/虚拟机指标**。先用脚本采集指标；**无模型时完全依赖脚本自带的阈值与建议**；配置模型后，才在**脱敏前置**的前提下引入大模型解读。
- **大模型可选**：没有模型 API 绑定，则相关“模型分析/智能问答”能力不可用，页面给出**一次性提示**（确认后不再出现），巡检仍走「仅原始结果」。
- **纯内网安全模型**：优先由部署服务器前端硬件防火墙/白名单，或部署服务器自身白名单控制访问；应用内白名单为兜底。**不做硬性检测，仅页面级安全提示**（确认后不再出现）。
- **防误操作可恢复**：只对**项目配置的变更**（新增/删除/修改等）自动审计并保留原始值，配合版本备份可回滚，降低普通用户误操作风险。
- **数据源与虚拟化范围（当前）**：数据源**仅 Prometheus**；虚拟化**仅支持 PVE**（其它虚拟化暂不支持）。
- **架构取舍**：基于私有/极少量访问的使用场景，采用当前的**单进程**架构（内置调度器 + 进程内线程池）。**并未引入队列方式**。

## 谁在用：角色与典型流程

1. **部署/配置人员**：为已知服务器绑定内置 **Shell 脚本**或 **PromQL 脚本**，或者新增自由脚本。
2. **服务器分组**：把服务器按用途划分为**分组**（可复用的“服务器集合”）。
3. **组织应用**：把**分组**、或**无法归组的独立服务器**，整理进**应用**（面向业务的一级单位，成员为服务器或分组，多对多、无层级）。
4. **定时巡检**：通过**定时任务**对**应用**内的服务器执行常规运维巡检（也可对分组/服务器/数据源手动执行）。
5. **结果送达**：巡检结果通过 **SMTP / 钉钉**发送到配置的收件人（运维人员或最终用户邮箱）。
6. **最终用户视角**：只收到**聚合报告/告警**，无需关心脚本与阈值；如需现场问答，可在「智能巡检」用自然语言查询。

> 核心概念：**应用** 是面向普通用户的“一级单位”；**分组** 是可复用的服务器集合；一台服务器归属一个分组，但可同时属于多个应用。

## 功能概览

- **智能巡检（Chatbot，只读）**：用自然语言询问系统当前状态（如“最近一次巡检概况？”“哪些服务器有异常？”）。**有默认模型时为默认首页**；只读——不执行任何写操作、**不写入数据库**、不记入审计；对话历史**只保留在当前会话里**（重启即清空）；沿用数据策略与脱敏规则（`cloud` 先脱敏再外发，`local` 零外传）；提问长度上限 2000 字。
- **仪表盘**：整体健康度 + 配置完整性 + 下一步入口（**无默认模型时为默认首页**）；含**无 SSH 且无数据源**、**无脚本/数据源绑定**、**长期未巡检**的服务器，以及**未配置模型**提示。
- **凭据管理**：SSH 私钥经 Fernet 加密存 `vault/`，列表仅显示 SHA256 指纹；支持**更换私钥**（同一凭据、绑定不受影响）。
- **脚本管理**：Shell（`bash -n` 校验）/ PromQL（头部元数据校验）；两栏编辑器（行号/缩进/快捷键/元数据自动生成）；**标签**用于批量筛选与绑定。
- **服务器 + 分组**：两级 CRUD，绑定凭据、Shell 脚本、Prometheus 数据源与 promql 脚本；**服务器复制**；**IP 唯一校验**；**虚拟化标识**（PVE 虚拟机名或 id，配合 `$guest`）。
- **应用**：服务器/分组组合，作为报告与通知的聚合单位。
- **数据源**：直连 Prometheus HTTP API，`none/basic/bearer` 认证，内嵌连通性测试（成功后拉取 `job` 填充**默认标签**）。
- **模型（可选）**：多供应商 OpenAI 兼容 API（DeepSeek/OpenAI/Qwen/Kimi/GLM/Ollama…）；**不配置也可用**（巡检走「仅原始结果」，仅智能问答不可用）。
- **通知**：SMTP / 钉钉，多条并存，支持“发送测试消息”；全部启用/停用 + 逐条启停。
- **执行**：内置调度器（定时）+ 手动立即执行（执行预览 + 确认）；**同一时刻只执行一个巡检**。
- **报告**：按「应用 → 服务器 → 脚本项」聚合；条目为「指标项｜值｜阈值｜判定（越界附超限幅度）」；归档原始输出 + 脱敏标注，Web 安全渲染。
- **审计**：写操作自动审计（保留原始值）；默认「需关注」，可导出 CSV/JSON。
- **配置版本备份**：全配置对象版本链、恢复、两版本对比、全量导出/导入。
- **应用日志**：`/logs` 实时 tail / 时间范围/级别过滤 / 手动清理。
- **多语言（全链路）**：支持中文与英文；脚本名称、说明、指标项、报告、通知、模型提示均按当前语言本地化。

## 脚本 × 报告：阈值与建议（无模型也能读懂）

- 脚本通过头部元数据声明：`# THRESHOLD`/`# WARN`（阈值）、`# UNIT`（单位）、`# DISPLAY: true`（仅展示、不判定）；Shell 多值可**行内** `threshold=`/`warn=`/`unit=`；PromQL 支持 `$instance` / `$guest` 占位符。
- 引擎用**通用求值器**逐项判定 `OK/WARN/FAIL/INFO`（**状态与告警由引擎按阈值确定性判定，与模型无关**），报告中展示「值 | 阈值 | 判定」与超限幅度。
- **处置建议（`# ADVICE`，基于脚本作者的定义）**：
  - **内置脚本**因需中英双语，建议通过**种子元数据**（`seeds/manifest.json` 的 `advice`，zh-CN/en）注入，**脚本正文不含 `# ADVICE`**；
  - **用户脚本**如需“一句话建议”，在正文写 `# ADVICE: <文本>` 即可（自由文本、不翻译）。
  - 建议随报告/通知展示；无模型时它就是唯一的“处置提示”，**不引入规则引擎/规则库**。

## 大模型（可选）

- **无模型**：首页跳转仪表盘；「立即执行」默认并锁定「仅原始结果」；定时任务「模型分析」显示警示；顶部常驻轻提示。
- **有模型**：仅对**越界项（WARN/FAIL）**请求模型解读，输出 `attention/conclusion/consequence/suggestion`，与脚本 `# ADVICE` **并列展示、互补**。
- **隐私隔离**：模型分析前按内置脱敏规则**先脱敏再外发**；`cloud` 走脱敏外发，`local`（Ollama）零外传；报告保持确定性判定，**不对 `raw` 报告加“未启用模型解读”说明**。
- **本地模型替代（零外传）**：用 Ollama 等本地 OpenAI 兼容端点，配合 `default_data_policy=local`，确保数据不出内网。

## 通知

- SMTP / 钉钉，多条并存；每次巡检聚合为**一条**告警（状态汇总 + 异常清单，按应用分节），发送给**所有启用通知**；支持发送测试消息与逐条/全部启停。
- 收件人可填**运维人员**或**最终用户**邮箱（即 SMTP `to` / 钉钉 @）。
- 告警正文**不做脱敏**（可能含引擎判定结果/原始值），外发前请自行评估。

> 注：当前为**全局通知**；**按应用分别绑定收件人暂未支持**（后续特性）。

## 审计、版本与备份（防误操作可恢复）

- **审计**：所有写操作（配置增/删/改、手动执行、通知结果）自动记录来源 IP 与原始值；脚本变更仅存 hash+摘要。
- **配置版本链**：配置对象每次用户发起的变更都会**自动生成版本快照**，可恢复指定版本或已删除对象。
- **备份**：
  - **手动全量导出**（`/backups` → 导入导出，JSON）：部署并测试通过后，建议**手动生成一份全量备份**留存。
  - **自动**：每次配置变更自动版本快照；`install.sh upgrade` 会先执行 `backup.sh` 整机备份（便于部署/测试阶段回滚）。
  - **整机灾备**：`bash backup.sh` 备份 `pypimeops.db` + `vault/` + `scripts/` + `secrets.env`；**`vault.key` 与 `vault.enc` 必须同时还原**。

## 安全模型（纯内网优先）

- 无登录机制；**优先**前端硬件防火墙/白名单，**其次**部署服务器白名单，**最次**应用内 IP 白名单（`settings.allowed_ips`）。
- 应用层仅做**一次性安全提示**（确认后不再出现），不做硬性检测；同时启用**轻量 CSRF**。
- 审计来源 IP；**NAT 共用出口 IP 时无法区分具体操作人**。

## 架构与单进程约束

```
Flask 主进程 (app.py)
 ├─ Web 层（Jinja2 + Bootstrap 5）+ IP 白名单中间件 + CSRF
 ├─ 调度线程（每 poll_interval 秒扫描 run_schedule）
 ├─ 执行引擎（ThreadPoolExecutor，可配并发）
 ├─ 采集层（SSHCollector / PrometheusCollector）
 ├─ 模型分析（按 5~10 台分批，多批并行；可选）
 └─ 存储（SQLite + vault/ + scripts/ + reports/ + logs/）
```

**必须单进程运行**：内置调度器 + 进程内线程池，禁止 gunicorn 多 worker，生产不要用 `nohup` 重复拉起。采用单进程架构（内置调度器 + 进程内线程池），**未引入任务队列**。

## 环境要求

- Linux + systemd（Debian/Ubuntu 或 RHEL/CentOS/Rocky）
- Python **3.12 推荐，最低 3.11**（`install.sh` 自动探测；Debian 12 自带 `python3`=3.11 可直接用）
- 出站：模型 API、目标服务器 SSH、Prometheus HTTP；入站：管理端口（自定义，示例 8080）
- 网络访问控制/防火墙由部署环境上一层负责

## 快速开始（开发机）

```bash
cp config.yaml.example config.yaml       # 修改 host/port 与 flask_secret
cp secrets.env.example secrets.env       # 填模型 key / SMTP 密码，chmod 600
python3 -m venv venv                     # Python 需 ≥3.11（3.12 推荐）
./venv/bin/pip install -r requirements.txt
./venv/bin/python init.py                # 幂等；--force 重置
./venv/bin/python app.py                 # host/port 读 config.yaml（--host/--port 可选覆盖）
```

或直接 `./start.sh`（自动建 venv / 生成配置 / 初始化 / 启动）。

浏览器打开 `http://<host>:<port>`，依次录入：凭据 → 服务器 → 数据源 → 模型（可选）→ 通知 → 分组 → 应用 → 绑定脚本 → 定时任务。

## 生产部署

### 一键脚本（推荐）

```bash
sudo ./deploy/install.sh install \
  --app-dir /opt/pypimeops --user pypimeops \
  --host 0.0.0.0 --port 8080 --mode systemd
```

- 子命令：`install`（默认）/ `upgrade` / `uninstall` / `status`
- 参数：`--app-dir --user --host --port --mode systemd|docker|dev --python --service-name --repo/--src --install-deps --keep-data -y`
- 幂等：已存在的 `config.yaml` / `secrets.env` / 用户 / 目录不会被覆盖
- 默认仅**检测并提示**系统依赖，加 `--install-deps` 才自动 `apt`/`dnf` 安装

### 手动部署（systemd）

```bash
sudo useradd -r -s /sbin/nologin pypimeops
sudo mkdir -p /opt/pypimeops && sudo chown -R pypimeops:pypimeops /opt/pypimeops
git clone <repo> /opt/pypimeops
python3 -m venv /opt/pypimeops/venv
/opt/pypimeops/venv/bin/pip install -r /opt/pypimeops/requirements.txt
cd /opt/pypimeops && cp config.yaml.example config.yaml && cp secrets.env.example secrets.env && chmod 600 secrets.env
/opt/pypimeops/venv/bin/python init.py
sudo sed -e 's|__APP_DIR__|/opt/pypimeops|g' -e 's|__SVC_USER__|pypimeops|g' \
  deploy/pypimeops.service | sudo tee /etc/systemd/system/pypimeops.service
sudo systemctl daemon-reload && sudo systemctl enable --now pypimeops
```

### Docker

```bash
cp config.yaml.example config.yaml && cp secrets.env.example secrets.env
docker compose up -d --build
```

端口由 `config.yaml` 决定，`docker-compose.yml` 的端口映射按自定义端口填写。

## 配置说明

`config.yaml`（不入 git，由 `config.yaml.example` 复制）：

| 项 | 说明 |
|----|------|
| `host` / `port` | Web 监听地址/端口（**唯一权威**；`--host/--port` 可选覆盖） |
| `paths.*` | scripts/reports/vault/logs/known_hosts/db 路径 |
| `paths.vault_key` | 可选：`vault.key` 外置路径（也可用环境变量 `PYPIMEOPS_VAULT_KEY_PATH`） |
| `secrets_env` | 密钥文件路径 |
| `poll_interval` | 调度轮询间隔（秒） |
| `ssh_batch_size` | 批次大小（模型分批 5~10 台） |
| `flask_secret` | 随机密钥，用于 session/CSRF |

`secrets.env`（不入 git，权限 600）：模型 key、SMTP 密码、钉钉加签、Prometheus token；变量名需与模型/数据源配置中的 `api_key_env` / `secret_env` 一致。

## 功能页面

| 页面 | 路由 | 说明 |
|------|------|------|
| 智能巡检 | `/chatbot` | 有默认模型时**默认首页**；只读自然语言问答 |
| 仪表盘 | `/dashboard` | 无默认模型时**默认首页**；整体健康 + 配置完整性 + 入口 |
| 分组 | `/groups` | 分组 CRUD，含组级 Prometheus 默认标签 |
| 应用 | `/applications` | 面向业务的组合（成员：服务器/分组，多对多） |
| 服务器 | `/servers` | 服务器 CRUD（分组/凭据/Shell 脚本/Prometheus 绑定/虚拟化标识/复制） |
| 数据源 | `/datasources` | Prometheus 配置、连通性测试、默认标签、被绑服务器 |
| 凭据 | `/credentials` | SSH 凭据（加密存储）、指纹、更换私钥 |
| 脚本 | `/scripts` | Shell/PromQL 脚本 CRUD + 编辑器 + 标签 + 使用情况 |
| 模型 | `/models` | 模型 CRUD、连通性测试、单一入口默认模型（可选） |
| 通知 | `/notifications` | SMTP / 钉钉 配置与启停 |
| 定时任务 | `/schedules` | 预设/自定义频率调度（可按应用执行）、立即执行 |
| 立即执行 | `/run` | 手动巡检（目标/脚本/模式 + 执行预览） |
| 报告 | `/reports` | 巡检报告：默认「需关注」，状态视图 + 筛选 + 批量删除 |
| 审计日志 | `/audit-logs` | 写操作审计：默认「需关注」，详情/恢复，导出 CSV/JSON |
| 应用日志 | `/logs` | 实时 tail / 时间范围 / 级别过滤 / 下载 / 清理 |
| 备份恢复 | `/backups` | 按对象 / 版本明细（对比、恢复）/ 导入导出 |
| 设置 | `/settings` | 基本 / 模型与数据 / 采集与保留 三标签页 |

## 内置 PromQL 模板库

`init.py` 预置模板（**默认不执行，需在「服务器详情 → Prometheus 数据源绑定」中勾选后才参与巡检**）：

| 分组 | 模板 |
|------|------|
| Node Exporter | 磁盘/内存/CPU 使用率、系统负载(1m)、运行时长、失败服务数、磁盘写入速率 |
| 通用 | 目标存活(up) |
| Proxmox VE | 节点/集群存活、节点 CPU/内存/磁盘、存储池、运行时长、未备份、HA fence、订阅异常、网络入/出 |
| PVE 单虚拟机 | CPU/内存、网络入出、磁盘写入、运行时长、HA 状态、未备份（需服务器填**虚拟化标识**，用 `$guest`） |
| Nginx | 存活、活跃连接、概览、QPS、新建连接速率、活跃连接(阈值)、等待连接数 |
| Keepalived | 存活、脚本检查 |
| HTTP | 站点可用（`up{job="http_status"}`） |
| Anubis | 代理请求速率 |
| VictoriaLogs | 磁盘使用率（指标经 Prometheus 采集） |

- 带 `# THRESHOLD: >N` 的模板会做 PASS/FAIL 判定并触发告警（阈值可在脚本中修改）。
- `$instance` 按服务器 IP/标签/显式 `prom_instance` 注入；`$guest` 由服务器「虚拟化标识」解析为 PVE `id`。

## Prometheus 绑定配置案例

> 以下为**脱敏示例**（主机名、IP、数据源名均为占位），实际以你的环境为准。

**入口**：`服务器` → 某服务器详情 → 「Prometheus 数据源绑定」→ 新增。

示例数据源：`prod-prom`，地址 `http://<prometheus-host>:9090`，认证 `none`。示例服务器：`app-node-01`，IP `<SERVER_IP>`（如 `10.0.0.11`），分组 `web`。

- **案例一（推荐）**：`prom_instance` 留空 → 用服务器 IP 生成 `instance=~"<IP>(:\d+)?"`，自动匹配 `:9100` 等端口。
- **案例二**：显式 `prom_instance=10.0.0.11:9100`（exporter 在另一台机器/同 IP 多端口时）。
- **案例三**：标签覆盖 `{"job":"node","env":"prod"}`，或把 `env` 放到**分组**「组级标签」由组内继承。

**三层匹配优先级**：绑定 `prom_instance` > 组级 `prom_labels_json` + 绑定 `labels_json` > 用 `servers.ip` 推导。

**注意**：选择器命中 **>1 个 instance** 时该服务器标 `ambiguous`、不采集并在报告提示，请填显式 `prom_instance`；**纯 Prometheus 巡检无需 SSH**。

## 模型供应商预设

| 供应商 | base_url | key 变量 |
|--------|----------|----------|
| DeepSeek | https://api.deepseek.com | `DEEPSEEK_API_KEY` |
| OpenAI | https://api.openai.com/v1 | `OPENAI_API_KEY` |
| 通义千问 | https://dashscope.aliyuncs.com/compatible-mode/v1 | `DASHSCOPE_API_KEY` |
| Kimi | https://api.moonshot.cn/v1 | `MOONSHOT_API_KEY` |
| GLM | https://open.bigmodel.cn/api/paas/v4 | `ZHIPU_API_KEY` |
| Ollama | http://127.0.0.1:11434/v1 | `OLLAMA_API_KEY` |

> 选预设会自动填充 `base_url`/key 变量/`temperature`/`top_p`/`extra_json`；「拉取模型」从 `GET {base_url}/models` 获取模型标识下拉（失败可手填）。

## 升级 / 回滚 / 卸载 / 排障

- 升级：`sudo ./deploy/install.sh upgrade`（自动先 `backup.sh` → 停服 → 更新 → pip → init → 启服）
- 回滚：停服 → 还原 `backup.sh` 备份 → 启服
- 卸载：`sudo ./deploy/install.sh uninstall`（二次确认后删数据；`--keep-data` 保留）
- 状态：`sudo ./deploy/install.sh status` / `systemctl status pypimeops` / `journalctl -u pypimeops -f`
- 排障：`logs/pypimeops.log`、端口占用、目录权限（`vault/` 700、`secrets.env`/`vault.key` 600）

## 常见问题（FAQ）

**为什么必须单进程运行？**
内置调度器 + 进程内线程池依赖单进程；多 worker（如 gunicorn）会导致调度重复触发、任务串行失效。请勿使用多 worker。

**模型的 API key 填在哪里？**
`secrets.env`（如 `DEEPSEEK_API_KEY=sk-...`，权限 600）；「模型」页只填**环境变量名**（`api_key_env`），**密钥不会保存进数据库**（只从 `secrets.env` 读取）。

**不配置模型能用吗？**
能。巡检走「仅原始结果」，报告仍按脚本阈值与建议生成；仅「智能巡检」问答不可用。

**数据源能直连 VictoriaLogs 吗？**
不能。VictoriaLogs 只提供 `/metrics`（抓取格式），不提供 Prometheus 查询 API；请把它接入 Prometheus，再由本项目的数据源查询其 `vl_*` 指标。

**服务器只做 Prometheus 巡检（不用 SSH）怎么配？**
「服务器」里 SSH 端口/用户/凭据留空，保存后到详情页添加 Prometheus 数据源绑定即可（连接方式会显示 `Prometheus`）。

**如何监控 PVE 里的某台虚拟机？**
在服务器填「虚拟化标识」（虚拟机名或 `qemu/xxx`），并勾选带 `$guest` 的「PVE 虚拟机 *」模板。填名字时引擎会自动解析为 PVE id。

**时间显示为什么和日志不一致？**
数据库统一 **UTC 存储**，页面按 **主机本地时区**展示（报告中的开始/结束亦为本地时间）。

**IP 白名单为空会怎样？**
应用不特殊处理，仅做**一次性安全提示**；请由前端防火墙（ufw/iptables）完成访问控制。

**提示“已有巡检正在执行”？**
为保证目标服务器与模型调用不过载，系统**同一时刻只执行一个巡检**（定时与手动都一样）；请等它跑完，或到「报告」查看进度。

**升级/卸载会丢数据吗？**
升级先执行 `backup.sh` 整机备份再更新；卸载需二次确认才删数据，可用 `--keep-data` 保留。`vault.key` 与 `vault.enc` 必须同时备份/还原。

## 版本

- 采用 **SemVer**（`MAJOR.MINOR.PATCH`）：**不兼容**变更升 MAJOR、**兼容**新功能升 MINOR、**兼容**修复升 PATCH；预发布用 `-rc.N`。
- 当前版本：**0.1.0**（0.x 演进期；接口 / 数据结构稳定后再发布 `1.0.0`）。
- 查看位置：应用「设置」页「关于」；`./deploy/install.sh status` 与启动日志（不放全站页脚）。
- 变更历史见 [`CHANGELOG.md`](CHANGELOG.md)；**单一版本来源**为代码常量 `config.APP_VERSION`。

## License

许可证

本项目以 **Apache License 2.0** 发布，全文见 [`LICENSE`](LICENSE)。

第三方组件及许可（完整清单见 [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)）：

- **Python 依赖**：Flask / markupsafe（BSD-3-Clause）、requests（Apache-2.0）、PyYAML（MIT）、cryptography（Apache-2.0 OR BSD-3-Clause）、markdown-it-py（MIT）、**paramiko（LGPL-2.1）**。
- **前端内置资源**：Bootstrap 5.3.3（MIT），其版权声明保留于 `web/static/vendor/` 文件头部。

**分发时请一并保留上述第三方许可声明**；`paramiko` 采用 LGPL-2.1，仅作为**未经修改的库**被导入使用（非并入本项目源码），再分发须保留其声明并允许替换该库。
