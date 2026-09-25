# PyPiMeOps

服务器运维巡检 Web 管理端：SSH 自定义脚本 + Prometheus 指标双通道采集，脱敏后交由大模型分析，
生成聚合报告并在异常时通过 SMTP / 钉钉告警。

> 完整设计见 `Plan.md`（不入 git）。

## 功能概览

- **智能巡检（Chatbot，只读）**：面向巡检人员的自然语言问答，**默认首页**
- **凭据管理**：SSH 私钥经 Fernet 加密存 `vault/`，列表仅显示 SHA256 指纹；支持**更换私钥**（同一凭据、绑定不受影响）
- **脚本管理**：Shell（`bash -n` 校验）/ PromQL（头部元数据校验），内容按 ID 存 `scripts/`；两栏编辑器（行号/缩进/快捷键/PromQL 元数据自动生成）
- **服务器 + 分组**：两级 CRUD，绑定凭据、Shell 脚本、Prometheus 数据源与 promql 脚本；**虚拟化标识**（PVE 虚拟机名或 id，配合 `$guest`）
- **数据源**：直连 Prometheus HTTP API，`none/basic/bearer` 认证，内嵌连通性测试（成功后拉取 `job` 填充**默认标签**）
- **模型**：多供应商 OpenAI 兼容 API（DeepSeek/OpenAI/Qwen/Kimi/GLM/Ollama…），内嵌连通性测试 + 模型下拉，默认模型
- **通知**：SMTP / 钉钉，多条并存，支持"发送测试消息"；**全部启用/全部停用 + 逐条启停**
- **执行**：内置调度器（分钟/小时/星期）+ 手动立即执行（两栏 + 执行预览 + 确认弹窗），全局单 run 互斥
- **报告**：`reports/` 归档原始完整输出 + 脱敏标注，Web 安全渲染；时间范围筛选、下载、目录/折叠/高亮
- **审计**：写操作全审计，脚本变更仅存 hash+摘要；动作快捷筛选、详情弹窗、导出 CSV/JSON
- **应用日志**：`/logs` 实时 tail / 时间范围筛选 / 手动清理
- **配置版本备份**：全配置对象版本链、恢复、按对象聚合、两版本对比、全量导出/导入（迁移/新增双模式）

## 智能巡检（Chatbot，只读）

**默认首页**（`/chatbot`，导航「智能巡检」，品牌标题亦指向此页）。面向普通巡检人员，用自然语言询问系统当前数据，例如：

- 最近一次巡检概况？
- 哪些服务器最近出现异常？
- 当前一共有多少台服务器？
- 默认模型是什么？

**实现（阶段一：上下文注入）**：将系统**只读快照**（资源统计、服务器清单含连接方式、最近 N 次巡检与异常清单、关键设置）注入 system prompt，交由**默认模型**作答。使用前请在「模型」页配置模型并设为默认。

- **只读**：不执行任何写操作（删除/恢复/触发巡检等），也不会修改配置。
- **对话历史**：仅存**本会话**（进程内、不落库），可点「清空对话」；重启即清空。
- **输出**：非流式；模型不可用或调用失败时页面**优雅提示**（不会 500）。
- **安全**：沿用 `default_data_policy` 与脱敏规则——`cloud` 时上下文**先脱敏再外发**，`local` 零外传；**聊天不写审计**。
- **入口**：受 IP 白名单与 CSRF 保护；提问长度上限 2000 字。

> 阶段二（预留）：为模型增加**只读工具调用（function calling）**与报告检索/NL→PromQL，届时再扩展。

## 功能页面

| 页面 | 路由 | 说明 |
|------|------|------|
| 智能巡检 | `/chatbot` | **默认首页**；只读自然语言问答 |
| 仪表盘 | `/dashboard` | 最近运行、服务器概览、异常统计 |
| 分组 | `/groups` | 分组 CRUD，含组级 Prometheus 默认标签 |
| 服务器 | `/servers` | 服务器 CRUD（分组/凭据/Shell 脚本/Prometheus 绑定/虚拟化标识） |
| 数据源 | `/datasources` | Prometheus 配置、连通性测试、默认标签、被绑服务器 |
| 凭据 | `/credentials` | SSH 凭据（加密存储）、指纹、更换私钥 |
| 脚本 | `/scripts` | Shell/PromQL 脚本 CRUD + 编辑器 |
| 模型 | `/models` | 模型 CRUD、连通性测试、模型下拉、默认模型 |
| 通知 | `/notifications` | SMTP / 钉钉 配置与启停 |
| 定时任务 | `/schedules` | 简化 cron 调度、启停 |
| 立即执行 | `/run` | 手动巡检（目标/脚本/模式 + 执行预览） |
| 报告 | `/reports` | 巡检报告：**默认「需关注」（失败/部分失败）**；状态视图（需关注/全部/成功/部分失败/失败/生成中，带计数）+ **「筛选」**（触发类型/生成时间，已应用条件以可清除 chip 展示）；卡片列表；批量删除（勾选 / 筛选结果 / 清空全部，默认隐藏） |
| 审计日志 | `/audit-logs` | 写操作审计、详情、导出 |
| 应用日志 | `/logs` | 运行日志实时/范围查看与清理 |
| 备份恢复 | `/backups` | 配置版本备份/恢复/导出导入 |
| 设置 | `/settings` | 站点标题、白名单、并发/超时、保留天数、脱敏规则等 |

## 架构与单进程约束

```
Flask 主进程 (app.py)
 ├─ Web 层（Jinja2 + Bootstrap 5）+ IP 白名单中间件 + CSRF
 ├─ 调度线程（每 poll_interval 秒扫描 run_schedule）
 ├─ 执行引擎（ThreadPoolExecutor，可配并发）
 ├─ 采集层（SSHCollector / PrometheusCollector）
 ├─ 模型分析（按 5~10 台分批，多批并行）
 └─ 存储（SQLite + vault/ + scripts/ + reports/ + logs/）
```

**必须单进程运行**：内置调度器 + 进程内线程池，禁止 gunicorn 多 worker，生产不要用 `nohup` 重复拉起。

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

浏览器打开 `http://<host>:<port>`，依次录入：凭据 → 服务器 → 数据源 → 模型 → 通知 → 绑定脚本。

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

`secrets.env`（不入 git，权限 600）：模型 key、SMTP 密码、钉钉加签、Prometheus token。
变量名需与模型/数据源配置中的 `api_key_env` / `secret_env` 一致。

## 测试环境

所有主机 IP、SSH 密钥路径、Prometheus 地址、模型 key 均为参数，Plan 与 git 中不写真实凭据。
测试拓扑：1 控制机 + N 台 SSH 目标 + 现有 Prometheus + 云端真实模型 + 通知仅日志落盘。

```bash
cd "$APP_DIR"
cp config.yaml.example config.yaml && cp secrets.env.example secrets.env && chmod 600 secrets.env
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
./venv/bin/python init.py
./venv/bin/python app.py
```

## Prometheus 绑定配置案例

> 以下为**脱敏示例**（主机名、IP、数据源名均为占位），实际以你的环境为准。

**入口**：`服务器` → 进入某台服务器详情 → 「Prometheus 数据源绑定」→ 新增绑定。

示例数据源：名称 `prod-prom`，地址 `http://<prometheus-host>:9090`，认证 `none`。
示例服务器：`app-node-01`，IP `<SERVER_IP>`（如 `10.0.0.11`），分组 `<分组名>`（如 `web`）。

### 案例一（推荐）：最简绑定，按 IP 自动推导 instance

| 字段 | 填写值 |
|------|--------|
| 数据源 | `prod-prom` |
| prom_instance | **留空** |
| 标签覆盖 (JSON) | `{}` |
| promql 脚本 | 勾选 `磁盘使用率`、`内存使用率`、`CPU 使用率`、`系统负载(1m)` 等 |
| 启用 | 勾选 |

引擎用服务器 IP 生成选择器 `instance=~"<SERVER_IP>(:\d+)?"`（如 `instance=~"10\.0\.0\.11(:\d+)?"`），注入脚本的 `$instance`。例如「磁盘使用率」实际查询：

```promql
100 - (
  node_filesystem_avail_bytes{fstype!~"tmpfs|overlay",instance=~"10\.0\.0\.11(:\d+)?"}
  / node_filesystem_size_bytes{fstype!~"tmpfs|overlay",instance=~"10\.0\.0\.11(:\d+)?"}
  * 100
)
```
可匹配 `instance="10.0.0.11:9100"` 这类序列（端口任意）。**只要服务器 IP 与 node_exporter 所在 IP 一致，就无需填 prom_instance。**

### 案例二：显式指定 instance

| 字段 | 填写值 |
|------|--------|
| prom_instance | `10.0.0.11:9100` |

精确匹配该实例。适用于：node_exporter 装在**另一台**机器（如 `10.0.0.99:9100`）；或同 IP 有多个 exporter 需按端口区分。

### 案例三：补充标签

| 字段 | 填写值 |
|------|--------|
| prom_instance | 留空 |
| 标签覆盖 (JSON) | `{"job": "node", "env": "prod"}` |

选择器变为 `instance=~"10\.0\.0\.11(:\d+)?"` 与 `job="node",env="prod"` 组合。也可把 `env` 放到**分组**的「组级标签」（`prom_labels_json`，如 `{"env":"prod"}`），组内服务器自动继承，服务器级 `labels_json` 可覆盖同名键。

### instance 匹配优先级（三层）
1. 绑定的 `prom_instance`（显式，最优先）
2. 组级 `prom_labels_json` + 绑定 `labels_json`（含 `instance` 键则直接用）
3. 仍无 instance → 用 `servers.ip` 推导

### 注意事项
- **歧义拒绝**：选择器命中 **>1 个 instance** 时该服务器标 `ambiguous`、不采集并在报告提示，此时请填显式 `prom_instance`。
- **纯 Prometheus 巡检无需 SSH 凭据**；同一服务器可 SSH + Prometheus 并行，结果合并入同一报告。
- 内置 PromQL 模板**默认不执行，必须显式勾选绑定**后才参与巡检。
- 认证 `none` 依赖 Prometheus 端 IP 白名单；`basic`/`bearer` 的凭据放 `secrets.env`（如 `PROM_TOKEN`），并在数据源里填对应 `secret_env`。
- 绑定后可在「数据源」页查看该数据源的**已绑服务器**列表，也可在「立即执行」选该数据源 + 服务器验证。

## 备份与恢复

- **配置版本备份**：Web `/backups` 页，全配置对象版本链、恢复指定版本/已删除对象、全量导出/导入
- **整机灾备**：`bash backup.sh` 备份 `pypimeops.db` + `vault/`（含 `vault.enc`/`vault.key`/`known_hosts`）+ `scripts/` + `secrets.env`
  - 恢复：停服 → 解压覆盖到 `APP_DIR` → 启服。**`vault.key` 与 `vault.enc` 必须同时还原**

## 升级 / 回滚 / 卸载 / 排障

- 升级：`sudo ./deploy/install.sh upgrade`（自动先 `backup.sh` → 停服 → 更新 → pip → init → 启服）
- 回滚：停服 → 还原 `backup.sh` 备份 → 启服
- 卸载：`sudo ./deploy/install.sh uninstall`（二次确认后删数据；`--keep-data` 保留）
- 状态：`sudo ./deploy/install.sh status` / `systemctl status pypimeops` / `journalctl -u pypimeops -f`
- 排障：`logs/pypimeops.log`、端口占用、目录权限（`vault/` 700、`secrets.env`/`vault.key` 600）

## 安全说明与局限

- 应用层 IP 白名单 + 轻量 CSRF；**无登录机制**，请由前端防火墙兜底
- 白名单为空时仅做一次性安全提示
- 审计记录来源 IP；**NAT 共用出口 IP 时无法区分具体操作人**
- 告警正文**不做脱敏**，可能含引擎硬事实/原始值，外发前请自行评估
- 模型分析前默认强制脱敏；`cloud` 走脱敏后外发，`local`（Ollama）零外传，local 失败不静默回落云端

## 内置 PromQL 模板库

`init.py` 预置以下模板（**默认不执行，需在「服务器详情 → Prometheus 数据源绑定」中勾选后才参与巡检**）：

| 分组 | 模板 |
|------|------|
| Node Exporter | 磁盘使用率、内存使用率、CPU 使用率、系统负载(1m)、运行时长、失败服务数、磁盘写入速率 |
| 通用 | 目标存活(up) |
| Proxmox VE | 节点/集群存活、节点 CPU/内存/磁盘使用率、存储池使用率、节点运行时长、未备份虚拟机数、HA fence、订阅异常、网络入/出速率 |
| PVE 单虚拟机 | CPU/内存、网络入出、磁盘写入、运行时长、HA 状态、未备份（需服务器填**虚拟化标识**，用 `$guest`） |
| Nginx | 存活、活跃连接数、概览（up/活跃/读写等待/累计/QPS/新建连接速率）、QPS、新建连接速率、活跃连接数(阈值)、等待连接数 |
| Keepalived | 存活、脚本检查 |
| HTTP | 站点可用（`up{job="http_status"}`） |
| Anubis | 代理请求速率 |
| VictoriaLogs | 磁盘使用率 |

- 带 `# THRESHOLD: >N` 的模板会做 PASS/FAIL 判定并触发告警（阈值可在脚本中修改）。
- `$instance` 按服务器 IP/标签/显式 `prom_instance` 注入；`$guest` 由服务器「虚拟化标识」解析为 PVE `id`。
- 采集输出会带出 `id`/`type`/`item` 等附加标签，便于逐项阅读。

## 模型供应商预设

| 供应商 | base_url | key 变量 |
|--------|----------|----------|
| DeepSeek | https://api.deepseek.com | `DEEPSEEK_API_KEY` |
| OpenAI | https://api.openai.com/v1 | `OPENAI_API_KEY` |
| 通义千问 | https://dashscope.aliyuncs.com/compatible-mode/v1 | `DASHSCOPE_API_KEY` |
| Kimi | https://api.moonshot.cn/v1 | `MOONSHOT_API_KEY` |
| GLM | https://open.bigmodel.cn/api/paas/v4 | `ZHIPU_API_KEY` |
| Ollama | http://127.0.0.1:11434/v1 | `OLLAMA_API_KEY` |

> 新增/编辑模型时：选预设供应商会**自动填充 base_url / key 变量 / temperature / top_p / extra_json**；点「拉取模型」可从 `GET {base_url}/models` 获取**模型标识下拉**（失败可手填）；`extra_json` 另有**模板下拉**（如 DeepSeek 关闭思考、`reasoning_effort`）。

## 常见问题（FAQ）

**为什么必须单进程运行？**
内置调度器 + 进程内线程池依赖单进程；多 worker（如 gunicorn）会导致调度重复触发、单 run 互斥失效。请勿使用多 worker。

**模型的 API key 填在哪里？**
`secrets.env`（如 `DEEPSEEK_API_KEY=sk-...`，权限 600）。「模型」页只填**环境变量名**（`api_key_env`），key 不落库。

**数据源能直连 VictoriaLogs 吗？**
不能。VictoriaLogs 只提供 `/metrics`（抓取格式），不提供 Prometheus 查询 API。请把它接入 Prometheus，再由本项目的数据源查询其 `vl_*` 指标。

**服务器只做 Prometheus 巡检（不用 SSH）怎么配？**
「服务器」里 SSH 端口/用户/凭据留空，保存后到详情页添加 Prometheus 数据源绑定即可（连接方式会显示 `Prometheus`）。

**如何监控 PVE 里的某台虚拟机？**
在服务器填「虚拟化标识」（虚拟机名或 `qemu/xxx`），并勾选带 `$guest` 的「PVE 虚拟机 *」模板。填名字时引擎会自动解析为 PVE id。

**时间显示为什么和日志不一致？**
数据库统一 **UTC 存储**，页面按 **主机本地时区**展示（报告中的开始/结束亦为本地时间）。

**IP 白名单为空会怎样？**
应用不特殊处理，仅做**一次性安全提示**；请由前端防火墙（ufw/iptables）完成访问控制。

**提示“已有巡检正在执行”？**
存在**全局单 run 互斥**：同一时刻仅允许一个 run（定时与手动统一），请等待完成或到「报告」查看进度。

**升级/卸载会丢数据吗？**
升级先执行 `backup.sh` 整机备份再更新；卸载需二次确认才删数据，可用 `--keep-data` 保留。`vault.key` 与 `vault.enc` 必须同时备份/还原。
