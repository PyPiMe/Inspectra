# Changelog

All notable changes to this project are documented in this file.

本项目的重要变更记录于此文件。

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

格式基于 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
本项目遵循 [Semantic Versioning](https://semver.org/spec/v2.0.0.html)。

## 0.1.0 - 2026-10-07

### Added

- Initial release: standalone server O&M inspection web app (SSH scripts + Prometheus metrics + optional LLM).
- 首个版本：独立的服务器运维巡检 Web 应用（SSH 脚本 + Prometheus 指标 + 可选大模型）。
- Credentials: Fernet-encrypted SSH keys, fingerprint, replace-key.
- 凭据：Fernet 加密 SSH 私钥、指纹、更换私钥。
- Scripts: Shell / PromQL, two-pane editor, tags, metadata thresholds and `# ADVICE`, bilingual names/descriptions.
- 脚本：Shell / PromQL、两栏编辑器、标签、元数据阈值与 `# ADVICE`、中英双语名称与说明。
- Servers / groups / applications; server duplication; unique-IP validation; PVE virtualization identity.
- 服务器 / 分组 / 应用；服务器复制；IP 唯一校验；PVE 虚拟化标识。
- Prometheus datasources: `none/basic/bearer`, connectivity test, three-layer instance matching.
- Prometheus 数据源：`none/basic/bearer`、连通性测试、三层 instance 匹配。
- Execution: built-in scheduler + manual run (only one inspection at a time), `raw` / `model` modes, optional LLM behind sanitization.
- 执行：内置调度器 + 手动执行（同一时刻只执行一个巡检）、`raw` / `model` 模式、可选大模型（脱敏前置）。
- Reports: `application → server → script item`, audit log, config version backups, full export/import.
- 报告：`应用 → 服务器 → 脚本项`、审计日志、配置版本备份、全量导出 / 导入。
- Dashboard: health + coverage + configuration completeness; default-home rule (chatbot with a model, dashboard without).
- 仪表盘：健康 + 覆盖 + 配置完整性；默认首页规则（有模型进智能巡检，无模型进仪表盘）。
- Full-chain i18n (zh-CN / en) and optional-model degradation guidance.
- 全链路多语言（中文 / English）与无模型降级引导。
- Packaging & licensing: Apache-2.0, `THIRD_PARTY_NOTICES.md`, bilingual `README`.
- 打包与许可：Apache-2.0、`THIRD_PARTY_NOTICES.md`、中英双语 `README`。
