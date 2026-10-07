# PyPiMeOps

**English** | [简体中文](README.md)

**PyPiMeOps** is a **standalone server O&M inspection web app**. For all applications an
organization exposes internally or externally, it collects server/VM metrics over two
channels — **SSH scripts** and **Prometheus metrics** — generates inspection reports based
on thresholds and advice declared in the scripts, optionally adds LLM interpretation, and
sends SMTP / DingTalk alerts on anomalies. Intranet-first deployment.

## Purpose & positioning

- **Standalone O&M web app**: one control host inspects **all applications** an
  organization exposes internally or externally.
- **Built for non-experts**: end users **don't need to know scripts or thresholds**.
  Thresholds and the "what to do when triggered" advice come from **built-in scripts**,
  producing a readable report directly.
- **Isolation, not replacement**: the LLM is **not** given raw server/VM metrics to
  analyze. Metrics are collected by scripts first; **without a model, everything relies
  on the scripts' own thresholds and advice**; only after a model is configured is LLM
  interpretation introduced, always **behind sanitization**.
- **LLM is optional**: with no model API bound, model-analysis / chat features are
  unavailable and the UI shows a **one-time notice** (dismissed once); inspection still
  runs in **raw-only** mode.
- **Intranet-first security model**: prefer a front hardware firewall / allowlist, or the
  hosting server's allowlist; the in-app IP allowlist is the last resort. **No hard
  enforcement — only a page-level security notice** (dismissed once).
- **Mis-operation recovery**: only **config changes** (create/delete/update, etc.) are
  auto-audited with original values retained; with version backups this supports rollback.
- **Datasource & virtualization scope (current)**: datasource is **Prometheus only**;
  virtualization is **PVE only** (others not supported yet).
- **Architecture trade-off**: given private / very-low-traffic usage, it uses a
  **single-process** architecture (built-in scheduler + in-process thread pool).
  **No task queue is introduced.**

## Who uses it: roles & typical flow

1. **Deployer/administrator**: bind built-in **Shell** or **PromQL** scripts to known
   servers, or add custom scripts.
2. **Group servers**: split servers into **groups** (reusable "server sets").
3. **Organize applications**: put **groups** — or **standalone servers that can't be
   grouped** — into an **application** (a business-facing first-class unit; members are
   servers or groups, many-to-many, no hierarchy).
4. **Scheduled inspection**: run routine inspection over the servers in an **application**
   via **scheduled tasks** (or manually over groups/servers/datasources).
5. **Delivery**: results are sent via **SMTP / DingTalk** to configured recipients
   (O&M staff or end-user mailboxes).
6. **End-user view**: they only receive the **aggregated report/alert**, no need to care
   about scripts or thresholds; for on-the-spot questions they can ask in **Chatbot**.

> Core concepts: an **application** is the first-class unit for ordinary users; a **group**
> is a reusable server set; a server belongs to one group but can be in many applications.

## Feature overview

- **Chatbot (read-only)**: ask about the current state in natural language (e.g. "summary
  of the latest inspection?", "which servers are abnormal?"). It is the **default home
  when a default model exists**; read-only — performs no writes, **writes nothing to the
  database**, and is not audited; chat history is kept **only in the current session**
  (cleared on restart); follows the data policy and sanitization rules (`cloud` =
  sanitize then send, `local` = zero egress); question length capped at 2000 chars.
- **Dashboard**: overall health + configuration completeness + next-step entry points
  (**default home when no model is configured**). Includes servers **with neither SSH nor
  a datasource**, servers **without bound scripts/datasources**, **long-uninspected**
  servers, and a **model-not-configured** hint.
- **Credentials**: SSH private keys encrypted with Fernet under `vault/`; list shows only
  the SHA256 fingerprint; supports **replacing the key** (same credential, bindings
  unaffected).
- **Scripts**: Shell (`bash -n` validation) / PromQL (header metadata validation);
  two-pane editor (line numbers/indent/shortcuts/auto-generated metadata); **tags** for
  bulk filtering and binding.
- **Servers + groups**: two-level CRUD, binding credentials, Shell scripts, Prometheus
  datasources and promql scripts; **server duplication**; **unique IP** validation;
  **virtualization identity** (PVE VM name or id, used with `$guest`).
- **Applications**: combinations of servers/groups; the aggregation unit for reports and
  notifications.
- **Datasources**: direct Prometheus HTTP API, `none/basic/bearer` auth, inline
  connectivity test (pulls `job` to fill the **default labels** on success).
- **Models (optional)**: multi-vendor OpenAI-compatible APIs (DeepSeek/OpenAI/Qwen/Kimi/
  GLM/Ollama…); **works without one** (inspection runs raw-only, only chat is unavailable).
- **Notifications**: SMTP / DingTalk, multiple entries, "send test message"; enable/disable
  all + per-entry toggling.
- **Execution**: built-in scheduler (cron-like) + manual run-now (preview + confirm);
  **only one inspection runs at a time**.
- **Reports**: aggregated as `application → server → script item`; each row is
  `item | value | threshold | verdict` (breaches show the excess); raw output archived with
  sanitization annotations, rendered safely in the browser.
- **Audit**: all write operations auto-audited (original values retained); defaults to
  "needs attention"; exportable as CSV/JSON.
- **Config version backups**: version chain per config object, restore, two-version compare,
  full export/import.
- **Application logs**: `/logs` live tail / time range / level filter / manual cleanup.
- **Full-chain i18n**: Chinese / English; script names, descriptions, item keys, reports,
  notifications and model prompts are localized to the current language.

## Scripts × reports: thresholds & advice (readable without a model)

- Scripts declare header metadata: `# THRESHOLD`/`# WARN` (thresholds), `# UNIT`, and
  `# DISPLAY: true` (display-only, no verdict); Shell multi-value lines may use inline
  `threshold=`/`warn=`/`unit=`; PromQL supports `$instance` / `$guest` placeholders.
- The engine evaluates each item with a **generic evaluator** into `OK/WARN/FAIL/INFO`
  (**status and alerting are determined deterministically by the engine from thresholds,
  independent of the model**), showing `value | threshold | verdict` and the excess.
- **Disposal advice (`# ADVICE`, defined by the script author)**:
  - **Built-in scripts**, being bilingual, get advice from **seed metadata**
    (`seeds/manifest.json` `advice`, zh-CN/en) — the script body does **not** contain
    `# ADVICE`;
  - **User scripts** wanting a one-line advice write `# ADVICE: <text>` in the body
    (free text, untranslated).
  - Advice is shown in reports/notifications; without a model it is the only "what to do"
    hint. **No rule engine / rule base is introduced.**

## LLM (optional)

- **Without a model**: home redirects to the dashboard; "Run now" defaults to and locks
  "raw only"; scheduled tasks in "model analysis" mode show a warning; a persistent top
  notice is shown.
- **With a model**: only **breaching items (WARN/FAIL)** are sent for interpretation,
  returning `attention/conclusion/consequence/suggestion`, shown **alongside** the script
  `# ADVICE` (complementary).
- **Privacy isolation**: before analysis, data is **sanitized first**; `cloud` sends
  sanitized data, `local` (Ollama) has zero egress; reports stay deterministic and
  **raw reports are not annotated with "model interpretation not enabled"**.
- **Local model alternative (zero egress)**: use a local OpenAI-compatible endpoint such as
  Ollama with `default_data_policy=local` to keep data inside the intranet.

## Notifications

- SMTP / DingTalk, multiple entries; each inspection aggregates into **one** alert (status
  summary + issue list, grouped by application) sent to **all enabled notifications**;
  supports test messages and per-entry / all enable-disable.
- Recipients can be **O&M staff** or **end-user** mailboxes (i.e. SMTP `to` / DingTalk @).
- Alert bodies are **not sanitized** (may contain engine verdicts/raw values); assess
  before sending externally.

> Note: notifications are currently **global**; **per-application recipient binding is not
> supported yet** (a future feature).

## Audit, versions & backups (mis-operation recovery)

- **Audit**: all writes (config create/update/delete, manual runs, notification results)
  record the source IP and original values; script changes store hash + summary only.
- **Config version chain**: every user-initiated change to a config object **auto-generates
  a version snapshot**; restore a specific version or a deleted object.
- **Backups**:
  - **Manual full export** (`/backups` → Import/Export, JSON): after deployment and
    testing, generate a **full backup** manually and keep it.
  - **Automatic**: a version snapshot on every config change; `install.sh upgrade` runs
    `backup.sh` (full machine backup) first, easing rollback during deploy/test.
  - **Full-machine DR**: `bash backup.sh` backs up `pypimeops.db` + `vault/` + `scripts/`
    + `secrets.env`; **`vault.key` and `vault.enc` must be restored together**.

## Security model (intranet-first)

- No login; **prefer** a front hardware firewall/allowlist, **then** the hosting server's
  allowlist, **last** the in-app IP allowlist (`settings.allowed_ips`).
- The app only shows a **one-time security notice** (dismissed once); no hard enforcement;
  lightweight **CSRF** is enabled.
- Audit records the source IP; **behind NAT with a shared egress IP, the operator cannot be
  distinguished**.

## Architecture & single-process constraint

```
Flask main process (app.py)
 ├─ Web layer (Jinja2 + Bootstrap 5) + IP allowlist middleware + CSRF
 ├─ Scheduler thread (scans run_schedule every poll_interval seconds)
 ├─ Execution engine (ThreadPoolExecutor, configurable concurrency)
 ├─ Collectors (SSHCollector / PrometheusCollector)
 ├─ Model analysis (batches of 5~10 hosts, parallel batches; optional)
 └─ Storage (SQLite + vault/ + scripts/ + reports/ + logs/)
```

**Must run as a single process**: built-in scheduler + in-process thread pool; gunicorn
with multiple workers is forbidden; do not start duplicate processes with `nohup`.
It uses a single-process architecture (built-in scheduler + in-process thread pool) with
**no task queue**.

## Requirements

- Linux + systemd (Debian/Ubuntu or RHEL/CentOS/Rocky)
- Python **3.12 recommended, 3.11 minimum** (`install.sh` auto-detects; Debian 12's
  `python3` = 3.11 works directly)
- Egress: model API, target SSH, Prometheus HTTP; Ingress: admin port (custom, e.g. 8080)
- Network access control/firewall is handled by the layer above the deployment

## Quick start (dev machine)

```bash
cp config.yaml.example config.yaml       # edit host/port and flask_secret
cp secrets.env.example secrets.env       # fill model key / SMTP password, chmod 600
python3 -m venv venv                     # Python >=3.11 (3.12 recommended)
./venv/bin/pip install -r requirements.txt
./venv/bin/python init.py                # idempotent; --force resets
./venv/bin/python app.py                 # host/port from config.yaml (--host/--port override)
```

Or just `./start.sh` (creates venv / config / init / start).

Open `http://<host>:<port>` and enter, in order: credentials → servers → datasources →
model (optional) → notifications → groups → applications → script bindings → schedules.

## Production deployment

### One-shot script (recommended)

```bash
sudo ./deploy/install.sh install \
  --app-dir /opt/pypimeops --user pypimeops \
  --host 0.0.0.0 --port 8080 --mode systemd
```

- Subcommands: `install` (default) / `upgrade` / `uninstall` / `status`
- Args: `--app-dir --user --host --port --mode systemd|docker|dev --python --service-name --repo/--src --install-deps --keep-data -y`
- Idempotent: existing `config.yaml` / `secrets.env` / user / directories are not overwritten
- By default only **detects and warns** about system deps; `--install-deps` installs them

### Manual deployment (systemd)

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

The port is determined by `config.yaml`; set the mapping in `docker-compose.yml`
accordingly.

## Configuration

`config.yaml` (not in git; copy from `config.yaml.example`):

| Key | Description |
|-----|-------------|
| `host` / `port` | Web listen address/port (**authoritative**; `--host/--port` override) |
| `paths.*` | scripts/reports/vault/logs/known_hosts/db paths |
| `paths.vault_key` | Optional: external `vault.key` path (or env `PYPIMEOPS_VAULT_KEY_PATH`) |
| `secrets_env` | Secrets file path |
| `poll_interval` | Scheduler poll interval (seconds) |
| `ssh_batch_size` | Batch size (model batches of 5~10 hosts) |
| `flask_secret` | Random key for session/CSRF |

`secrets.env` (not in git, mode 600): model keys, SMTP password, DingTalk sign secret,
Prometheus token. Variable names must match each model/datasource's `api_key_env` /
`secret_env`.

## Pages

| Page | Route | Description |
|------|-------|-------------|
| Chatbot | `/chatbot` | **Default home when a model is set**; read-only Q&A |
| Dashboard | `/dashboard` | **Default home when no model**; health + config completeness + entry points |
| Groups | `/groups` | Group CRUD, with group-level Prometheus default labels |
| Applications | `/applications` | Business-facing combinations (members: servers/groups, many-to-many) |
| Servers | `/servers` | Server CRUD (group/credential/Shell scripts/Prometheus bindings/VM id/duplicate) |
| Datasources | `/datasources` | Prometheus config, connectivity test, default labels, bound servers |
| Credentials | `/credentials` | SSH credentials (encrypted), fingerprint, replace key |
| Scripts | `/scripts` | Shell/PromQL CRUD + editor + tags + usage |
| Models | `/models` | Model CRUD, connectivity test, single-entry default model (optional) |
| Notifications | `/notifications` | SMTP / DingTalk config & toggling |
| Schedules | `/schedules` | Preset/custom-frequency scheduling (by application), run now |
| Run now | `/run` | Manual inspection (targets/scripts/mode + preview) |
| Reports | `/reports` | Reports: defaults to "needs attention", views + filter + batch delete |
| Audit log | `/audit-logs` | Write audit: defaults to "needs attention", detail/restore, CSV/JSON export |
| App logs | `/logs` | Live tail / time range / level filter / download / cleanup |
| Backups | `/backups` | By object / version detail (compare, restore) / import-export |
| Settings | `/settings` | Basic / Model & Data / Collection & Retention tabs |

## Built-in PromQL template library

`init.py` presets the following (runs **not executed by default** — select them under
"Server detail → Prometheus datasource binding" to include them):

| Group | Templates |
|-------|-----------|
| Node Exporter | Disk/Memory/CPU usage, load(1m), uptime, failed services, disk write rate |
| Generic | Target up |
| Proxmox VE | Node/cluster up, node CPU/mem/disk, storages, uptime, not-backed-up, HA fence, subscription, net in/out |
| PVE single VM | CPU/mem, net in/out, disk write, uptime, HA state, not-backed-up (set **VM identity**, uses `$guest`) |
| Nginx | up, active connections, overview, QPS, new-connection rate, active(th), waiting |
| Keepalived | up, script check |
| HTTP | Site availability (`up{job="http_status"}`) |
| Anubis | Proxy request rate |
| VictoriaLogs | Disk usage (metrics via Prometheus) |

- Templates with `# THRESHOLD: >N` do PASS/FAIL and trigger alerts (editable in the script).
- `$instance` is injected from server IP/labels/explicit `prom_instance`; `$guest` is
  resolved by the server's "virtualization identity" to the PVE `id`.

## Prometheus binding examples

> **Sanitized examples** below (hostnames, IPs, datasource names are placeholders); use
> your own environment.

**Where**: `Servers` → a server detail → "Prometheus datasource bindings" → add.

Example datasource: `prod-prom`, `http://<prometheus-host>:9090`, auth `none`. Example
server: `app-node-01`, IP `<SERVER_IP>` (e.g. `10.0.0.11`), group `web`.

- **Case 1 (recommended)**: leave `prom_instance` empty → use the server IP to build
  `instance=~"<IP>(:\d+)?"`, auto-matching ports like `:9100`.
- **Case 2**: explicit `prom_instance=10.0.0.11:9100` (exporter on another host / multiple
  ports on one IP).
- **Case 3**: label override `{"job":"node","env":"prod"}`, or put `env` in the **group**
  "group-level labels" inherited by its servers.

**Three-layer matching priority**: binding `prom_instance` > group `prom_labels_json` +
binding `labels_json` > derived from `servers.ip`.

**Notes**: if the selector matches **>1 instance**, the server is marked `ambiguous`, not
collected, and flagged in the report — set an explicit `prom_instance`. **Pure-Prometheus
inspection requires no SSH.**

## Model provider presets

| Provider | base_url | key var |
|----------|----------|---------|
| DeepSeek | https://api.deepseek.com | `DEEPSEEK_API_KEY` |
| OpenAI | https://api.openai.com/v1 | `OPENAI_API_KEY` |
| Qwen | https://dashscope.aliyuncs.com/compatible-mode/v1 | `DASHSCOPE_API_KEY` |
| Kimi | https://api.moonshot.cn/v1 | `MOONSHOT_API_KEY` |
| GLM | https://open.bigmodel.cn/api/paas/v4 | `ZHIPU_API_KEY` |
| Ollama | http://127.0.0.1:11434/v1 | `OLLAMA_API_KEY` |

> Selecting a preset auto-fills `base_url`/key var/`temperature`/`top_p`/`extra_json`;
> "Pull models" fetches the model-id dropdown from `GET {base_url}/models` (manual entry
> allowed on failure).

## Upgrade / rollback / uninstall / troubleshooting

- Upgrade: `sudo ./deploy/install.sh upgrade` (runs `backup.sh` → stop → update → pip →
  init → start)
- Rollback: stop → restore the `backup.sh` backup → start
- Uninstall: `sudo ./deploy/install.sh uninstall` (deletes data after confirm; use
  `--keep-data` to keep it)
- Status: `sudo ./deploy/install.sh status` / `systemctl status pypimeops` /
  `journalctl -u pypimeops -f`
- Troubleshooting: `logs/pypimeops.log`, port usage, directory permissions (`vault/` 700,
  `secrets.env`/`vault.key` 600)

## FAQ

**Why single-process only?**
The built-in scheduler + in-process thread pool depend on a single process; multiple
workers (e.g. gunicorn) cause duplicate scheduling and break serialized execution.

**Where do I put the model API key?**
In `secrets.env` (e.g. `DEEPSEEK_API_KEY=sk-...`, mode 600). The Models page only stores the
**env var name** (`api_key_env`); the **key is never saved to the database** (read from
`secrets.env` only).

**Can I use it without a model?**
Yes. Inspection runs raw-only; reports are still generated from script thresholds and
advice; only Chatbot is unavailable.

**Can a datasource connect directly to VictoriaLogs?**
No. VictoriaLogs only exposes `/metrics` (scrape format), not a Prometheus query API;
scrape it into Prometheus and query its `vl_*` metrics here.

**How do I inspect a Prometheus-only server (no SSH)?**
Leave SSH port/user/credential empty on the server; then add a Prometheus datasource
binding on its detail page (connection shows `Prometheus`).

**How do I monitor a PVE VM?**
Set the server's "virtualization identity" (VM name or `qemu/xxx`) and select the
`$guest`-based "PVE VM *" templates. A name is resolved to the PVE id at runtime.

**Why do times differ from the logs?**
The database stores **UTC**; pages render in the **host's local timezone** (report
start/end too).

**What happens if the IP allowlist is empty?**
The app does nothing special and shows a **one-time security notice**; use a front
firewall (ufw/iptables) for access control.

**"An inspection is already running"?**
To avoid overloading targets/model calls, the system **runs only one inspection at a
time** (scheduled and manual alike); wait for it to finish or check progress on Reports.

**Will upgrade/uninstall lose data?**
Upgrade runs `backup.sh` first; uninstall deletes data only after confirmation (`--keep-data`
keeps it). `vault.key` and `vault.enc` must be backed up/restored together.

## Version

- Uses **SemVer** (`MAJOR.MINOR.PATCH`): **incompatible** → MAJOR, **compatible** feature → MINOR, **compatible** fix → PATCH; pre-releases use `-rc.N`.
- Current version: **0.1.0** (0.x evolution; `1.0.0` once the API/schema stabilizes).
- Where to see it: the Settings page's "About" area; `./deploy/install.sh status` and the startup log (not a site-wide footer).
- Change history: [`CHANGELOG.md`](CHANGELOG.md); the **single source of truth** is the code constant `config.APP_VERSION`.

## License

Released under the **Apache License 2.0**; see [`LICENSE`](LICENSE).

Third-party components (full list in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)):

- **Python deps**: Flask / markupsafe (BSD-3-Clause), requests (Apache-2.0), PyYAML (MIT),
  cryptography (Apache-2.0 OR BSD-3-Clause), markdown-it-py (MIT), **paramiko (LGPL-2.1)**.
- **Vendored frontend**: Bootstrap 5.3.3 (MIT), copyright notice retained in the file
  headers under `web/static/vendor/`.

**Keep these third-party notices when redistributing.** `paramiko` is LGPL-2.1 and is used
as an **unmodified library** (not merged into this project's source); redistribution must
retain its notice and allow replacing the library.
