#!/usr/bin/env bash
# PyPiMeOps 容器入口：幂等生成配置/密钥 → 对齐属主 → 初始化 → 启动。
# Idempotent container entrypoint: generate config/secrets, align ownership, init, then run.
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"
APP_USER="pypimeops"

log() { printf '[entrypoint] %s\n' "$*"; }

# --- 时区（TZ 留空 = UTC）---
if [ -n "${TZ:-}" ] && [ -e "/usr/share/zoneinfo/${TZ}" ]; then
  ln -snf "/usr/share/zoneinfo/${TZ}" /etc/localtime
  printf '%s\n' "${TZ}" > /etc/timezone
  log "TZ=${TZ}"
else
  log "TZ 未设置，使用 UTC"
fi

mkdir -p "$DATA_DIR"

# --- config.yaml（缺则按模板生成并注入随机 flask_secret）---
if [ ! -f "$DATA_DIR/config.yaml" ]; then
  log "生成 config.yaml"
  cp /app/config.yaml.example "$DATA_DIR/config.yaml"
  SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
  python - "$DATA_DIR/config.yaml" "$SECRET" <<'PYEOF'
import pathlib, re, sys
path, secret = sys.argv[1], sys.argv[2]
p = pathlib.Path(path)
text = re.sub(r'(?m)^flask_secret:.*$', f'flask_secret: "{secret}"', p.read_text())
p.write_text(text)
PYEOF
else
  log "config.yaml 已存在，跳过"
fi

# --- secrets.env（缺则生成并 chmod 600）---
if [ ! -f "$DATA_DIR/secrets.env" ]; then
  log "生成 secrets.env"
  cp /app/secrets.env.example "$DATA_DIR/secrets.env"
fi
chmod 600 "$DATA_DIR/secrets.env" 2>/dev/null || true

# --- PUID/PGID 对齐（建立同名用户/组，非 root 运行）---
if ! getent group "$PGID" >/dev/null 2>&1; then
  groupadd -g "$PGID" "$APP_USER"
fi
if ! getent passwd "$PUID" >/dev/null 2>&1; then
  useradd -u "$PUID" -g "$PGID" -M -s /usr/sbin/nologin "$APP_USER"
fi

chown -R "$PUID:$PGID" "$DATA_DIR"
mkdir -p "$DATA_DIR/vault" "$DATA_DIR/scripts" "$DATA_DIR/reports" "$DATA_DIR/logs"
chown -R "$PUID:$PGID" "$DATA_DIR"

# --- 初始化（幂等）后启动（exec 转发信号）---
log "初始化数据库与内置种子（init.py）"
gosu "$PUID:$PGID" python /app/init.py --config "$DATA_DIR/config.yaml"

log "启动 PyPiMeOps"
exec gosu "$PUID:$PGID" python /app/app.py --config "$DATA_DIR/config.yaml"
