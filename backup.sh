#!/usr/bin/env bash
# 整机灾备：备份 pypimeops.db + vault/（含 vault.enc/vault.key/known_hosts）+ scripts/ + secrets.env
# 与 backup.py 配置版本备份并存。恢复流程见 README。
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${BACKUP_DIR:-$APP_DIR/backups}"
STAMP="$(date +%Y%m%d_%H%M%S)"
ARCHIVE="$BACKUP_DIR/pypimeops_backup_$STAMP.tar.gz"

mkdir -p "$BACKUP_DIR"
cd "$APP_DIR"

# 解析 config.yaml 中的路径（优先用 venv python，失败则回退默认）
eval "$(
  ./venv/bin/python - <<'PYEOF' 2>/dev/null || true
import os
try:
    import yaml
    with open("config.yaml") as fh:
        data = yaml.safe_load(fh) or {}
    paths = data.get("paths") or {}
    vault_dir = paths.get("vault") or "./vault"
    scripts_dir = paths.get("scripts") or "./scripts"
    vault_key = paths.get("vault_key") or os.path.join(vault_dir, "vault.key")
    secrets_env = data.get("secrets_env") or "./secrets.env"
    print(f'VAULT_DIR="{vault_dir}"')
    print(f'SCRIPTS_DIR="{scripts_dir}"')
    print(f'VAULT_KEY="{vault_key}"')
    print(f'SECRETS_ENV="{secrets_env}"')
except Exception:
    raise SystemExit(1)
PYEOF
)"
VAULT_DIR="${VAULT_DIR:-./vault}"
SCRIPTS_DIR="${SCRIPTS_DIR:-./scripts}"
VAULT_KEY="${VAULT_KEY:-./vault/vault.key}"
SECRETS_ENV="${SECRETS_ENV:-./secrets.env}"

ITEMS=(pypimeops.db "$SCRIPTS_DIR")
[ -d "$VAULT_DIR" ] && ITEMS+=("$VAULT_DIR")
[ -f "$SECRETS_ENV" ] && ITEMS+=("$SECRETS_ENV")
# vault.key 外置时单独加入
case "$VAULT_KEY" in
  "$VAULT_DIR"/*) : ;;
  *) [ -f "$VAULT_KEY" ] && ITEMS+=("$VAULT_KEY") ;;
esac

echo "[*] 备份到 $ARCHIVE"
tar -czf "$ARCHIVE" "${ITEMS[@]}"
echo "[OK] 完成：$ARCHIVE"
echo "提示：恢复时解压覆盖到 APP_DIR 后重启服务；vault.key 与 vault.enc 必须同时还原。"
