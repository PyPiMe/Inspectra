#!/usr/bin/env bash
# 开发便利启动脚本（生产请用 systemd 或 Docker；本脚本仅用于本机快速启动）
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  for c in python3.12 python3.13 python3.11 python3.10 python3; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 11) else 1)' >/dev/null 2>&1; then
      PY="$c"; break
    fi
  done
fi
[ -n "$PY" ] || { echo "[ERROR] 需要 Python 3.11+（Debian 12 可用自带 python3）"; exit 1; }
echo "[*] 使用 Python：$("$PY" --version 2>&1)（$PY）"

if [ ! -d venv ]; then
  echo "[*] 创建虚拟环境 venv"
  "$PY" -m venv venv
fi

echo "[*] 安装依赖"
./venv/bin/pip install -U pip >/dev/null
./venv/bin/pip install -r requirements.txt

if [ ! -f config.yaml ]; then
  echo "[*] 生成 config.yaml（来自 config.yaml.example）"
  cp config.yaml.example config.yaml
  SECRET="$(./venv/bin/python -c 'import secrets;print(secrets.token_hex(32))')"
  "$PY" - "$SECRET" <<'PYEOF'
import re, sys, pathlib
p = pathlib.Path("config.yaml")
p.write_text(re.sub(r'flask_secret:.*', f'flask_secret: "{sys.argv[1]}"', p.read_text()))
PYEOF
fi

if [ ! -f secrets.env ]; then
  echo "[*] 生成 secrets.env（来自 secrets.env.example）"
  cp secrets.env.example secrets.env
  chmod 600 secrets.env
fi

echo "[*] 初始化（幂等）"
./venv/bin/python init.py

echo "[*] 启动 PyPiMeOps（host/port 读 config.yaml）"
exec ./venv/bin/python app.py "$@"
