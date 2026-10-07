#!/usr/bin/env bash
# PyPiMeOps 一键安装/升级/卸载/状态脚本
# 用法：
#   ./deploy/install.sh install   [选项]
#   ./deploy/install.sh upgrade   [选项]
#   ./deploy/install.sh uninstall [选项]
#   ./deploy/install.sh status    [选项]
set -euo pipefail

APP_DIR="/opt/pypimeops"
SVC_USER="pypimeops"
WEB_HOST="0.0.0.0"
WEB_PORT="8080"
MODE="systemd"
PYTHON=""   # 空=自动探测（3.12/3.13/3.11/3.10/python3）
MIN_PY="3.11"
SERVICE_NAME="pypimeops"
REPO=""
SRC_DIR=""
INSTALL_DEPS=0
ASSUME_YES=0
KEEP_DATA=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CMD="install"

log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,8p' "$0"
  cat <<'EOF'

选项：
  --app-dir DIR        安装目录（默认 /opt/pypimeops）
  --user NAME          服务用户（默认 pypimeops）
  --host HOST          Web 监听地址（默认 0.0.0.0）
  --port PORT          Web 监听端口（默认 8080）
  --mode MODE          systemd|docker|dev（默认 systemd）
  --python BIN         指定 Python 解释器（默认自动探测 3.12/3.13/3.11/3.10/python3，需 >= 3.11）
  --service-name NAME  systemd 服务名（默认 pypimeops）
  --repo URL           git 仓库地址（与 --src 二选一，可选）
  --src DIR            本地源码目录（可选）
  --install-deps       自动安装系统依赖（默认仅检测提示）
  --keep-data          卸载时保留数据目录
  -y, --yes            非交互，全部确认
  -h, --help           帮助
EOF
}

confirm() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  local ans
  read -r -p "$1 [y/N] " ans
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "该操作需要 root 权限，请使用 sudo 运行。"
  fi
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then echo apt; return; fi
  if command -v dnf >/dev/null 2>&1; then echo dnf; return; fi
  if command -v yum >/dev/null 2>&1; then echo yum; return; fi
  echo none
}

python_ok() {
  # 判断解释器版本是否 >= MIN_PY
  "$1" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 11) else 1)' >/dev/null 2>&1
}

find_python() {
  if [ -n "$PYTHON" ]; then
    if command -v "$PYTHON" >/dev/null 2>&1 && python_ok "$PYTHON"; then
      return 0
    fi
    warn "指定的解释器不可用或版本 < $MIN_PY：$PYTHON"
    return 1
  fi
  local c
  for c in python3.12 python3.13 python3.11 python3.10 python3; do
    if command -v "$c" >/dev/null 2>&1 && python_ok "$c"; then
      PYTHON="$c"
      return 0
    fi
  done
  return 1
}

apt_has() {
  apt-cache show "$1" >/dev/null 2>&1
}

install_system_deps() {
  local mgr; mgr="$(detect_pkg_mgr)"
  log "使用 $mgr 安装系统依赖"
  case "$mgr" in
    apt)
      apt-get update
      local pkgs=(gcc libffi-dev libssl-dev python3-pip)
      # Debian 12(bookworm) 无 python3.12 包；仅在仓库确实提供时才装 3.12/3.13，否则用发行版自带 python3
      if apt_has python3.12 && apt_has python3.12-venv; then
        pkgs+=(python3.12 python3.12-venv)
      elif apt_has python3.13 && apt_has python3.13-venv; then
        pkgs+=(python3.13 python3.13-venv)
      else
        pkgs+=(python3 python3-venv)
      fi
      apt-get install -y "${pkgs[@]}"
      ;;
    dnf)
      dnf install -y gcc libffi-devel openssl-devel python3 python3-pip
      ;;
    yum)
      yum install -y gcc libffi-devel openssl-devel python3
      ;;
    none)
      warn "未识别的包管理器，请手动安装 Python $MIN_PY+ 与编译依赖。"
      ;;
  esac
}

ensure_user_and_dirs() {
  if id "$SVC_USER" >/dev/null 2>&1; then
    ok "服务用户 $SVC_USER 已存在"
  else
    log "创建服务用户 $SVC_USER"
    useradd -r -s /sbin/nologin "$SVC_USER"
  fi
  mkdir -p "$APP_DIR"
  chown -R "$SVC_USER":"$SVC_USER" "$APP_DIR"
  chmod 700 "$APP_DIR/vault" 2>/dev/null || true
}

setup_env_file() {
  if [ ! -f "$APP_DIR/.env" ]; then
    log "生成 .env（Docker 环境变量）"
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"
  else
    ok ".env 已存在，跳过"
  fi
  mkdir -p "$APP_DIR/data"
}

place_code() {
  if [ -n "$REPO" ]; then
    if [ -d "$APP_DIR/.git" ]; then
      log "更新代码（git pull）"
      git -C "$APP_DIR" pull --ff-only
    else
      log "克隆代码到 $APP_DIR"
      git clone "$REPO" "$APP_DIR"
    fi
  elif [ -n "$SRC_DIR" ]; then
    log "从 $SRC_DIR 复制代码到 $APP_DIR"
    cp -a "$SRC_DIR"/. "$APP_DIR"/
  else
    if [ "$REPO_ROOT" != "$APP_DIR" ]; then
      log "从 $REPO_ROOT 复制代码到 $APP_DIR"
      mkdir -p "$APP_DIR"
      cp -a "$REPO_ROOT"/. "$APP_DIR"/
    else
      ok "原地安装（代码已在 $APP_DIR）"
    fi
  fi
  chown -R "$SVC_USER":"$SVC_USER" "$APP_DIR"
}

setup_venv() {
  if [ -x "$APP_DIR/venv/bin/python" ]; then
    ok "复用已有虚拟环境：$APP_DIR/venv"
  else
    [ -n "$PYTHON" ] || find_python || die "未找到 Python $MIN_PY+，无法创建虚拟环境"
    if ! "$PYTHON" -m venv --help >/dev/null 2>&1; then
      die "Python 缺少 venv 模块。请安装 ${PYTHON}-venv 或 python3-venv，或使用 --install-deps"
    fi
    log "创建虚拟环境并安装依赖（$PYTHON）"
    "$PYTHON" -m venv "$APP_DIR/venv"
  fi
  "$APP_DIR/venv/bin/pip" install -U pip >/dev/null
  "$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
}

fix_perms() {
  chown -R "$SVC_USER":"$SVC_USER" "$APP_DIR"
  mkdir -p "$APP_DIR/vault"
  chmod 700 "$APP_DIR/vault" 2>/dev/null || true
  [ -f "$APP_DIR/vault/vault.key" ] && chmod 600 "$APP_DIR/vault/vault.key" 2>/dev/null || true
  [ -f "$APP_DIR/secrets.env" ] && chmod 600 "$APP_DIR/secrets.env" 2>/dev/null || true
  return 0
}

setup_config() {
  if [ ! -f "$APP_DIR/config.yaml" ]; then
    log "生成 config.yaml"
    cp "$APP_DIR/config.yaml.example" "$APP_DIR/config.yaml"
    local secret
    secret="$("$APP_DIR/venv/bin/python" -c 'import secrets;print(secrets.token_hex(32))')"
    "$APP_DIR/venv/bin/python" - "$APP_DIR/config.yaml" "$WEB_HOST" "$WEB_PORT" "$secret" <<'PYEOF'
import re, sys, pathlib
path, host, port, secret = sys.argv[1:5]
p = pathlib.Path(path)
text = p.read_text()
text = re.sub(r'(?m)^host:.*$', f'host: {host}', text)
text = re.sub(r'(?m)^port:.*$', f'port: {port}', text)
text = re.sub(r'(?m)^flask_secret:.*$', f'flask_secret: "{secret}"', text)
p.write_text(text)
PYEOF
  else
    ok "config.yaml 已存在，跳过（不覆盖）"
  fi
  if [ ! -f "$APP_DIR/secrets.env" ]; then
    log "生成 secrets.env"
    cp "$APP_DIR/secrets.env.example" "$APP_DIR/secrets.env"
    chmod 600 "$APP_DIR/secrets.env"
  else
    ok "secrets.env 已存在，跳过（不覆盖）"
  fi
  fix_perms
}

run_init() {
  log "初始化数据库（幂等）"
  if [ "$(id -u)" -eq 0 ] && id "$SVC_USER" >/dev/null 2>&1; then
    if command -v runuser >/dev/null 2>&1; then
      ( cd "$APP_DIR" && runuser -u "$SVC_USER" -- "$APP_DIR/venv/bin/python" init.py )
    elif command -v sudo >/dev/null 2>&1; then
      ( cd "$APP_DIR" && sudo -u "$SVC_USER" "$APP_DIR/venv/bin/python" init.py )
    else
      ( cd "$APP_DIR" && "$APP_DIR/venv/bin/python" init.py )
    fi
  else
    ( cd "$APP_DIR" && "$APP_DIR/venv/bin/python" init.py )
  fi
}

register_systemd() {
  log "注册 systemd 服务 $SERVICE_NAME"
  sed -e "s|__APP_DIR__|$APP_DIR|g" -e "s|__SVC_USER__|$SVC_USER|g" \
    "$APP_DIR/deploy/pypimeops.service" > "/etc/systemd/system/${SERVICE_NAME}.service"
  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
}

register_docker() {
  command -v docker >/dev/null 2>&1 || die "未找到 docker，请先安装。"
  log "以 Docker Compose 启动"
  ( cd "$APP_DIR" && docker compose up -d --build )
}

print_next_steps() {
  ok "安装完成"
  case "$MODE" in
    systemd)
      cat <<EOF
验证：
  systemctl status $SERVICE_NAME
  journalctl -u $SERVICE_NAME -f
  curl -I http://127.0.0.1:$WEB_PORT
EOF
      ;;
    docker)
      echo "验证：docker compose ps / docker compose logs -f / curl -I http://127.0.0.1:$WEB_PORT"
      ;;
    dev)
      cat <<EOF
开发模式：手动启动
  cd $APP_DIR
  ./venv/bin/python app.py            # host/port 读 config.yaml
EOF
      ;;
  esac
  echo "后续：在 Web 页面录入 凭据/服务器/数据源/模型/通知 并绑定脚本。"
}

do_install() {
  case "$MODE" in systemd|docker) need_root ;; esac
  if [ "$INSTALL_DEPS" -eq 1 ]; then
    need_root
    install_system_deps
  fi
  # Docker 模式：镜像自包含，初始化交容器入口，不依赖宿主 Python/venv/init。
  # Docker mode: the image is self-contained; init runs in the container.
  if [ "$MODE" = docker ]; then
    mkdir -p "$APP_DIR"
    place_code
    setup_env_file
    register_docker
    print_next_steps
    return 0
  fi
  if ! find_python; then
    if [ "$INSTALL_DEPS" -eq 1 ]; then
      die "已尝试安装系统依赖，仍未找到 Python $MIN_PY+。请手动安装后用 --python 指定。"
    else
      warn "可加 --install-deps 自动安装，或用 --python 指定解释器。"
      die "未找到 Python $MIN_PY+（Debian 12 自带 python3=3.11，可直接使用）"
    fi
  fi
  ok "使用 Python：$("$PYTHON" --version 2>&1)（$PYTHON）"
  ensure_user_and_dirs
  place_code
  setup_venv
  setup_config
  run_init
  fix_perms
  case "$MODE" in
    systemd) register_systemd ;;
    dev) ok "dev 模式：跳过服务注册" ;;
    *) die "未知模式：$MODE" ;;
  esac
  print_next_steps
}

do_upgrade() {
  case "$MODE" in systemd|docker) need_root ;; esac
  [ "$MODE" = docker ] || find_python || true
  log "升级前整机备份"
  ( cd "$APP_DIR" && bash backup.sh ) || warn "backup.sh 执行失败，请确认后继续"
  # 失败兜底：即使后续步骤出错也把服务拉起来，避免升级中断导致停服
  if [ "$MODE" = systemd ]; then
    trap 'systemctl start "$SERVICE_NAME" 2>/dev/null || true' EXIT
  fi
  case "$MODE" in
    systemd) systemctl stop "$SERVICE_NAME" || true ;;
    docker) ( cd "$APP_DIR" && docker compose down ) || true ;;
  esac
  place_code
  if [ "$MODE" = docker ]; then
    setup_env_file
  else
    setup_venv
    run_init
    fix_perms
  fi
  case "$MODE" in
    systemd) systemctl start "$SERVICE_NAME" ;;
    docker) register_docker ;;
  esac
  [ "$MODE" = systemd ] && trap - EXIT
  ok "升级完成"
}

do_uninstall() {
  need_root
  case "$MODE" in
    systemd) systemctl disable --now "$SERVICE_NAME" || true; rm -f "/etc/systemd/system/${SERVICE_NAME}.service"; systemctl daemon-reload ;;
    docker) ( cd "$APP_DIR" && docker compose down ) || true ;;
  esac
  if [ "$KEEP_DATA" -eq 1 ]; then
    ok "保留数据目录 $APP_DIR（未删除）"
  elif confirm "确认删除数据目录 $APP_DIR（含数据库/凭据/报告）？"; then
    rm -rf "$APP_DIR"
    ok "已删除 $APP_DIR"
  else
    ok "保留数据目录 $APP_DIR"
  fi
  if confirm "删除服务用户 $SVC_USER？"; then
    userdel "$SVC_USER" 2>/dev/null || true
  fi
}

do_status() {
  local ver=""
  if [ -x "$APP_DIR/venv/bin/python" ]; then
    ver="$("$APP_DIR/venv/bin/python" -c "import sys; sys.path.insert(0, '$APP_DIR'); from config import APP_VERSION; print(APP_VERSION)" 2>/dev/null || true)"
  fi
  if [ -n "$ver" ]; then echo "版本：$ver"; fi
  case "$MODE" in
    systemd) systemctl status "$SERVICE_NAME" --no-pager || true; echo "日志：journalctl -u $SERVICE_NAME -f" ;;
    docker) ( cd "$APP_DIR" && docker compose ps ) || true; echo "日志：docker compose logs -f" ;;
    dev) echo "dev 模式无托管服务；日志见 $APP_DIR/logs/" ;;
  esac
}

# ---- 参数解析
while [ $# -gt 0 ]; do
  case "$1" in
    install|upgrade|uninstall|status) CMD="$1"; shift ;;
    --app-dir) APP_DIR="$2"; shift 2 ;;
    --user) SVC_USER="$2"; shift 2 ;;
    --host) WEB_HOST="$2"; shift 2 ;;
    --port) WEB_PORT="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --python) PYTHON="$2"; shift 2 ;;
    --service-name) SERVICE_NAME="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --src) SRC_DIR="$2"; shift 2 ;;
    --install-deps) INSTALL_DEPS=1; shift ;;
    --keep-data) KEEP_DATA=1; shift ;;
    -y|--yes) ASSUME_YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数：$1（--help 查看用法）" ;;
  esac
done

case "$CMD" in
  install) do_install ;;
  upgrade) do_upgrade ;;
  uninstall) do_uninstall ;;
  status) do_status ;;
  *) usage; exit 1 ;;
esac
