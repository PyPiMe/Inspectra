"""启动配置加载（config.yaml）+ secrets.env 读取。

config.yaml 仅存放启动参数：host/port/路径/轮询间隔/SSH 批次大小/flask secret/secrets.env 路径。
其余运行时可变项一律存 settings 表（见 models.py / app.py）。
"""
from __future__ import annotations

import os
import secrets
from typing import Any

import yaml

_DEFAULT_CONFIG = "config.yaml"
_config: "Config | None" = None

# Application version (SemVer). Single source of truth; keep pyproject/README/CHANGELOG in sync.
# 应用版本（SemVer），单一来源；请同步 pyproject/README/CHANGELOG。
APP_VERSION = "0.1.0"


class Config:
    def __init__(self, data: dict[str, Any], base_dir: str):
        self.base_dir = os.path.abspath(base_dir)
        self.raw = data

        self.host: str = str(data.get("host", "0.0.0.0"))
        self.port: int = int(data.get("port", 8080))

        paths = data.get("paths") or {}

        def _abs(p: str | None, default: str) -> str:
            p = p or default
            if os.path.isabs(p):
                return p
            return os.path.normpath(os.path.join(self.base_dir, p))

        self.scripts_dir = _abs(paths.get("scripts"), "./scripts")
        self.reports_dir = _abs(paths.get("reports"), "./reports")
        self.vault_dir = _abs(paths.get("vault"), "./vault")
        self.logs_dir = _abs(paths.get("logs"), "./logs")
        self.known_hosts = _abs(paths.get("known_hosts"), "./vault/known_hosts")

        # vault.key 支持外置：config paths.vault_key 优先，其次环境变量 PYPIMEOPS_VAULT_KEY_PATH，最后默认同目录
        vault_key = paths.get("vault_key") or os.environ.get("PYPIMEOPS_VAULT_KEY_PATH")
        self.vault_key_path = _abs(vault_key, "./vault/vault.key") if vault_key else os.path.join(self.vault_dir, "vault.key")

        self.secrets_env = _abs(data.get("secrets_env"), "./secrets.env")
        self.db_path = _abs(paths.get("db"), "./pypimeops.db")

        self.poll_interval = int(data.get("poll_interval", 15))
        self.ssh_batch_size = int(data.get("ssh_batch_size", 10))
        self.flask_secret = str(data.get("flask_secret") or secrets.token_hex(32))

    def ensure_dirs(self) -> None:
        for d in (self.scripts_dir, self.reports_dir, self.vault_dir, self.logs_dir):
            os.makedirs(d, exist_ok=True)
        os.makedirs(os.path.dirname(self.known_hosts), exist_ok=True)

    def load_secrets(self) -> dict[str, str]:
        return load_secrets_env(self.secrets_env)


def load_secrets_env(path: str) -> dict[str, str]:
    """解析 KEY=VALUE 形式的 secrets.env（忽略注释与空行，去首尾引号）。"""
    out: dict[str, str] = {}
    if not path or not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key:
                out[key] = val
    return out


def load_config(path: str | None = None) -> Config:
    cfg_path = path or os.environ.get("PYPIMEOPS_CONFIG") or _DEFAULT_CONFIG
    if not os.path.isfile(cfg_path):
        raise FileNotFoundError(
            f"配置文件不存在: {cfg_path}（请先 `cp config.yaml.example config.yaml` 并按需修改）"
        )
    with open(cfg_path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"配置文件格式错误（应为 YAML 映射）: {cfg_path}")
    base_dir = os.path.dirname(os.path.abspath(cfg_path))
    return Config(data, base_dir)


def get_config(path: str | None = None) -> Config:
    global _config
    if _config is None:
        _config = load_config(path)
    return _config


def set_config(cfg: Config) -> None:
    global _config
    _config = cfg
