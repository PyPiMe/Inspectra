"""SQLite 建表、DAO 与事务辅助。

- 全局 WAL + synchronous=NORMAL
- 配置对象主键 INTEGER PRIMARY KEY AUTOINCREMENT（ID 不复用）
- 审计日志、配置对象版本链（backup_versions）与对象变更同事务写入
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

_db_path: str | None = None
_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    desc TEXT DEFAULT '',
    prom_labels_json TEXT DEFAULT '{}',
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS applications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    desc TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS application_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    application_id INTEGER NOT NULL,
    member_type TEXT NOT NULL,
    member_id INTEGER NOT NULL,
    UNIQUE(application_id, member_type, member_id)
);

CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER,
    hostname TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER DEFAULT 22,
    user TEXT DEFAULT '',
    vault_key TEXT DEFAULT '',
    scripts_json TEXT DEFAULT '[]',
    vm_ident TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS scripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    filename TEXT DEFAULT '',
    kind TEXT DEFAULT 'shell',
    desc TEXT DEFAULT '',
    created_at TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS datasources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    base_url TEXT NOT NULL,
    auth_type TEXT DEFAULT 'none',
    secret_env TEXT DEFAULT '',
    verify_tls INTEGER DEFAULT 1,
    timeout INTEGER DEFAULT 10,
    labels_json TEXT DEFAULT '{}',
    enabled INTEGER DEFAULT 1,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS server_datasources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    datasource_id INTEGER NOT NULL,
    prom_instance TEXT DEFAULT '',
    labels_json TEXT DEFAULT '{}',
    scripts_json TEXT DEFAULT '[]',
    enabled INTEGER DEFAULT 1,
    UNIQUE(server_id, datasource_id)
);

CREATE TABLE IF NOT EXISTS models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    provider TEXT DEFAULT 'openai_compat',
    model_id TEXT NOT NULL,
    base_url TEXT NOT NULL,
    api_key_env TEXT DEFAULT '',
    temperature REAL,
    top_p REAL,
    enabled INTEGER DEFAULT 1,
    extra_json TEXT DEFAULT '{}',
    data_policy TEXT DEFAULT 'cloud',
    sanitize_overrides TEXT DEFAULT '',
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    config_json TEXT DEFAULT '{}',
    secret_env TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS vault_entries (
    key TEXT PRIMARY KEY,
    enc_blob BLOB NOT NULL,
    name TEXT DEFAULT '',
    note TEXT DEFAULT '',
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS run_schedule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    targets_json TEXT DEFAULT '{}',
    scripts_json TEXT DEFAULT '[]',
    cron_min TEXT DEFAULT '*',
    cron_hour TEXT DEFAULT '*',
    cron_dow TEXT DEFAULT '*',
    mode TEXT DEFAULT 'model',
    last_fired_at TEXT,
    enabled INTEGER DEFAULT 1,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS run_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started TEXT,
    finished TEXT,
    schedule_id INTEGER,
    trigger TEXT DEFAULT 'manual',
    mode TEXT DEFAULT 'model',
    targets_json TEXT DEFAULT '{}',
    scripts_json TEXT DEFAULT '[]',
    status TEXT DEFAULT 'running',
    policy TEXT DEFAULT '',
    sanitize_hits TEXT DEFAULT '[]',
    error TEXT DEFAULT '',
    summary TEXT DEFAULT '{}',
    report_file TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS run_results (
    run_id INTEGER PRIMARY KEY,
    detail_json TEXT DEFAULT '{}',
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    ip TEXT,
    action TEXT,
    target_type TEXT,
    target_id TEXT,
    target_name TEXT,
    detail TEXT,
    status TEXT,
    version_id INTEGER
);

CREATE TABLE IF NOT EXISTS backup_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    object_type TEXT NOT NULL,
    object_id TEXT,
    version INTEGER NOT NULL,
    action TEXT NOT NULL,
    snapshot_json TEXT,
    operator_ip TEXT,
    note TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_target_type ON audit_log(target_type);
CREATE INDEX IF NOT EXISTS idx_audit_ip_ts ON audit_log(ip, ts);
CREATE INDEX IF NOT EXISTS idx_backup_obj ON backup_versions(object_type, object_id, version);
"""

# 配置对象类型 -> 表名（用于版本备份/审计）
CONFIG_TABLES = {
    "script": "scripts",
    "server": "servers",
    "group": "groups",
    "application": "applications",
    "datasource": "datasources",
    "model": "models",
    "notification": "notifications",
    "schedule": "run_schedule",
    "setting": "settings",
}

TABLE_COLUMNS: dict[str, list[str]] = {
    "groups": ["name", "desc", "prom_labels_json", "created_at", "updated_at"],
    "applications": ["name", "desc", "enabled", "created_at", "updated_at"],
    "application_members": ["application_id", "member_type", "member_id"],
    "servers": ["group_id", "hostname", "ip", "port", "user", "vault_key", "scripts_json", "vm_ident", "enabled", "created_at", "updated_at"],
    "scripts": ["name", "filename", "kind", "desc", "created_at", "updated_at"],
    "datasources": ["name", "base_url", "auth_type", "secret_env", "verify_tls", "timeout", "labels_json", "enabled", "created_at"],
    "server_datasources": ["server_id", "datasource_id", "prom_instance", "labels_json", "scripts_json", "enabled"],
    "models": ["label", "provider", "model_id", "base_url", "api_key_env", "temperature", "top_p", "enabled", "extra_json", "data_policy", "sanitize_overrides", "created_at"],
    "notifications": ["type", "name", "config_json", "secret_env", "enabled", "created_at"],
    "run_schedule": ["name", "targets_json", "scripts_json", "cron_min", "cron_hour", "cron_dow", "mode", "last_fired_at", "enabled", "created_at"],
    "run_history": ["started", "finished", "schedule_id", "trigger", "mode", "targets_json", "scripts_json", "status", "policy", "sanitize_hits", "error", "summary", "report_file"],
    "audit_log": ["ts", "ip", "action", "target_type", "target_id", "target_name", "detail", "status", "version_id"],
    "backup_versions": ["object_type", "object_id", "version", "action", "snapshot_json", "operator_ip", "note", "created_at"],
    "settings": ["key", "value"],
}

DEFAULT_SETTINGS: dict[str, str] = {
    "site_title": "PyPiMeOps",
    "default_language": "zh-CN",
    "app_log_level": "INFO",
    "allowed_ips": "",
    "default_model": "",
    "concurrency": "10",
    "model_concurrency": "3",
    "model_request_timeout": "60",
    "model_retry_times": "2",
    "audit_retention_days": "90",
    "app_log_retention_days": "7",
    "report_retention_days": "90",
    "backup_retention_days": "90",
    "default_data_policy": "cloud",
    "sanitize_enabled": "true",
    "sanitize_rules": "",
    "warn_push_enabled": "true",
    "require_script_metadata": "warn",
    "notify_oversize_enabled": "true",
    "notify_ambiguous_enabled": "true",
    "model_output_max_bytes": "8192",
    "model_batch_max_bytes": "32768",
    "ssh_connect_timeout": "10",
    "ssh_command_timeout": "60",
    "whitelist_ack": "false",
}


def utcnow() -> str:
    """统一 UTC 存储（ISO8601，秒级）。"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def local_str(iso_ts: str | None, fmt: str = "%Y-%m-%d %H:%M:%S %Z") -> str:
    """将 UTC 存储的 ISO 时间换算为部署环境本地时区字符串（仅用于展示）。"""
    if not iso_ts:
        return ""
    try:
        dt = datetime.fromisoformat(iso_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime(fmt)
    except (ValueError, TypeError):
        return iso_ts


def set_db_path(path: str) -> None:
    global _db_path
    _db_path = os.path.abspath(path)


def get_db_path() -> str:
    global _db_path
    if _db_path is None:
        from config import get_config

        _db_path = get_config().db_path
    return _db_path


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(get_db_path(), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=OFF")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    """事务上下文：成功提交，异常回滚。"""
    conn = connect()
    try:
        with _lock:
            yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
    finally:
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """轻量迁移：为既有库补齐新增列并回填审计-版本关联。"""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    if "version_id" not in cols:
        conn.execute("ALTER TABLE audit_log ADD COLUMN version_id INTEGER")
    vcols = {r["name"] for r in conn.execute("PRAGMA table_info(vault_entries)").fetchall()}
    for col, ddl in (("name", "TEXT DEFAULT ''"), ("note", "TEXT DEFAULT ''"), ("created_at", "TEXT")):
        if col not in vcols:
            conn.execute(f"ALTER TABLE vault_entries ADD COLUMN {col} {ddl}")
    scols = {r["name"] for r in conn.execute("PRAGMA table_info(run_schedule)").fetchall()}
    if "mode" not in scols:
        conn.execute("ALTER TABLE run_schedule ADD COLUMN mode TEXT DEFAULT 'model'")
    hcols = {r["name"] for r in conn.execute("PRAGMA table_info(run_history)").fetchall()}
    if "mode" not in hcols:
        conn.execute("ALTER TABLE run_history ADD COLUMN mode TEXT DEFAULT 'model'")
    svcols = {r["name"] for r in conn.execute("PRAGMA table_info(servers)").fetchall()}
    if "vm_ident" not in svcols:
        conn.execute("ALTER TABLE servers ADD COLUMN vm_ident TEXT DEFAULT ''")
    dscols = {r["name"] for r in conn.execute("PRAGMA table_info(datasources)").fetchall()}
    if "labels_json" not in dscols:
        conn.execute("ALTER TABLE datasources ADD COLUMN labels_json TEXT DEFAULT '{}'")
    _backfill_audit_versions(conn)


def _backfill_audit_versions(conn: sqlite3.Connection) -> None:
    """回填历史审计与版本的关联：仅在 (对象类型, 对象ID, 动作, 时间) 唯一匹配时关联，避免误连。"""
    rows = conn.execute(
        "SELECT id, ts, action, target_type, target_id FROM audit_log"
        " WHERE version_id IS NULL AND action IN ('create','update','delete','restore')"
    ).fetchall()
    for r in rows:
        cands = conn.execute(
            "SELECT b.id FROM backup_versions b"
            " WHERE b.object_type=? AND b.object_id=? AND b.action=? AND b.created_at=?"
            " AND b.id NOT IN (SELECT version_id FROM audit_log WHERE version_id IS NOT NULL)",
            (r["target_type"], str(r["target_id"]), r["action"], r["ts"]),
        ).fetchall()
        if len(cands) == 1:
            conn.execute("UPDATE audit_log SET version_id=? WHERE id=?", (cands[0]["id"], r["id"]))


# ---------------------------------------------------------------- 通用 DAO

def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


def insert(conn: sqlite3.Connection, table: str, data: dict[str, Any]) -> int:
    cols = [c for c in TABLE_COLUMNS[table] if c in data]
    placeholders = ",".join("?" for _ in cols)
    sql = f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders})"
    cur = conn.execute(sql, [data[c] for c in cols])
    return int(cur.lastrowid)


def update(conn: sqlite3.Connection, table: str, obj_id: Any, data: dict[str, Any]) -> None:
    cols = [c for c in TABLE_COLUMNS[table] if c in data]
    if not cols:
        return
    assignments = ",".join(f"{c}=?" for c in cols)
    sql = f"UPDATE {table} SET {assignments} WHERE id=?"
    conn.execute(sql, [data[c] for c in cols] + [obj_id])


def delete(conn: sqlite3.Connection, table: str, obj_id: Any) -> None:
    conn.execute(f"DELETE FROM {table} WHERE id=?", (obj_id,))


def fetch_one(table: str, obj_id: Any, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    own = conn is None
    conn = conn or connect()
    try:
        row = conn.execute(f"SELECT * FROM {table} WHERE id=?", (obj_id,)).fetchone()
        return row_to_dict(row)
    finally:
        if own:
            conn.close()


def fetch_all(table: str, where: str = "", params: Iterable[Any] = (), order: str = "id ASC") -> list[dict[str, Any]]:
    conn = connect()
    try:
        sql = f"SELECT * FROM {table}"
        if where:
            sql += f" WHERE {where}"
        if order:
            sql += f" ORDER BY {order}"
        return rows_to_dicts(conn.execute(sql, tuple(params)).fetchall())
    finally:
        conn.close()


def query(sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
    conn = connect()
    try:
        return rows_to_dicts(conn.execute(sql, tuple(params)).fetchall())
    finally:
        conn.close()


# ---------------------------------------------------------------- settings

def get_settings(conn: sqlite3.Connection | None = None) -> dict[str, str]:
    own = conn is None
    conn = conn or connect()
    try:
        out = dict(DEFAULT_SETTINGS)
        for r in conn.execute("SELECT key, value FROM settings").fetchall():
            out[r["key"]] = r["value"]
        return out
    finally:
        if own:
            conn.close()


def get_setting(key: str, default: str = "") -> str:
    conn = connect()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if row is not None:
            return row["value"]
        return DEFAULT_SETTINGS.get(key, default)
    finally:
        conn.close()


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def get_int_setting(key: str, default: int) -> int:
    try:
        return int(get_setting(key, str(default)))
    except (TypeError, ValueError):
        return default


def get_bool_setting(key: str, default: bool = False) -> bool:
    return get_setting(key, "true" if default else "false").strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------- audit & versions

def write_audit(
    conn: sqlite3.Connection,
    ip: str,
    action: str,
    target_type: str,
    target_id: Any = "",
    target_name: str = "",
    detail: Any = "",
    status: str = "ok",
    version_id: int | None = None,
) -> int:
    if not isinstance(detail, str):
        detail = json.dumps(detail, ensure_ascii=False)
    cur = conn.execute(
        "INSERT INTO audit_log (ts, ip, action, target_type, target_id, target_name, detail, status, version_id)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (utcnow(), ip, action, target_type, str(target_id or ""), target_name or "", detail, status, version_id),
    )
    return int(cur.lastrowid)


def next_version(conn: sqlite3.Connection, object_type: str, object_id: Any) -> int:
    row = conn.execute(
        "SELECT MAX(version) AS v FROM backup_versions WHERE object_type=? AND object_id=?",
        (object_type, str(object_id)),
    ).fetchone()
    return int(row["v"] or 0) + 1


def write_version(
    conn: sqlite3.Connection,
    object_type: str,
    object_id: Any,
    action: str,
    snapshot: Any,
    operator_ip: str = "",
    note: str = "",
) -> int:
    """写入版本快照，返回 backup_versions 行 id（用于与审计日志关联）。"""
    version = next_version(conn, object_type, object_id)
    snapshot_json = snapshot if isinstance(snapshot, str) else json.dumps(snapshot, ensure_ascii=False, default=str)
    cur = conn.execute(
        "INSERT INTO backup_versions (object_type, object_id, version, action, snapshot_json, operator_ip, note, created_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (object_type, str(object_id), version, action, snapshot_json, operator_ip, note, utcnow()),
    )
    return int(cur.lastrowid)


def cleanup_audit(retention_days: int) -> int:
    if retention_days <= 0:
        return 0
    conn = connect()
    try:
        cutoff = datetime.now(timezone.utc).timestamp() - retention_days * 86400
        cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).replace(microsecond=0).isoformat()
        cur = conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff_iso,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def cleanup_backups(retention_days: int) -> int:
    if retention_days <= 0:
        return 0
    conn = connect()
    try:
        cutoff = datetime.now(timezone.utc).timestamp() - retention_days * 86400
        cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).replace(microsecond=0).isoformat()
        cur = conn.execute("DELETE FROM backup_versions WHERE created_at < ?", (cutoff_iso,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()
