"""配置对象版本备份/恢复（backup_versions）+ 全量导出/导入。

- 覆盖全配置对象（脚本/服务器/分组/数据源/模型/通知/定时任务/settings 逐键）
- 恢复前自动把当前状态存为新版本；恢复保留原对象 ID；恢复前校验引用完整性
- 导入双模式：migrate=覆盖式（保留原 ID 与版本链，仅空库或二次确认）；daily=新增式（分配新 ID）
"""
from __future__ import annotations

import json
import os
from typing import Any

import models
import vault as vault_mod
from config import get_config

CONFIG_ORDER = ["group", "datasource", "model", "notification", "script", "server", "schedule"]


# ------------------------------------------------------------ 脚本正文文件

def script_ext(kind: str) -> str:
    return ".promql" if (kind or "shell") == "promql" else ".sh"


def script_path(script: dict[str, Any]) -> str:
    return os.path.join(get_config().scripts_dir, f"{script['id']}{script_ext(script.get('kind'))}")


def read_script(script: dict[str, Any]) -> str:
    path = script_path(script)
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    return ""


def write_script(script: dict[str, Any], content: str) -> None:
    """先写临时文件，事务提交成功后由调用方原子 rename（此处直接原子写）。"""
    cfg = get_config()
    os.makedirs(cfg.scripts_dir, exist_ok=True)
    path = script_path(script)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(content or "")
    os.replace(tmp, path)


def remove_script_file(script: dict[str, Any]) -> None:
    path = script_path(script)
    try:
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


# ------------------------------------------------------------ 快照

def snapshot_object(conn, object_type: str, object_id: Any) -> dict[str, Any] | None:
    table = models.CONFIG_TABLES.get(object_type)
    if not table:
        return None
    if object_type == "setting":
        row = conn.execute("SELECT key, value FROM settings WHERE key=?", (object_id,)).fetchone()
        return dict(row) if row else None
    row = conn.execute(f"SELECT * FROM {table} WHERE id=?", (object_id,)).fetchone()
    if row is None:
        return None
    data = dict(row)
    if object_type == "script":
        data["content"] = read_script(data)
    return data


def record(conn, object_type: str, object_id: Any, action: str, snapshot: dict[str, Any] | None, operator_ip: str = "", note: str = "") -> int:
    return models.write_version(conn, object_type, object_id, action, snapshot or {}, operator_ip, note)


def list_versions(
    object_type: str | None = None,
    object_id: Any = None,
    action: str | None = None,
    limit: int = 100,
    offset: int = 0,
    exclude_audited: bool = False,
) -> list[dict[str, Any]]:
    where = []
    params: list[Any] = []
    if object_type:
        where.append("object_type=?")
        params.append(object_type)
    if object_id is not None and object_id != "":
        where.append("object_id=?")
        params.append(str(object_id))
    if action:
        where.append("action=?")
        params.append(action)
    if exclude_audited:
        where.append("id NOT IN (SELECT version_id FROM audit_log WHERE version_id IS NOT NULL)")
    sql = "SELECT * FROM backup_versions"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    return models.query(sql, params)


def count_versions(
    object_type: str | None = None,
    object_id: Any = None,
    action: str | None = None,
    exclude_audited: bool = False,
) -> int:
    where, params = [], []
    if object_type:
        where.append("object_type=?")
        params.append(object_type)
    if object_id is not None and object_id != "":
        where.append("object_id=?")
        params.append(str(object_id))
    if action:
        where.append("action=?")
        params.append(action)
    if exclude_audited:
        where.append("id NOT IN (SELECT version_id FROM audit_log WHERE version_id IS NOT NULL)")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    return int(models.query(f"SELECT COUNT(*) AS c FROM backup_versions{clause}", params)[0]["c"])


def get_version(version_id: int) -> dict[str, Any] | None:
    rows = models.query("SELECT * FROM backup_versions WHERE id=?", (version_id,))
    return rows[0] if rows else None


def parse_snapshot(row: dict[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(row.get("snapshot_json") or "{}")
    except (ValueError, TypeError):
        return {}


def diff_snapshots(a: dict[str, Any] | None, b: dict[str, Any] | None) -> list[dict[str, Any]]:
    a = a or {}
    b = b or {}
    keys = sorted(set(a) | set(b))
    out = []
    for k in keys:
        if k in ("created_at", "updated_at", "id"):
            continue
        if a.get(k) != b.get(k):
            out.append({"key": k, "old": a.get(k), "new": b.get(k)})
    return out


# ------------------------------------------------------------ 引用完整性

def check_references(conn, object_type: str, snapshot: dict[str, Any]) -> list[str]:
    missing: list[str] = []

    def _exists(table: str, obj_id: Any) -> bool:
        if obj_id in (None, "", 0, "0"):
            return True
        return conn.execute(f"SELECT 1 FROM {table} WHERE id=?", (obj_id,)).fetchone() is not None

    def _parse_ids(raw: Any) -> list[int]:
        try:
            val = json.loads(raw) if isinstance(raw, str) else (raw or [])
            return [int(x) for x in val if str(x).strip() not in ("", "None")]
        except (ValueError, TypeError):
            return []

    if object_type == "server":
        gid = snapshot.get("group_id")
        if gid and not _exists("groups", gid):
            missing.append(f"分组 #{gid}")
        vk = snapshot.get("vault_key")
        if vk:
            row = conn.execute("SELECT 1 FROM vault_entries WHERE key=?", (vk,)).fetchone()
            if row is None:
                missing.append(f"凭据 {vk}")
        for sid in _parse_ids(snapshot.get("scripts_json")):
            if not _exists("scripts", sid):
                missing.append(f"脚本 #{sid}")
    elif object_type == "schedule":
        targets = snapshot.get("targets_json")
        try:
            targets = json.loads(targets) if isinstance(targets, str) else (targets or {})
        except (ValueError, TypeError):
            targets = {}
        for sid in targets.get("servers", []):
            if not _exists("servers", sid):
                missing.append(f"服务器 #{sid}")
        for gid in targets.get("groups", []):
            if not _exists("groups", gid):
                missing.append(f"分组 #{gid}")
        for did in targets.get("datasources", []):
            if not _exists("datasources", did):
                missing.append(f"数据源 #{did}")
        for sid in _parse_ids(snapshot.get("scripts_json")):
            if not _exists("scripts", sid):
                missing.append(f"脚本 #{sid}")
    return missing


# ------------------------------------------------------------ 恢复

def restore(version_id: int, operator_ip: str = "") -> tuple[bool, str]:
    row = get_version(version_id)
    if not row:
        return False, "版本不存在"
    object_type = row["object_type"]
    object_id = row["object_id"]
    snapshot = parse_snapshot(row)
    if not snapshot:
        return False, "快照为空，无法恢复"
    if object_type == "setting":
        return _restore_setting(object_id, snapshot, operator_ip)
    if object_type not in models.CONFIG_TABLES:
        return False, f"不支持恢复的对象类型：{object_type}"

    table = models.CONFIG_TABLES[object_type]
    with models.db() as conn:
        missing = check_references(conn, object_type, snapshot)
        if missing:
            return False, "引用完整性校验失败，请先恢复依赖：" + "、".join(missing)

        existing = conn.execute(f"SELECT * FROM {table} WHERE id=?", (object_id,)).fetchone()
        if existing is None:
            occupied = conn.execute(f"SELECT 1 FROM {table} WHERE id=?", (object_id,)).fetchone()
            if occupied is not None:
                return False, f"对象 ID #{object_id} 已被占用，拒绝恢复（ID 不复用）"
            # 恢复已删除对象：保留原 ID
            cols = [c for c in models.TABLE_COLUMNS[table] if c in snapshot]
            placeholders = ",".join("?" for _ in cols)
            conn.execute(
                f"INSERT INTO {table} (id,{','.join(cols)}) VALUES (?,{placeholders})",
                [object_id] + [snapshot.get(c) for c in cols],
            )
            action = "restore"
        else:
            # 恢复前把当前状态存为新版本
            current = snapshot_object(conn, object_type, object_id)
            record(conn, object_type, object_id, "update", current, operator_ip, note="恢复前自动备份当前状态")
            cols = [c for c in models.TABLE_COLUMNS[table] if c in snapshot]
            assignments = ",".join(f"{c}=?" for c in cols)
            conn.execute(f"UPDATE {table} SET {assignments} WHERE id=?", [snapshot.get(c) for c in cols] + [object_id])
            action = "restore"

        if object_type == "script":
            write_script(snapshot, snapshot.get("content", ""))

        vid = record(conn, object_type, object_id, action, snapshot, operator_ip, note=f"恢复版本 {row['version']}")
        models.write_audit(
            conn,
            operator_ip,
            "restore",
            object_type,
            object_id,
            snapshot.get("name") or snapshot.get("label") or snapshot.get("hostname") or str(object_id),
            {"version": row["version"]},
            version_id=vid,
        )
    return True, "恢复成功"


def _restore_setting(key: str, snapshot: dict[str, Any], operator_ip: str) -> tuple[bool, str]:
    with models.db() as conn:
        current = snapshot_object(conn, "setting", key)
        if current:
            record(conn, "setting", key, "update", current, operator_ip, note="恢复前自动备份当前状态")
        models.set_setting(conn, key, snapshot.get("value", ""))
        vid = record(conn, "setting", key, "restore", snapshot, operator_ip, note="恢复设置")
        models.write_audit(conn, operator_ip, "restore", "setting", key, key, snapshot, version_id=vid)
    return True, "恢复成功"


# ------------------------------------------------------------ 全量导出/导入

def export_all() -> dict[str, Any]:
    with models.db() as conn:
        data: dict[str, Any] = {"version": 1, "settings": {}, "objects": {}, "versions": [], "vault_entries": []}
        for row in conn.execute("SELECT key, value FROM settings").fetchall():
            data["settings"][row["key"]] = row["value"]
        for obj_type, table in models.CONFIG_TABLES.items():
            if obj_type == "setting":
                continue
            items = []
            for row in conn.execute(f"SELECT * FROM {table} ORDER BY id ASC").fetchall():
                item = dict(row)
                if obj_type == "script":
                    item["content"] = read_script(item)
                items.append(item)
            data["objects"][obj_type] = items
        data["objects"]["server_datasources"] = [
            dict(r) for r in conn.execute("SELECT * FROM server_datasources ORDER BY id ASC").fetchall()
        ]
        for row in conn.execute("SELECT * FROM backup_versions ORDER BY id ASC").fetchall():
            data["versions"].append(dict(row))
        for row in conn.execute("SELECT key, enc_blob, name, note, created_at FROM vault_entries").fetchall():
            import base64

            data["vault_entries"].append(
                {
                    "key": row["key"],
                    "enc_blob": base64.b64encode(row["enc_blob"]).decode("ascii"),
                    "name": row["name"] or "",
                    "note": row["note"] or "",
                    "created_at": row["created_at"] or "",
                }
            )
    return data


def import_all(data: dict[str, Any], mode: str = "daily", force: bool = False, operator_ip: str = "") -> tuple[bool, str]:
    import base64

    objects = data.get("objects") or {}
    if mode == "migrate":
        with models.db() as conn:
            existing = 0
            for obj_type, table in models.CONFIG_TABLES.items():
                if obj_type == "setting":
                    continue
                existing += conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
            if existing and not force:
                return False, "目标库非空：覆盖式导入需二次确认（force）"
        return _import_migrate(data, operator_ip)
    return _import_daily(objects, operator_ip)


def _import_migrate(data: dict[str, Any], operator_ip: str) -> tuple[bool, str]:
    import base64

    with models.db() as conn:
        for obj_type, table in models.CONFIG_TABLES.items():
            if obj_type == "setting":
                continue
            conn.execute(f"DELETE FROM {table}")
        conn.execute("DELETE FROM server_datasources")
        conn.execute("DELETE FROM backup_versions")
        conn.execute("DELETE FROM vault_entries")
        conn.execute("DELETE FROM settings")

        for entry in data.get("vault_entries") or []:
            conn.execute(
                "INSERT OR REPLACE INTO vault_entries (key, enc_blob, name, note, created_at) VALUES (?, ?, ?, ?, ?)",
                (
                    entry["key"],
                    base64.b64decode(entry["enc_blob"]),
                    entry.get("name", ""),
                    entry.get("note", ""),
                    entry.get("created_at", ""),
                ),
            )
        for key, value in (data.get("settings") or {}).items():
            models.set_setting(conn, key, value)
        for obj_type in CONFIG_ORDER:
            table = models.CONFIG_TABLES[obj_type]
            for item in data.get("objects", {}).get(obj_type, []):
                item = dict(item)
                content = item.pop("content", None)
                cols = ["id"] + [c for c in models.TABLE_COLUMNS[table] if c in item]
                placeholders = ",".join("?" for _ in cols)
                conn.execute(
                    f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders})",
                    [item.get(c) for c in cols],
                )
                if obj_type == "script" and content is not None:
                    write_script(item, content)
        for item in data.get("objects", {}).get("server_datasources", []):
            item = dict(item)
            cols = ["id"] + [c for c in models.TABLE_COLUMNS["server_datasources"] if c in item]
            placeholders = ",".join("?" for _ in cols)
            conn.execute(
                f"INSERT INTO server_datasources ({','.join(cols)}) VALUES ({placeholders})",
                [item.get(c) for c in cols],
            )
        for row in data.get("versions") or []:
            conn.execute(
                "INSERT INTO backup_versions (id, object_type, object_id, version, action, snapshot_json, operator_ip, note, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    row.get("id"),
                    row.get("object_type"),
                    row.get("object_id"),
                    row.get("version"),
                    row.get("action"),
                    row.get("snapshot_json"),
                    row.get("operator_ip"),
                    row.get("note"),
                    row.get("created_at"),
                ),
            )
        models.write_audit(conn, operator_ip, "import", "all", "", "migrate", {"mode": "migrate"})
    return True, "覆盖式导入完成"


def _import_daily(objects: dict[str, Any], operator_ip: str) -> tuple[bool, str]:
    id_maps: dict[str, dict[int, int]] = {t: {} for t in CONFIG_ORDER}

    def _map_ids(raw: Any, obj_type: str) -> str:
        try:
            ids = json.loads(raw) if isinstance(raw, str) else (raw or [])
        except (ValueError, TypeError):
            ids = []
        mapped = [id_maps.get(obj_type, {}).get(int(x), int(x)) for x in ids if str(x).strip() not in ("", "None")]
        return json.dumps(mapped)

    with models.db() as conn:
        for obj_type in CONFIG_ORDER:
            table = models.CONFIG_TABLES[obj_type]
            for item in objects.get(obj_type, []):
                item = dict(item)
                old_id = item.pop("id", None)
                content = item.pop("content", None)
                if obj_type == "server":
                    item["group_id"] = id_maps["group"].get(item.get("group_id"), item.get("group_id"))
                    item["scripts_json"] = _map_ids(item.get("scripts_json"), "script")
                elif obj_type == "schedule":
                    try:
                        targets = json.loads(item.get("targets_json") or "{}")
                    except (ValueError, TypeError):
                        targets = {}
                    targets["servers"] = [id_maps["server"].get(int(x), int(x)) for x in targets.get("servers", [])]
                    targets["groups"] = [id_maps["group"].get(int(x), int(x)) for x in targets.get("groups", [])]
                    targets["datasources"] = [id_maps["datasource"].get(int(x), int(x)) for x in targets.get("datasources", [])]
                    item["targets_json"] = json.dumps(targets)
                    item["scripts_json"] = _map_ids(item.get("scripts_json"), "script")
                cols = [c for c in models.TABLE_COLUMNS[table] if c in item]
                placeholders = ",".join("?" for _ in cols)
                cur = conn.execute(
                    f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders})",
                    [item.get(c) for c in cols],
                )
                if old_id is not None:
                    id_maps[obj_type][int(old_id)] = int(cur.lastrowid)
                if obj_type == "script":
                    new_script = {"id": int(cur.lastrowid), "kind": item.get("kind", "shell")}
                    write_script(new_script, content or "")

        # 服务器×数据源绑定（新增式：重映射 server_id / datasource_id / scripts_json）
        for item in objects.get("server_datasources", []):
            item = dict(item)
            item.pop("id", None)
            item["server_id"] = id_maps["server"].get(item.get("server_id"), item.get("server_id"))
            item["datasource_id"] = id_maps["datasource"].get(item.get("datasource_id"), item.get("datasource_id"))
            item["scripts_json"] = _map_ids(item.get("scripts_json"), "script")
            cols = [c for c in models.TABLE_COLUMNS["server_datasources"] if c in item]
            placeholders = ",".join("?" for _ in cols)
            conn.execute(
                f"INSERT INTO server_datasources ({','.join(cols)}) VALUES ({placeholders})",
                [item.get(c) for c in cols],
            )
        models.write_audit(conn, operator_ip, "import", "all", "", "daily", {"mode": "daily"})
    return True, "新增式导入完成"


def cleanup(retention_days: int) -> int:
    return models.cleanup_backups(retention_days)
