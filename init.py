#!/usr/bin/env python3
"""首次初始化：建库/生成 vault.key/示例脚本与 PromQL 模板/默认 settings。

- 幂等：已初始化则跳过不覆盖、补缺失项
- `--force` 重置（危险操作，需确认）
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

import backup
import models
import sanitize
import vault
from config import get_config, set_config, load_config

# Built-in seeds live as plain files under seeds/ (content) plus seeds/manifest.json
# (metadata + zh-CN/en name & desc). init.py only loads and applies them.
SEEDS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seeds")


def _load_seeds() -> list[dict]:
    """Load seeds/manifest.json and attach each file's content. 读取种子清单并附加正文。"""
    path = os.path.join(SEEDS_DIR, "manifest.json")
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    out: list[dict] = []
    for item in manifest:
        try:
            with open(os.path.join(SEEDS_DIR, item["file"]), "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            continue
        item = dict(item)
        item["content"] = content
        out.append(item)
    return out


SEEDS = _load_seeds()


def _hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _seed_scripts(force: bool = False) -> dict:
    """Apply built-in seeds idempotently. 幂等应用内置种子。

    - new script            -> create
    - unmodified built-in   -> update to latest seed (or force)
    - modified built-in     -> keep user content, record conflict
    返回 {"created","updated","kept","conflicts"}。
    """
    rows = models.fetch_all("scripts")
    by_seed = {r.get("seed_key"): r for r in rows if r.get("seed_key")}
    # Match legacy rows by (name, kind): shell/promql seeds may share a display name.
    by_name = {(r["name"], r.get("kind") or "shell"): r for r in rows}
    claimed: set[int] = set()
    created = updated = kept = 0
    conflicts: list[dict] = []
    for item in SEEDS:
        key = item["key"]
        kind = item["kind"]
        filename = item["file"].split("/", 1)[1]
        content = item["content"]
        chash = _hash(content)
        name = item["name"]["zh-CN"]
        desc = item["desc"]["zh-CN"]
        i18n = json.dumps(
            {
                "zh-CN": {"name": name, "desc": desc},
                "en": {"name": item["name"]["en"], "desc": item["desc"]["en"]},
            },
            ensure_ascii=False,
        )
        row = by_seed.get(key)
        if row is None:
            cand = by_name.get((name, kind))
            if cand is not None and int(cand["id"]) not in claimed:
                row = cand
        if row is not None:
            claimed.add(int(row["id"]))
        if row is None:
            with models.db() as conn:
                sid = models.insert(
                    conn,
                    "scripts",
                    {
                        "name": name,
                        "filename": filename,
                        "kind": kind,
                        "desc": desc,
                        "seed_key": key,
                        "seed_hash": chash,
                        "i18n_json": i18n,
                        "created_at": models.utcnow(),
                        "updated_at": models.utcnow(),
                    },
                )
                backup.record(conn, "script", sid, "create", {"id": sid, "name": name, "kind": kind, "content": content})
            backup.write_script({"id": sid, "kind": kind}, content)
            by_seed[key] = {"id": sid, "kind": kind, "name": name}
            claimed.add(int(sid))
            created += 1
            continue

        sid = row["id"]
        cur = backup.read_script(row)
        cur_h = _hash(cur)
        was_seed = bool(row.get("seed_key"))
        modified = (not force) and (cur_h != (row.get("seed_hash") if was_seed else chash))
        if modified:
            # Keep user content; still link the seed + translations so it shows multi-language.
            with models.db() as conn:
                models.update(
                    conn,
                    "scripts",
                    sid,
                    {"seed_key": key, "seed_hash": chash, "i18n_json": i18n, "updated_at": models.utcnow()},
                )
            kept += 1
            conflicts.append({"id": sid, "name": row.get("name") or name, "seed_name": name, "seed_key": key})
            continue

        with models.db() as conn:
            models.update(
                conn,
                "scripts",
                sid,
                {
                    "name": name,
                    "filename": filename,
                    "kind": kind,
                    "desc": desc,
                    "seed_key": key,
                    "seed_hash": chash,
                    "i18n_json": i18n,
                    "updated_at": models.utcnow(),
                },
            )
            backup.record(conn, "script", sid, "update", {"id": sid, "name": name, "kind": kind, "content": content})
        backup.write_script({"id": sid, "kind": kind}, content)
        updated += 1
    return {"created": created, "updated": updated, "kept": kept, "conflicts": conflicts}


def _seed_settings(force: bool = False) -> int:
    changed = 0
    with models.db() as conn:
        current = models.get_settings(conn)
        for key, value in models.DEFAULT_SETTINGS.items():
            if key == "sanitize_rules" and not value:
                value = json.dumps(sanitize.default_rules(), ensure_ascii=False)
            if key not in current or force:
                if current.get(key) != value:
                    models.set_setting(conn, key, value)
                    changed += 1
    return changed


def reset() -> None:
    """危险操作：清空所有数据表并删除脚本文件。"""
    conn = models.connect()
    try:
        for table in (
            "server_datasources",
            "servers",
            "groups",
            "scripts",
            "datasources",
            "models",
            "notifications",
            "run_schedule",
            "run_history",
            "audit_log",
            "backup_versions",
            "vault_entries",
            "settings",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
    finally:
        conn.close()
    cfg = get_config()
    if os.path.isdir(cfg.scripts_dir):
        for name in os.listdir(cfg.scripts_dir):
            if name.endswith((".sh", ".promql")):
                try:
                    os.remove(os.path.join(cfg.scripts_dir, name))
                except OSError:
                    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PyPiMeOps 初始化")
    parser.add_argument("--config", default=None, help="config.yaml 路径（默认 ./config.yaml）")
    parser.add_argument("--force", action="store_true", help="重置并重建（危险）")
    parser.add_argument("-y", "--yes", action="store_true", help="跳过确认")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    set_config(cfg)
    models.set_db_path(cfg.db_path)
    cfg.ensure_dirs()
    models.init_db()
    vault.ensure_key()

    if args.force:
        if not args.yes:
            answer = input("--force 将清空所有数据与脚本文件，确认？[y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                print("已取消")
                return 1
        reset()

    seeded = _seed_scripts(force=args.force)
    changed = _seed_settings(force=args.force)
    print(f"[OK] 数据库：{cfg.db_path}")
    print(f"[OK] vault.key：{cfg.vault_key_path}")
    print(f"[OK] 内置脚本：新增 {seeded['created']}，更新 {seeded['updated']}，保留已修改 {seeded['kept']}；settings 变更：{changed} 项")
    if seeded["conflicts"]:
        print("[!] 以下内置脚本你已修改，升级未覆盖（可在「脚本」页恢复默认或另存为新脚本）：")
        for c in seeded["conflicts"]:
            print(f"    - #{c['id']} {c['name']}")
    print("提示：如需巡检，请依次在 Web 页面录入 凭据/服务器/数据源/模型/通知 并绑定脚本。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
