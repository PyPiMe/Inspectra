"""PyPiMeOps Web 入口：路由 + IP 白名单中间件 + CSRF + 调度线程启动。"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import logging
import logging.handlers
import os
import sqlite3
import threading
from datetime import datetime, timezone
from functools import wraps
from typing import Any

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import Markup, escape
from markdown_it import MarkdownIt

import backup
import applog
import chatbot
import collectors
import engine
import i18n
import model_client
import models
import notify
import sanitize
import vault
from config import get_config, load_config, set_config
import scheduler as scheduler_mod
from scheduler import Scheduler

log = logging.getLogger("pypimeops.app")
scheduler = Scheduler()

# 报告 Markdown 渲染：禁用原始 HTML（转义），仅启用表格扩展，防存储型 XSS
_md = MarkdownIt("commonmark", {"html": False}).enable("table")


def render_markdown(text: str) -> Markup:
    return Markup(_md.render(text or ""))


# ------------------------------------------------------------ 工具

def client_ip() -> str:
    return request.remote_addr or ""


def now_local_str(iso_ts: str | None) -> str:
    return models.local_str(iso_ts)


def parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return default


def parse_ids(values: list[str]) -> list[int]:
    out = []
    for v in values:
        try:
            out.append(int(v))
        except (ValueError, TypeError):
            continue
    return out


def json_or(value: Any, default: Any) -> Any:
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return default


def server_conn_type(server: dict[str, Any], has_prom: bool) -> str:
    """派生"连接方式"：SSH / Prometheus / SSH + Prometheus / 未配置（不落库，按绑定推导）。"""
    ssh = bool(server.get("port")) or bool((server.get("user") or "").strip()) or bool(server.get("vault_key")) or bool(
        json_or(server.get("scripts_json"), []) or []
    )
    parts = []
    if ssh:
        parts.append("SSH")
    if has_prom:
        parts.append("Prometheus")
    return " + ".join(parts) if parts else "未配置"


def _obj_display_name(obj_type: str, obj: dict[str, Any] | None) -> str:
    """配置对象的可读名称（用于详情/历史/备份页标题）。"""
    if not obj:
        return ""
    return str(obj.get("name") or obj.get("label") or obj.get("hostname") or obj.get("key") or "")


PER_PAGE_CHOICES = (20, 50, 100)


def local_input_to_utc(text: str | None) -> str | None:
    """把 datetime-local（本地时间）转为 UTC ISO8601，用于与库中 UTC 时间比较。"""
    t = (text or "").strip().replace("T", " ")
    if not t:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            dt = datetime.strptime(t, fmt)
            return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()
        except ValueError:
            continue
    return None


def _audit_filters(args) -> tuple[list[str], list[Any]]:
    where, params = [], []
    ip = args.get("ip")
    action = args.get("action")
    ttype = args.get("target_type")
    q = args.get("q")
    if ip:
        where.append("ip LIKE ?")
        params.append(f"%{ip}%")
    if action:
        where.append("action=?")
        params.append(action)
    if ttype:
        where.append("target_type=?")
        params.append(ttype)
    if q:
        where.append("(target_name LIKE ? OR detail LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%"])
    status = args.get("status")
    if status:
        where.append("status=?")
        params.append(status)
    if local_input_to_utc(args.get("start")):
        where.append("ts>=?")
        params.append(local_input_to_utc(args.get("start")))
    if local_input_to_utc(args.get("end")):
        where.append("ts<=?")
        params.append(local_input_to_utc(args.get("end")))
    return where, params


_AUDIT_ACTIONS = ["create", "update", "delete", "run", "restore", "rekey", "import", "export", "cleanup", "notify_failed", "model_extra_id"]
_AUDIT_NEED_SQL = "(action IN ('delete','restore','rekey','import') OR status<>'ok' OR status IS NULL)"
_AUDIT_ACTION_CN = {
    "create": "新增", "update": "修改", "delete": "删除", "run": "执行", "restore": "恢复",
    "rekey": "更换密钥", "import": "导入", "export": "导出", "cleanup": "清理",
    "notify_failed": "告警失败", "model_extra_id": "模型异常ID", "schedule_skip": "调度跳过",
}
_AUDIT_ACTION_COLOR = {
    "create": "success", "update": "primary", "delete": "danger", "restore": "warning",
    "rekey": "warning", "import": "info", "export": "secondary", "run": "dark",
    "cleanup": "secondary", "notify_failed": "danger", "model_extra_id": "secondary",
    "schedule_skip": "warning",
}
_AUDIT_TTYPE_CN = {
    "group": "分组", "server": "服务器", "script": "脚本", "datasource": "数据源", "model": "模型",
    "notification": "通知", "schedule": "定时任务", "setting": "设置", "credential": "凭据",
    "run": "运行", "report": "报告", "backup": "备份", "applog": "应用日志",
    "server_datasource": "数据源绑定", "all": "全部",
}


def _duration(started: str | None, finished: str | None) -> str:
    if not started or not finished:
        return ""
    try:
        s = datetime.fromisoformat(started)
        f = datetime.fromisoformat(finished)
        sec = max(0, int((f - s).total_seconds()))
        return f"{sec // 60}m{sec % 60}s" if sec >= 60 else f"{sec}s"
    except (ValueError, TypeError):
        return ""


def page_args() -> tuple[int, int]:
    """从 query string 取分页参数：page、per_page（限 20/50/100，默认 20）。"""
    page = max(1, parse_int(request.args.get("page"), 1))
    per_page = parse_int(request.args.get("per_page"), 20)
    if per_page not in PER_PAGE_CHOICES:
        per_page = 20
    return page, per_page


def paginate(rows_sql: str, count_sql: str, params: list[Any], page: int, per_page: int):
    """通用分页：返回 (rows, total, page, pages)。rows_sql 不含 LIMIT/OFFSET。"""
    total = int(models.query(count_sql, params)[0]["c"])
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(max(1, page), pages)
    rows = models.query(rows_sql + " LIMIT ? OFFSET ?", list(params) + [per_page, (page - 1) * per_page])
    return rows, total, page, pages


def _localize_script(row: dict[str, Any]) -> dict[str, Any]:
    """Attach localized display fields (lname/ldesc/lmeta) and dirty flag to a script row."""
    name, desc, meta = i18n.localize_script(row)
    row["lname"] = name
    row["ldesc"] = desc
    row["lmeta"] = meta
    if row.get("seed_key"):
        content = backup.read_script(row)
        row["dirty"] = bool(content) and content_hash(content) != (row.get("seed_hash") or "")
    else:
        row["dirty"] = False
    return row


def _localize_scripts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_localize_script(r) for r in rows]


def _picker_scripts(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Localized script rows for the checkbox pickers (overwrite name/desc for display)."""
    out: list[dict[str, Any]] = []
    for r in rows:
        r["name"], r["desc"], _ = i18n.localize_script(r)
        r["tags"] = _row_tags(r)
        out.append(r)
    return out


def _i18n_form_values(cur_row: dict[str, Any] | None, lang: str, base: dict[str, str], field_map: dict[str, str]) -> dict:
    """Build i18n_json from base fields + translation-panel inputs (`tr_<lang>_<field>`).

    基座字段写入当前语言；翻译面板 `tr_<lang>_<field>` 写入其它语言。field_map: 表单后缀 -> 存储键。
    """
    ij: dict[str, dict] = {k: dict(v) for k, v in i18n.parse_i18n(cur_row or {}).items()}
    entry = ij.setdefault(lang, {})
    for suffix, stored in field_map.items():
        if suffix in base and base[suffix] is not None:
            entry[stored] = base[suffix]
    for key, raw in request.form.items():
        if not key.startswith("tr_"):
            continue
        prefix, _, last = key.rpartition("_")
        if last not in field_map:
            continue
        other = prefix[3:]
        if not other or other == lang:
            continue
        stored = field_map[last]
        val = (raw or "").strip()
        sub = ij.setdefault(other, {})
        if val:
            sub[stored] = val
        else:
            sub.pop(stored, None)
        if not sub:
            ij.pop(other, None)
    if not any(ij.get(lang, {}).values()):
        ij.pop(lang, None)
    return ij


def _localize_named_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach localized lname/ldesc for applications/groups. 应用/分组本地化展示名。"""
    for r in rows:
        r["lname"], r["ldesc"] = i18n.localize_named(r)
    return rows


def _picker_named(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Localized name/desc in place, for checkbox/select pickers. 选择器用本地化名称。"""
    for r in rows:
        r["name"], r["desc"] = i18n.localize_named(r)
    return rows


def _script_row_map(ids) -> dict[int, dict[str, Any]]:
    ids = sorted({int(x) for x in ids if x})
    if not ids:
        return {}
    q = ",".join("?" for _ in ids)
    return {int(r["id"]): r for r in models.query(f"SELECT * FROM scripts WHERE id IN ({q})", ids)}


def _application_name_map(ids) -> dict[int, str]:
    """Map application ids to localized names. 应用 id → 本地化名。"""
    ids = sorted({int(x) for x in ids if x})
    if not ids:
        return {}
    q = ",".join("?" for _ in ids)
    rows = models.query(f"SELECT * FROM applications WHERE id IN ({q})", ids)
    return {int(r["id"]): i18n.localize_named(r)[0] for r in rows}


def _app_label(app_ids, name_map: dict[int, str]) -> str:
    names = [name_map.get(int(i), f"#{i}") for i in (app_ids or [])]
    return "、".join(names) if names else i18n.t("reports2.unassigned")


def _localize_detail(detail: dict[str, Any] | None):
    """Rewrite report-detail app/script names by the viewer language. 报告详情应用/脚本名按查看语言解析。"""
    if not detail or not detail.get("apps"):
        return detail
    sids = [r.get("script_id") for a in detail["apps"] for s in a.get("servers", []) for r in s.get("results", [])]
    aids = [a.get("application_id") for a in detail["apps"] if a.get("application_id")]
    rows = _script_row_map(sids)
    amap = _application_name_map(aids)
    for a in detail["apps"]:
        aid = a.get("application_id")
        a["name"] = amap.get(int(aid), a.get("name")) if aid else i18n.t("reports2.unassigned")
        for s in a.get("servers", []):
            for r in s.get("results", []):
                sid = r.get("script_id")
                row = rows.get(int(sid)) if sid else None
                if row:
                    r["script"] = i18n.localize_script(row)[0]
                    for it in r.get("items") or []:
                        k = it.get("key")
                        if k:
                            it["name"] = i18n.localize_item(row, k)
    return detail


def _localize_summary(summary: dict[str, Any] | None) -> dict[str, Any]:
    """Localize summary app/script names by the viewer language. 摘要应用/脚本名按查看语言解析。"""
    if not summary:
        return summary or {}
    issues = summary.get("issues") or []
    rows = _script_row_map([it.get("script_id") for it in issues])
    aid_set = {i for it in issues for i in (it.get("app_ids") or [])}
    aid_set |= {a.get("id") for a in (summary.get("apps") or []) if a.get("id")}
    amap = _application_name_map(aid_set)
    for it in issues:
        sid = it.get("script_id")
        row = rows.get(int(sid)) if sid else None
        if row:
            it["script"] = i18n.localize_script(row)[0]
            if it.get("item_key"):
                it["item"] = i18n.localize_item(row, it["item_key"])
        if it.get("app_ids"):
            it["app"] = _app_label(it["app_ids"], amap)
        elif it.get("app") in ("未归属", "__unassigned__"):
            it["app"] = i18n.t("reports2.unassigned")
    for a in summary.get("apps") or []:
        aid = a.get("id")
        if aid:
            a["name"] = amap.get(int(aid), a.get("name"))
        elif a.get("name") in ("未归属", "__unassigned__"):
            a["name"] = i18n.t("reports2.unassigned")
    summary["issues"] = issues
    return summary


def _safe_back(default_url: str) -> str:
    """Return the same-site `back` target (from form/query) or the default. 返回站内 back 或默认。"""
    b = (request.form.get("back") or request.args.get("back") or "").strip()
    return b if b.startswith("/") else default_url


def _parse_tags(raw: Any) -> list[str]:
    """Parse a comma-separated tag input into a unique list. 解析逗号分隔的标签。"""
    if not raw:
        return []
    out: list[str] = []
    for part in str(raw).replace("，", ",").split(","):
        t = part.strip()
        if t and t not in out:
            out.append(t)
    return out


def _parse_bindings(raw: Any) -> list[dict[str, Any]]:
    """Normalize a posted bindings JSON array for a new server. 解析新建页提交的绑定 JSON。"""
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    out: list[dict[str, Any]] = []
    for b in data:
        if not isinstance(b, dict):
            continue
        did = parse_int(b.get("datasource_id"))
        if not did:
            continue
        labels = b.get("labels_json") or "{}"
        if isinstance(labels, dict):
            labels = json.dumps(labels, ensure_ascii=False)
        try:
            json.loads(labels)
        except ValueError as exc:
            raise ValueError("labels_json") from exc
        scripts = b.get("scripts_json") or []
        if not isinstance(scripts, list):
            scripts = []
        scripts = [int(x) for x in scripts if str(x).strip().isdigit()]
        out.append({
            "datasource_id": did,
            "prom_instance": str(b.get("prom_instance") or "").strip(),
            "labels_json": labels,
            "scripts_json": json.dumps(scripts),
            "enabled": 1 if b.get("enabled", 1) else 0,
        })
    return out


def _row_tags(row: dict[str, Any]) -> list[str]:
    try:
        v = json.loads(row.get("tags_json") or "[]")
        return [str(x) for x in v] if isinstance(v, list) else []
    except (ValueError, TypeError):
        return []


def content_hash(text: str) -> str:
    import hashlib
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _seed_item(seed_key: str) -> dict[str, Any] | None:
    """Look up a built-in seed by key from init.SEEDS (imported lazily to avoid cycles)."""
    import init
    for item in init.SEEDS:
        if item["key"] == seed_key:
            return item
    return None


def _t_or(key: str, fallback: str) -> str:
    """i18n.t with a fallback when the key is missing. 带回退的翻译。"""
    val = i18n.t(key)
    return val if val != key else fallback


_BAD_SRV = ("WARN", "FAIL", "ERROR")


def _run_targets(run: dict[str, Any], apps: dict, groups: dict, servers_map: dict) -> list:
    tj = json_or(run.get("targets_json"), {})
    if tj.get("applications"):
        return [("app", int(i), apps.get(int(i), f"#{i}")) for i in tj["applications"]]
    if tj.get("groups"):
        return [("group", int(i), groups.get(int(i), f"#{i}")) for i in tj["groups"]]
    if tj.get("servers"):
        return [("server", int(i), servers_map.get(int(i), f"#{i}")) for i in tj["servers"]]
    if tj.get("all"):
        return [("all", 0, "__ALL__")]
    return [("unassigned", 0, "__UNASSIGNED__")]


def _target_attention(run: dict[str, Any], detail: dict | None, typ: str, tid: int, group_servers: dict) -> bool:
    """Whether a target still needs attention in a run, by its own servers.

    目标维度判定：**仅依据结构化证据（detail 的服务器状态/问题项）**；无 detail（生成失败/中断/提前中止）
    不算“需关注”（这类只在运行卡片上以次要徽标提示）。消除混合运行牵连。
    """
    if not detail or not detail.get("apps"):
        return False
    apps = detail.get("apps") or []
    issues = (run.get("summary_obj") or {}).get("issues") or []

    def has_issue(sids: set[int]) -> bool:
        for it in issues:
            sid = it.get("server_id")
            if sid and int(sid) in sids and (it.get("status") or "").upper() in ("WARN", "FAIL", "ERROR", "UNKNOWN"):
                return True
        return False

    if typ == "all":
        sids = {int(s.get("server_id") or 0) for a in apps for s in (a.get("servers") or [])}
        if any((s.get("status") or "").upper() in _BAD_SRV for a in apps for s in (a.get("servers") or [])):
            return True
        return has_issue(sids)
    if typ in ("app", "unassigned"):
        want = tid if typ == "app" else 0
        for a in apps:
            if int(a.get("application_id") or 0) == want:
                srvs = a.get("servers") or []
                if any((s.get("status") or "").upper() in _BAD_SRV for s in srvs):
                    return True
                return has_issue({int(s.get("server_id") or 0) for s in srvs})
        return False
    if typ == "group":
        sids = set(group_servers.get(tid, []))
        for a in apps:
            for s in a.get("servers") or []:
                if int(s.get("server_id") or 0) in sids and (s.get("status") or "").upper() in _BAD_SRV:
                    return True
        return has_issue(sids)
    if typ == "server":
        for a in apps:
            for s in a.get("servers") or []:
                if int(s.get("server_id") or 0) == tid:
                    return (s.get("status") or "").upper() in _BAD_SRV or has_issue({tid})
        return has_issue({tid})
    return False


def _group_runs_by_target(rows: list[dict], apps: dict, groups: dict, servers_map: dict,
                          group_servers: dict, detail_of) -> tuple[list[dict], list[dict]]:
    """Split decorated runs into (needs-attention, recovered) target groups.

    按目标汇总运行，并按“目标最新一次运行”判定 需关注 / 已恢复。
    """
    per: dict[tuple, dict] = {}
    for r in rows:
        for typ, tid, name in _run_targets(r, apps, groups, servers_map):
            per.setdefault((typ, tid), {"type": typ, "name": name, "runs": []})["runs"].append(r)
    need: list[dict] = []
    recovered: list[dict] = []
    for (typ, tid), info in per.items():
        runs = sorted(info["runs"], key=lambda x: (x.get("id") or 0), reverse=True)
        # 仅用“有结构化 detail”的运行判定需关注/已恢复；生成失败/中断等无证据运行被跳过（仍显示在运行列表）。
        evidence = [(r, detail_of(r["id"])) for r in runs]
        evidence = [(r, d) for (r, d) in evidence if d and d.get("apps")]
        if not evidence:
            continue
        head = evidence[0][0]
        latest_bad = _target_attention(evidence[0][0], evidence[0][1], typ, tid, group_servers)
        hist_bad = any(_target_attention(r, d, typ, tid, group_servers) for r, d in evidence[1:])
        entry = {"name": info["name"], "type": typ, "runs": runs, "latest": runs[0], "head": head,
                 "recovered": (not latest_bad) and hist_bad}
        if latest_bad:
            need.append(entry)
        elif hist_bad:
            recovered.append(entry)
    need.sort(key=lambda g: -(g["latest"].get("id") or 0))
    recovered.sort(key=lambda g: -(g["latest"].get("id") or 0))
    return need, recovered


def _report_target_maps() -> tuple[dict, dict, dict, dict]:
    """Localized app/group/server maps + group->server ids for report targeting."""
    apps = {int(a["id"]): a["name"] for a in _picker_named(models.fetch_all("applications"))}
    groups = {int(g["id"]): g["name"] for g in _picker_named(models.fetch_all("groups"))}
    srv_rows = models.fetch_all("servers")
    servers_map = {int(s["id"]): (s.get("hostname") or s.get("ip") or f"#{s['id']}") for s in srv_rows}
    group_servers: dict[int, list[int]] = {}
    for s in srv_rows:
        if s.get("group_id"):
            group_servers.setdefault(int(s["group_id"]), []).append(int(s["id"]))
    return apps, groups, servers_map, group_servers


def _detail_loader():
    """Cached detail_json loader per run id. 报告结构化数据按 run 缓存加载。"""
    cache: dict[int, Any] = {}

    def load(rid: int):
        if rid not in cache:
            drow = models.query("SELECT detail_json FROM run_results WHERE run_id=?", (rid,))
            try:
                cache[rid] = json.loads(drow[0]["detail_json"] or "{}") if drow else None
            except (ValueError, TypeError):
                cache[rid] = None
        return cache[rid]

    return load


def _need_target_count() -> int:
    """Global count of targets whose latest run still needs attention. 需关注目标数（全局）。"""
    rows = []
    for r in models.fetch_all("run_history", order="id DESC"):
        d = dict(r)
        d["summary_obj"] = _localize_summary(json_or(d.get("summary"), {}))
        rows.append(d)
    apps, groups, servers_map, grp = _report_target_maps()
    need, _ = _group_runs_by_target(rows, apps, groups, servers_map, grp, _detail_loader())
    return len(need)


_EXTRA_TEMPLATE_KEYS = [
    "model.extra_none", "model.extra_deepseek_no_thinking",
    "model.extra_effort_low", "model.extra_effort_high", "model.extra_openai_json",
]


def _localized_presets() -> tuple[dict[str, dict[str, str]], list[dict[str, str]]]:
    """Model presets/templates with localized labels for the current language. 模型预设本地化标签。"""
    presets = {
        k: {**v, "label": _t_or("model.provider_" + k, v.get("label") or k)}
        for k, v in model_client.PROVIDER_PRESETS.items()
    }
    templates = []
    for i, tp in enumerate(model_client.EXTRA_JSON_TEMPLATES):
        key = _EXTRA_TEMPLATE_KEYS[i] if i < len(_EXTRA_TEMPLATE_KEYS) else ""
        templates.append({**tp, "label": _t_or(key, tp.get("label") or "") if key else tp.get("label")})
    return presets, templates


def _status_label(st: Any) -> str:
    st = (st or "").upper()
    if not st:
        return ""
    key = "status." + st.lower()
    val = i18n.t(key)
    return st if val == key else val


def _render_report_md(run: dict[str, Any], summary: dict[str, Any], detail: dict[str, Any] | None) -> str:
    """Render report markdown from structured data in the current language.

    按当前语言由结构化数据（summary/detail）生成报告 Markdown。
    """
    t = i18n.t
    site = models.get_setting("site_title", "PyPiMeOps") or "PyPiMeOps"
    lines: list[str] = [t("report_md.title", site=site, id=run.get("id")), ""]
    trig_key = "report_md.trigger_" + (run.get("trigger") or "")
    trig = t(trig_key)
    lines.append(t("report_md.trigger", trigger=(run.get("trigger") if trig == trig_key else trig)))
    mode = summary.get("mode") or run.get("mode") or ""
    lines.append(t("report_md.mode", mode=t("notify.mode_raw" if mode == "raw" else "notify.mode_model")))
    lines.append(t("report_md.started", t=models.local_str(run.get("started"))))
    lines.append(t("report_md.finished", t=models.local_str(run.get("finished"))))
    dur = _duration(run.get("started"), run.get("finished"))
    if dur:
        lines.append(t("report_md.duration", t=dur))
    if mode != "raw" and run.get("policy"):
        lines.append(t("report_md.policy", policy=run.get("policy")))
    targets = summary.get("targets_label") or ""
    if targets:
        lines.append(t("report_md.targets", targets=targets))
    if summary.get("selected_count") is not None:
        line = t("report_md.servers", selected=summary.get("selected_count", 0), executed=summary.get("executed_count", 0))
        if summary.get("skipped_count"):
            line += t("report_md.skipped", skipped=summary.get("skipped_count"))
        lines.append(line)

    apps = (detail or {}).get("apps") or []

    def _bad(servers: list[dict[str, Any]]) -> int:
        return sum(
            1 for s in servers for r in (s.get("results") or [])
            if (r.get("status") or "").upper() in ("FAIL", "ERROR", "WARN", "UNKNOWN")
        )

    lines += ["", t("report_md.summary_header"), "",
              f"| {t('report_md.th_app')} | {t('report_md.th_status')} | {t('report_md.th_servers')} | {t('report_md.th_issues')} |",
              "|------|------|--------|------|"]
    for a in apps:
        lines.append(f"| {a.get('name')} | {_status_label(a.get('status'))} | {len(a.get('servers') or [])} | {_bad(a.get('servers') or [])} |")
    lines += ["", t("report_md.detail_header")]
    for a in apps:
        lines += ["", t("report_md.app", name=a.get("name"), status=_status_label(a.get("status"))), ""]
        lines += [f"| {t('report_md.th_servers')} | {t('report_md.th_status')} | {t('report_md.th_issues')} |",
                  "|--------|------|------|"]
        for s in a.get("servers") or []:
            n = _bad([s]) if s.get("results") else (1 if s.get("skipped") else 0)
            lines.append(f"| {s.get('name')} | {_status_label(s.get('status'))} | {n} |")
        for s in a.get("servers") or []:
            lines += ["", t("report_md.server", name=s.get("name"), status=_status_label(s.get("status")))]
            if s.get("conclusion"):
                lines.append(t("report_md.conclusion", v=s["conclusion"]))
            if s.get("consequence"):
                lines.append(t("report_md.consequence", v=s["consequence"]))
            if s.get("suggestion"):
                lines.append(t("report_md.suggestion", v=s["suggestion"]))
            if s.get("attention"):
                lines.append(t("report_md.attention", v=s["attention"]))
            results = s.get("results") or []
            if not results:
                lines.append(t("report_md.skipped_note") if s.get("skipped") else t("report_md.no_result"))
                continue
            good: list[str] = []
            for r in results:
                st = (r.get("status") or "").upper()
                items = r.get("items") or []
                if st in ("FAIL", "ERROR", "WARN", "UNKNOWN") or (r.get("meta") or {}).get("DISPLAY"):
                    lines += ["", t("report_md.script", name=r.get("script") or ""), "",
                              t("report_md.script_status", status=_status_label(st), source=r.get("source") or "")]
                    if items:
                        lines += ["", f"| {t('report_md.th_item')} | {t('report_md.th_value')} | {t('report_md.th_threshold')} | {t('report_md.th_verdict')} |",
                                  "|------|------|------|------|"]
                        for it in items:
                            verdict = _status_label((it.get("status") or "").upper())
                            if it.get("excess"):
                                verdict += f" ({it['excess']})"
                            val = (str(it.get("value", "")) + (" " + it["unit"] if it.get("unit") else "")).strip()
                            lines.append(f"| {it.get('name')} | {val} | {it.get('threshold') or ''} | {verdict} |")
                    elif r.get("raw"):
                        lines += ["", "```text", (r.get("raw") or "").rstrip(), "```"]
                    elif r.get("error"):
                        lines.append(r.get("error"))
                else:
                    good.append(r.get("script") or "")
            if good:
                lines += ["", t("report_md.other_ok", n=len(good), names="、".join(good))]
    lines.append("")
    return "\n".join(lines)


_file_handler: logging.Handler | None = None
_console_handler: logging.Handler | None = None
_NOISY_LOGGERS = ("werkzeug", "paramiko", "cryptography", "urllib3", "requests")


def apply_log_level(level: str | None) -> None:
    """应用日志级别（pypimeops.* 与日志文件），保存设置后即时生效。"""
    lvl = getattr(logging, (level or "INFO").strip().upper(), logging.INFO)
    logging.getLogger().setLevel(lvl)
    for h in (_file_handler, _console_handler):
        if h is not None:
            h.setLevel(lvl)
    # 第三方噪声固定 WARNING（HTTP 访问日志、TLS 弃用提示等），不入日志
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def setup_logging() -> None:
    global _file_handler, _console_handler
    cfg = get_config()
    os.makedirs(cfg.logs_dir, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    root = logging.getLogger()
    if _file_handler is None:
        _file_handler = logging.handlers.RotatingFileHandler(
            os.path.join(cfg.logs_dir, "pypimeops.log"),
            maxBytes=5 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        _file_handler.setFormatter(fmt)
        root.addHandler(_file_handler)
    if _console_handler is None:
        _console_handler = logging.StreamHandler()
        _console_handler.setFormatter(fmt)
        root.addHandler(_console_handler)
    apply_log_level(models.get_setting("app_log_level", "INFO"))


# ------------------------------------------------------------ 版本化写入

def save_object(
    obj_type: str,
    obj_id: int | None,
    data: dict[str, Any],
    ip: str,
    name: str = "",
    detail: Any = None,
    script_content: str | None = None,
    note: str = "",
    after_write=None,
) -> int:
    table = models.CONFIG_TABLES[obj_type]
    with models.db() as conn:
        if obj_id:
            models.update(conn, table, obj_id, data)
            action = "update"
        else:
            data.setdefault("created_at", models.utcnow())
            obj_id = models.insert(conn, table, data)
            action = "create"
        if after_write is not None:
            after_write(conn, int(obj_id))
        snapshot = backup.snapshot_object(conn, obj_type, obj_id)
        if script_content is not None:
            snapshot = snapshot or {}
            snapshot["content"] = script_content
        vid = backup.record(conn, obj_type, obj_id, action, snapshot, ip, note)
        models.write_audit(conn, ip, action, obj_type, obj_id, name or str(obj_id), detail if detail is not None else data, version_id=vid)
    if obj_type == "script" and script_content is not None:
        backup.write_script({"id": obj_id, "kind": data.get("kind", "shell")}, script_content)
    return int(obj_id)


def delete_object(obj_type: str, obj_id: int, ip: str, name: str = "") -> None:
    table = models.CONFIG_TABLES[obj_type]
    snapshot = None
    with models.db() as conn:
        snapshot = backup.snapshot_object(conn, obj_type, obj_id)
        if obj_type == "application":
            conn.execute("DELETE FROM application_members WHERE application_id=?", (obj_id,))
        models.delete(conn, table, obj_id)
        vid = backup.record(conn, obj_type, obj_id, "delete", snapshot, ip)
        models.write_audit(conn, ip, "delete", obj_type, obj_id, name or str(obj_id), {"deleted": True}, version_id=vid)
    if obj_type == "script" and snapshot:
        backup.remove_script_file(snapshot)


def set_setting_versioned(key: str, value: str, ip: str) -> None:
    with models.db() as conn:
        current = backup.snapshot_object(conn, "setting", key)
        if current and current.get("value") == value:
            return
        models.set_setting(conn, key, value)
        snapshot = backup.snapshot_object(conn, "setting", key)
        vid = backup.record(conn, "setting", key, "update", snapshot, ip)
        models.write_audit(conn, ip, "update", "setting", key, key, {"old": (current or {}).get("value"), "new": value}, version_id=vid)


# ------------------------------------------------------------ 引用保护

def references_to(obj_type: str, obj_id: int) -> list[str]:
    refs: list[str] = []
    if obj_type == "group":
        n = models.query("SELECT id, hostname FROM servers WHERE group_id=?", (obj_id,))
        refs += [f"服务器 {r['hostname']}" for r in n]
        for a in models.query(
            "SELECT a.name AS name FROM applications a JOIN application_members m ON m.application_id=a.id"
            " WHERE m.member_type='group' AND m.member_id=?",
            (obj_id,),
        ):
            refs.append(f"应用 {a['name']}")
    elif obj_type == "datasource":
        n = models.query("SELECT id FROM server_datasources WHERE datasource_id=?", (obj_id,))
        if n:
            refs.append(f"服务器×数据源绑定 {len(n)} 处")
    elif obj_type == "model":
        if models.get_setting("default_model", "") == str(obj_id):
            refs.append("默认模型设置")
    elif obj_type == "script":
        for s in models.fetch_all("servers"):
            if obj_id in (json_or(s.get("scripts_json"), []) or []):
                refs.append(f"服务器 {s['hostname']}")
        for b in models.fetch_all("server_datasources"):
            if obj_id in (json_or(b.get("scripts_json"), []) or []):
                refs.append(f"数据源绑定 #{b['id']}")
    elif obj_type == "server":
        n = models.query("SELECT id FROM server_datasources WHERE server_id=?", (obj_id,))
        if n:
            refs.append(f"数据源绑定 {len(n)} 处")
        for a in models.query(
            "SELECT a.name AS name FROM applications a JOIN application_members m ON m.application_id=a.id"
            " WHERE m.member_type='server' AND m.member_id=?",
            (obj_id,),
        ):
            refs.append(f"应用 {a['name']}")
    elif obj_type == "credential":
        n = models.query("SELECT id, hostname FROM servers WHERE vault_key=?", (str(obj_id),))
        refs += [f"服务器 {r['hostname']}" for r in n]
    return refs


# ------------------------------------------------------------ 应用工厂

def create_app() -> Flask:
    cfg = get_config()
    models.set_db_path(cfg.db_path)
    models.init_db()
    vault.ensure_key()
    # 启动恢复：上次进程中断遗留的 running 运行标记为中断（避免永久“生成中”）。
    with models.db() as conn:
        cur = conn.execute(
            "UPDATE run_history SET status='error', finished=?, error=? WHERE status='running'",
            (models.utcnow(), "服务重启，运行中断"),
        )
        if cur.rowcount:
            logging.getLogger("pypimeops.app").warning("标记 %s 条中断运行（服务重启）", cur.rowcount)
    setup_logging()

    app = Flask(__name__, template_folder="web/templates", static_folder="web/static")
    app.secret_key = cfg.flask_secret
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

    _basedir = os.path.dirname(os.path.abspath(__file__))
    i18n.init(os.path.join(_basedir, "locales"), os.path.join(_basedir, "locales", "custom"))
    i18n.set_fallback(models.get_setting("default_language", "zh-CN") or "zh-CN")

    def _pick_lang() -> str:
        code = (request.cookies.get("lang") or "").strip()
        if code and i18n.has(code):
            return code
        code = (models.get_setting("default_language", "zh-CN") or "zh-CN").strip()
        if code and i18n.has(code):
            return code
        avail = {x["code"] for x in i18n.languages()}
        for part in (request.headers.get("Accept-Language") or "").split(","):
            cand = part.split(";")[0].strip()
            if not cand:
                continue
            if cand in avail:
                return cand
            short = cand.split("-")[0]
            for a in avail:
                if a.split("-")[0] == short:
                    return a
        return "zh-CN"

    # ---- IP 白名单 + CSRF
    def allowed(ip: str, allowed_ips: str) -> bool:
        if not allowed_ips.strip():
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for item in allowed_ips.replace(",", "\n").split():
            item = item.strip()
            if not item:
                continue
            try:
                if addr in ipaddress.ip_network(item, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def csrf_token() -> str:
        token = session.get("_csrf")
        if not token:
            token = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii")
            session["_csrf"] = token
        return token

    @app.before_request
    def _guard():
        g.ip = client_ip()
        i18n.set_current(_pick_lang())
        allowed_ips = models.get_setting("allowed_ips", "")
        if not allowed(g.ip, allowed_ips):
            return "403 Forbidden", 403
        g.csrf = csrf_token()
        if request.method == "POST":
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
            if not sent or sent != session.get("_csrf"):
                return "403 CSRF token 校验失败", 403
        return None

    @app.context_processor
    def _inject():
        settings = models.get_settings()
        _presets, _templates = _localized_presets()
        return {
            "csrf_token": g.get("csrf", ""),
            "client_ip": g.get("ip", ""),
            "now_local": now_local_str(models.utcnow()),
            "site_title": (settings.get("site_title") or "").strip() or "PyPiMeOps",
            "whitelist_empty": not (settings.get("allowed_ips") or "").strip(),
            "whitelist_ack": settings.get("whitelist_ack") == "true",
            "engine_running": engine.is_running(),
            "nav_active": request.endpoint or "",
            "PROVIDER_PRESETS": _presets,
            "EXTRA_JSON_TEMPLATES": _templates,
            "json_or": json_or,
            "now_local_str": now_local_str,
            "languages": i18n.languages(),
            "current_lang": i18n.current(),
            "js_i18n": i18n.js_dict(),
        }

    app.jinja_env.globals["t"] = i18n.t
    app.jinja_env.globals["tn"] = i18n.tn

    @app.template_filter("local")
    def _local(ts: str) -> str:
        return now_local_str(ts)

    @app.template_filter("markdown")
    def _markdown_filter(text: str) -> Markup:
        return render_markdown(text)

    @app.template_filter("fp_short")
    def _fp_short(fp: str) -> str:
        """指纹短显示：前 4 字节 … 后 4 字节。"""
        if not fp:
            return ""
        parts = fp.split(":")
        if len(parts) <= 8:
            return fp
        return ":".join(parts[:4]) + " … " + ":".join(parts[-4:])

    # ---- 语言切换
    @app.route("/lang/<code>")
    def set_language(code: str):
        from flask import make_response

        nxt = request.args.get("next") or request.referrer or url_for("index")
        if not str(nxt).startswith("/"):
            nxt = url_for("index")
        resp = make_response(redirect(nxt))
        if i18n.has(code):
            resp.set_cookie("lang", code, max_age=365 * 86400, samesite="Lax")
        return resp

    # ---- 首页：默认进入「智能巡检」
    @app.route("/")
    def index():
        return redirect(url_for("chatbot_page"))

    # ---- 仪表盘
    @app.route("/dashboard")
    def dashboard():
        runs = models.query("SELECT * FROM run_history ORDER BY id DESC LIMIT 10")
        servers = models.fetch_all("servers")
        latest = runs[0] if runs else None
        summary = _localize_summary(json_or((latest or {}).get("summary"), {}))
        applications = _localize_named_rows([a for a in models.fetch_all("applications") if a.get("enabled", 1)])
        apps_health = summary.get("apps") or []
        if not apps_health:
            amap = engine.application_servers()
            apps_health = [
                {"name": a["lname"] or a["name"], "status": "-", "server_count": len(amap.get(int(a["id"]), []))}
                for a in applications
            ]
        return render_template(
            "dashboard.html",
            runs=runs,
            servers=servers,
            latest=latest,
            summary=summary,
            apps_health=apps_health,
            group_count=len(models.fetch_all("groups")),
            application_count=len(applications),
            script_count=len(models.fetch_all("scripts")),
            datasource_count=len(models.fetch_all("datasources")),
            model_count=len(models.fetch_all("models")),
            notification_count=len(models.fetch_all("notifications")),
        )

    # ---- 分组
    @app.route("/groups")
    def groups():
        q = (request.args.get("q") or "").strip()
        page, per_page = page_args()
        where, params = [], []
        if q:
            where.append("(name LIKE ? OR desc LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows, total, page, pages = paginate(
            f"SELECT * FROM groups{clause} ORDER BY id DESC",
            f"SELECT COUNT(*) AS c FROM groups{clause}",
            params, page, per_page,
        )
        return render_template("groups.html", groups=rows, q=q, page=page, pages=pages, total=total, per_page=per_page)

    @app.route("/groups/save", methods=["POST"])
    def groups_save():
        gid = parse_int(request.form.get("id")) or None
        name = (request.form.get("name") or "").strip()
        if not name:
            flash(i18n.t("groups.err_name_required"), "danger")
            return redirect(url_for("groups"))
        data = {
            "name": name,
            "desc": (request.form.get("desc") or "").strip(),
            "prom_labels_json": (request.form.get("prom_labels_json") or "{}").strip() or "{}",
            "updated_at": models.utcnow(),
        }
        try:
            json.loads(data["prom_labels_json"])
        except ValueError:
            flash(i18n.t("groups.err_labels_json"), "danger")
            return redirect(url_for("groups"))
        save_object("group", gid, data, g.ip, name)
        flash(i18n.t("groups.saved"), "success")
        return redirect(url_for("groups"))

    @app.route("/groups/<int:gid>/delete", methods=["POST"])
    def groups_delete(gid: int):
        refs = references_to("group", gid)
        if refs:
            flash(i18n.t("common.err_referenced", refs="、".join(refs)), "danger")
            return redirect(url_for("groups"))
        delete_object("group", gid, g.ip)
        flash(i18n.t("groups.deleted"), "success")
        return redirect(url_for("groups"))

    @app.route("/groups/<int:gid>/history")
    def groups_history(gid: int):
        return _history_view("group", gid, "group_detail.html", "分组")

    # ---- 应用
    def _application_members(app_id: int) -> dict[str, list[int]]:
        out: dict[str, list[int]] = {"servers": [], "groups": []}
        for m in models.query(
            "SELECT member_type, member_id FROM application_members WHERE application_id=? ORDER BY id", (app_id,)
        ):
            if m["member_type"] == "server":
                out["servers"].append(int(m["member_id"]))
            elif m["member_type"] == "group":
                out["groups"].append(int(m["member_id"]))
        return out

    @app.route("/applications")
    def applications():
        q = (request.args.get("q") or "").strip()
        page, per_page = page_args()
        where, params = [], []
        if q:
            where.append("(name LIKE ? OR desc LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows, total, page, pages = paginate(
            f"SELECT * FROM applications{clause} ORDER BY id DESC",
            f"SELECT COUNT(*) AS c FROM applications{clause}",
            params, page, per_page,
        )
        members = {int(r["id"]): _application_members(int(r["id"])) for r in rows}
        return render_template(
            "applications.html", applications=rows, members=members, q=q,
            server_items=[{"id": s["id"], "name": s["hostname"]} for s in models.fetch_all("servers")],
            group_items=[{"id": g["id"], "name": g["name"]} for g in models.fetch_all("groups")],
            page=page, pages=pages, total=total, per_page=per_page,
        )

    @app.route("/applications/save", methods=["POST"])
    def applications_save():
        aid = parse_int(request.form.get("id")) or None
        name = (request.form.get("name") or "").strip()
        if not name:
            flash(i18n.t("applications.err_name_required"), "danger")
            return redirect(url_for("applications"))
        server_ids = parse_ids(request.form.getlist("member_servers"))
        group_ids = parse_ids(request.form.getlist("member_groups"))
        data = {
            "name": name,
            "desc": (request.form.get("desc") or "").strip(),
            "enabled": 1 if request.form.get("enabled") is not None else 0,
            "updated_at": models.utcnow(),
        }

        def _write_members(conn, obj_id: int) -> None:
            conn.execute("DELETE FROM application_members WHERE application_id=?", (obj_id,))
            for mt, mid in [("server", i) for i in server_ids] + [("group", i) for i in group_ids]:
                conn.execute(
                    "INSERT OR IGNORE INTO application_members (application_id, member_type, member_id) VALUES (?,?,?)",
                    (obj_id, mt, mid),
                )

        save_object(
            "application", aid, data, g.ip, name,
            detail={"name": name, "servers": server_ids, "groups": group_ids},
            after_write=_write_members,
        )
        flash(i18n.t("applications.saved"), "success")
        return redirect(url_for("applications"))

    @app.route("/applications/<int:aid>/delete", methods=["POST"])
    def applications_delete(aid: int):
        delete_object("application", aid, g.ip)
        flash(i18n.t("applications.deleted"), "success")
        return redirect(url_for("applications"))

    @app.route("/applications/<int:aid>/history")
    def applications_history(aid: int):
        return _history_view("application", aid, "group_detail.html", "应用")

    # ---- 服务器
    @app.route("/servers")
    def servers():
        q = (request.args.get("q") or "").strip()
        group_id = parse_int(request.args.get("group_id"), 0)
        enabled = request.args.get("enabled") or ""
        page, per_page = page_args()
        where, params = [], []
        if q:
            where.append("(hostname LIKE ? OR ip LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        if group_id:
            where.append("group_id=?")
            params.append(group_id)
        if enabled in ("0", "1"):
            where.append("enabled=?")
            params.append(int(enabled))
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows, total, page, pages = paginate(
            f"SELECT * FROM servers{clause} ORDER BY id DESC",
            f"SELECT COUNT(*) AS c FROM servers{clause}",
            params, page, per_page,
        )
        credentials = _credential_list()
        bound_ids = {int(r["server_id"]) for r in models.query("SELECT DISTINCT server_id FROM server_datasources")}
        conn_types = {s["id"]: server_conn_type(s, s["id"] in bound_ids) for s in rows}
        return render_template(
            "servers.html",
            servers=rows,
            groups={int(r["id"]): r for r in _picker_named(models.fetch_all("groups"))},
            all_groups=_picker_named(models.fetch_all("groups")),
            credentials=credentials,
            cred_names={c["key"]: c["name"] for c in credentials},
            scripts=_picker_scripts(models.fetch_all("scripts", "kind='shell'")),
            datasources=models.fetch_all("datasources"),
            prom_scripts=_picker_scripts(models.fetch_all("scripts", "kind='promql'")),
            conn_types=conn_types,
            q=q, group_id=group_id, enabled=enabled,
            page=page, pages=pages, total=total, per_page=per_page,
        )

    @app.route("/servers/new")
    def server_new():
        """Full-page create (also used for copy via ?copy=<sid>). 全页新建/复制。"""
        copy_id = parse_int(request.args.get("copy"))
        src = models.fetch_one("servers", copy_id) if copy_id else None
        credentials = _credential_list()
        server = {
            "id": 0, "hostname": (src.get("hostname") + "-copy") if src else "",
            "ip": "", "group_id": src.get("group_id") if src else None,
            "port": src.get("port") if src else 0, "user": src.get("user") if src else "",
            "vault_key": src.get("vault_key") if src else "", "vm_ident": "",  # 复制清空虚拟化标识
            "enabled": (src.get("enabled", 1) if src else 1),
            "copy_from": copy_id or 0,
        }
        bound_scripts = json_or(src.get("scripts_json"), []) if src else []
        prefill_bindings = []
        if src:
            for b in models.fetch_all("server_datasources", "server_id=?", (copy_id,)):
                prefill_bindings.append({
                    "datasource_id": b["datasource_id"],
                    "prom_instance": "",  # 复制时清空
                    "labels_json": b.get("labels_json") or "{}",
                    "scripts_json": json_or(b.get("scripts_json"), []),
                    "enabled": b.get("enabled", 1),
                })
        return render_template(
            "server_new.html",
            server=server, copy_mode=bool(src), back=request.args.get("back", ""),
            groups=_picker_named(models.fetch_all("groups")),
            credentials=credentials,
            cred_names={c["key"]: c["name"] for c in credentials},
            shell_scripts=_picker_scripts(models.fetch_all("scripts", "kind='shell'")),
            prom_scripts=_picker_scripts(models.fetch_all("scripts", "kind='promql'")),
            datasources=models.fetch_all("datasources"),
            bound_scripts=bound_scripts,
            prefill_bindings=prefill_bindings,
            prom_items=[{"id": s["id"], "name": i18n.localize_script(s)[0]} for s in models.fetch_all("scripts", "kind='promql'")],
        )

    @app.route("/servers/<int:sid>")
    def server_detail(sid: int):
        server = models.fetch_one("servers", sid)
        if not server:
            abort(404)
        bindings = models.fetch_all("server_datasources", "server_id=?", (sid,))
        credentials = _credential_list()
        return render_template(
            "server_detail.html",
            server=server, back=request.args.get("back", ""),
            groups=_picker_named(models.fetch_all("groups")),
            credentials=credentials,
            cred_names={c["key"]: c["name"] for c in credentials},
            shell_scripts=_picker_scripts(models.fetch_all("scripts", "kind='shell'")),
            datasources=models.fetch_all("datasources"),
            prom_scripts=_picker_scripts(models.fetch_all("scripts", "kind='promql'")),
            bindings=bindings,
            conn_type=server_conn_type(server, bool(bindings)),
        )

    @app.route("/servers/save", methods=["POST"])
    def servers_save():
        sid = parse_int(request.form.get("id")) or None
        hostname = (request.form.get("hostname") or "").strip()
        ip = (request.form.get("ip") or "").strip()
        if not hostname or not ip:
            flash(i18n.t("servers.err_host_ip_required"), "danger")
            return redirect(url_for("servers"))
        # IP 唯一性（新建/复制/保存均校验）——阻止重复保存。
        if models.query("SELECT id FROM servers WHERE ip=? AND id<>?", (ip, sid or 0)):
            flash(i18n.t("servers.err_ip_dup", ip=ip), "danger")
            return redirect(url_for("servers"))
        vm_ident = (request.form.get("vm_ident") or "").strip()
        if vm_ident and models.query("SELECT id FROM servers WHERE vm_ident=? AND id<>?", (vm_ident, sid or 0)):
            flash(i18n.t("servers.err_vm_ident_dup", vm=vm_ident), "danger")
            return redirect(url_for("servers"))
        port = parse_int(request.form.get("port"), 0)
        vault_key = (request.form.get("vault_key") or "").strip()
        shell_ids = parse_ids(request.form.getlist("scripts"))
        did = parse_int(request.form.get("datasource_id"))
        prom_ids = parse_ids(request.form.getlist("prom_scripts"))
        # 保存硬校验：**本次新增**的 Shell 脚本须已配 SSH；已选 PromQL 脚本须已选数据源。
        cur_server = models.fetch_one("servers", sid) if sid else None
        existing_shell = set(parse_ids(json_or((cur_server or {}).get("scripts_json"), [])))
        copy_from = parse_int(request.form.get("copy_from"))
        if not sid and copy_from:
            _src = models.fetch_one("servers", copy_from)
            if _src:
                existing_shell |= set(parse_ids(json_or(_src.get("scripts_json"), [])))
        new_shell = set(shell_ids) - existing_shell
        if new_shell and not (port and vault_key):
            log.warning(
                "shell-ssh gate: sid=%s copy_from=%s scripts=%s existing=%s",
                sid, copy_from, shell_ids, sorted(existing_shell),
            )
            if sid:
                # 编辑页：新增 Shell 脚本必须配 SSH，阻止保存。
                flash(i18n.t("servers.err_shell_needs_ssh"), "danger")
                return redirect(url_for("servers"))
            # 新建/复制页：忽略本次提交的 Shell 脚本并提示（不阻断保存）。
            shell_ids = [x for x in shell_ids if x in existing_shell]
            flash(i18n.t("servers.warn_shell_ignored"), "warning")
        if prom_ids and not did and not sid:
            flash(i18n.t("servers.err_prom_needs_ds"), "danger")
            return redirect(url_for("servers"))
        new_bindings: list[dict[str, Any]] = []
        if not sid:
            try:
                new_bindings = _parse_bindings(request.form.get("bindings_json"))
            except ValueError:
                flash(i18n.t("servers.err_labels_json_saved"), "danger")
                return redirect(url_for("servers"))
        data = {
            "group_id": parse_int(request.form.get("group_id")) or None,
            "hostname": hostname,
            "ip": ip,
            "port": port,  # 0=未设置（Prometheus-only 服务器可留空）
            "user": (request.form.get("user") or "").strip(),
            "vault_key": vault_key,
            "scripts_json": json.dumps(shell_ids),
            "vm_ident": vm_ident,
            "enabled": 1 if request.form.get("enabled") else 0,
            "updated_at": models.utcnow(),
        }
        back = _safe_back(url_for("servers"))
        new_id = save_object("server", sid, data, g.ip, hostname)
        # 新增：可一次性提交多条数据源绑定（新页 bindings_json）或旧的单条 datasource_id。
        if not sid:
            if not new_bindings and did:
                new_bindings = [{
                    "datasource_id": did,
                    "prom_instance": (request.form.get("prom_instance") or "").strip(),
                    "labels_json": (request.form.get("labels_json") or "{}").strip() or "{}",
                    "scripts_json": prom_ids,
                    "enabled": 1,
                }]
            with models.db() as conn:
                for b in new_bindings:
                    bid = models.insert(conn, "server_datasources", {**b, "server_id": new_id})
                    models.write_audit(conn, g.ip, "create", "server_datasource", bid, f"server-{new_id}", b)
        flash(i18n.t("servers.saved"), "success")
        return redirect(back)

    @app.route("/servers/<int:sid>/delete", methods=["POST"])
    def servers_delete(sid: int):
        with models.db() as conn:
            conn.execute("DELETE FROM server_datasources WHERE server_id=?", (sid,))
        delete_object("server", sid, g.ip)
        flash("服务器已删除（含数据源绑定）", "success")
        return redirect(url_for("servers"))

    def _render_bindings(sid: int) -> str:
        """渲染服务器的数据源绑定区块（含弹窗），供页面内 AJAX 局部刷新。

        Render the server's datasource-binding section (incl. modals) for in-page AJAX refresh.
        """
        return render_template(
            "_server_bindings.html",
            server=models.fetch_one("servers", sid),
            bindings=models.fetch_all("server_datasources", "server_id=?", (sid,)),
            datasources=models.fetch_all("datasources"),
            prom_scripts=_picker_scripts(models.fetch_all("scripts", "kind='promql'")),
        )

    @app.route("/servers/<int:sid>/bindings/save", methods=["POST"])
    def binding_save(sid: int):
        want_json = request.headers.get("X-Requested-With") == "XMLHttpRequest"

        def _fail(key: str, **kw):
            msg = i18n.t(key, **kw)
            if want_json:
                return jsonify({"ok": False, "error": msg})
            flash(msg, "danger")
            return redirect(url_for("server_detail", sid=sid))

        bid = parse_int(request.form.get("binding_id")) or None
        data = {
            "server_id": sid,
            "datasource_id": parse_int(request.form.get("datasource_id")),
            "prom_instance": (request.form.get("prom_instance") or "").strip(),
            "labels_json": (request.form.get("labels_json") or "{}").strip() or "{}",
            "scripts_json": json.dumps(parse_ids(request.form.getlist("prom_scripts"))),
            "enabled": 1 if request.form.get("enabled") else 0,
        }
        if not data["datasource_id"]:
            return _fail("server_detail.err_pick_ds")
        try:
            json.loads(data["labels_json"])
        except ValueError:
            return _fail("server_detail.err_labels")
        table = "server_datasources"
        with models.db() as conn:
            if bid:
                clash = conn.execute(
                    "SELECT id FROM server_datasources WHERE server_id=? AND datasource_id=? AND id<>?",
                    (sid, data["datasource_id"], bid),
                ).fetchone()
                if clash:
                    return _fail("server_detail.binding_clash", id=clash["id"])
                models.update(conn, table, bid, data)
                models.write_audit(conn, g.ip, "update", "server_datasource", bid, f"server-{sid}", data)
                msg, cat = i18n.t("server_detail.binding_updated"), "success"
            else:
                existing = conn.execute(
                    "SELECT id FROM server_datasources WHERE server_id=? AND datasource_id=?",
                    (sid, data["datasource_id"]),
                ).fetchone()
                if existing:
                    # 已存在同一 (服务器, 数据源) 绑定：改为更新，避免 UNIQUE 冲突
                    # Same (server, datasource) already bound: update it to avoid a UNIQUE conflict
                    bid = int(existing["id"])
                    models.update(conn, table, bid, data)
                    models.write_audit(conn, g.ip, "update", "server_datasource", bid, f"server-{sid}", data)
                    msg, cat = i18n.t("server_detail.binding_updated_existing"), "warning"
                else:
                    bid = models.insert(conn, table, data)
                    models.write_audit(conn, g.ip, "create", "server_datasource", bid, f"server-{sid}", data)
                    msg, cat = i18n.t("server_detail.binding_created"), "success"
        if want_json:
            return jsonify({"ok": True, "msg": msg, "html": _render_bindings(sid)})
        flash(msg, cat)
        return redirect(url_for("server_detail", sid=sid))

    @app.route("/servers/<int:sid>/bindings/<int:bid>/delete", methods=["POST"])
    def binding_delete(sid: int, bid: int):
        want_json = request.headers.get("X-Requested-With") == "XMLHttpRequest"
        with models.db() as conn:
            models.delete(conn, "server_datasources", bid)
            models.write_audit(conn, g.ip, "delete", "server_datasource", bid, f"server-{sid}", {"deleted": True})
        msg = i18n.t("server_detail.binding_deleted")
        if want_json:
            return jsonify({"ok": True, "msg": msg, "html": _render_bindings(sid)})
        flash(msg, "success")
        return redirect(url_for("server_detail", sid=sid))

    # ---- 数据源
    @app.route("/datasources")
    def datasources():
        q = (request.args.get("q") or "").strip()
        enabled = request.args.get("enabled") or ""
        page, per_page = page_args()
        where, params = [], []
        if q:
            where.append("(name LIKE ? OR base_url LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        if enabled in ("0", "1"):
            where.append("enabled=?")
            params.append(int(enabled))
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows, total, page, pages = paginate(
            f"SELECT * FROM datasources{clause} ORDER BY id DESC",
            f"SELECT COUNT(*) AS c FROM datasources{clause}",
            params, page, per_page,
        )
        ds_ids = [int(r["id"]) for r in rows]
        bindings_by_ds: dict[int, list[dict[str, Any]]] = {i: [] for i in ds_ids}
        if ds_ids:
            marks = ",".join("?" for _ in ds_ids)
            binds = models.query(
                "SELECT sd.id AS binding_id, sd.datasource_id, sd.prom_instance, sd.scripts_json,"
                " sd.enabled AS binding_enabled, s.id AS server_id, s.hostname, s.ip, s.enabled AS server_enabled"
                f" FROM server_datasources sd LEFT JOIN servers s ON s.id = sd.server_id"
                f" WHERE sd.datasource_id IN ({marks}) ORDER BY sd.datasource_id, s.hostname",
                ds_ids,
            )
            for r in binds:
                bindings_by_ds.setdefault(int(r["datasource_id"]), []).append(
                    {
                        "binding_id": r["binding_id"],
                        "server_id": r["server_id"],
                        "hostname": r["hostname"] or f"(已删除服务器 #{r['server_id']})",
                        "ip": r["ip"] or "",
                        "prom_instance": r["prom_instance"] or "",
                        "script_count": len(json_or(r["scripts_json"], []) or []),
                        "enabled": bool(r["binding_enabled"]) and bool(r["server_enabled"] if r["server_enabled"] is not None else 1),
                    }
                )
        return render_template(
            "datasources.html",
            datasources=rows,
            bindings_by_ds=bindings_by_ds,
            q=q, enabled=enabled,
            page=page, pages=pages, total=total, per_page=per_page,
        )

    @app.route("/datasources/save", methods=["POST"])
    def datasources_save():
        did = parse_int(request.form.get("id")) or None
        name = (request.form.get("name") or "").strip()
        base_url = (request.form.get("base_url") or "").strip()
        if not name or not base_url:
            flash("名称与地址必填", "danger")
            return redirect(url_for("datasources"))
        data = {
            "name": name,
            "base_url": base_url,
            "auth_type": request.form.get("auth_type") or "none",
            "secret_env": (request.form.get("secret_env") or "").strip(),
            "verify_tls": 1 if request.form.get("verify_tls") else 0,
            "timeout": parse_int(request.form.get("timeout"), 10),
            "labels_json": (request.form.get("labels_json") or "{}").strip() or "{}",
            "enabled": 1 if request.form.get("enabled") else 0,
        }
        try:
            json.loads(data["labels_json"])
        except ValueError:
            flash("默认标签需为合法 JSON", "danger")
            return redirect(url_for("datasources"))
        save_object("datasource", did, data, g.ip, name)
        flash("数据源已保存", "success")
        return redirect(url_for("datasources"))

    @app.route("/datasources/<int:did>/delete", methods=["POST"])
    def datasources_delete(did: int):
        refs = references_to("datasource", did)
        if refs:
            flash(i18n.t("common.err_referenced", refs="、".join(refs)), "danger")
            return redirect(url_for("datasources"))
        delete_object("datasource", did, g.ip)
        flash("数据源已删除", "success")
        return redirect(url_for("datasources"))

    @app.route("/datasources/test", methods=["POST"])
    def datasources_test():
        ds = {
            "base_url": request.form.get("base_url"),
            "auth_type": request.form.get("auth_type") or "none",
            "secret_env": request.form.get("secret_env") or "",
            "verify_tls": 1 if request.form.get("verify_tls") else 0,
            "timeout": parse_int(request.form.get("timeout"), 10),
        }
        ok, msg = collectors.PrometheusCollector(ds, get_config().load_secrets()).test_connection()
        flash(("连通性测试通过：" if ok else "连通性测试失败：") + msg, "success" if ok else "danger")
        return redirect(request.referrer or url_for("datasources"))

    @app.route("/datasources/test_ajax", methods=["POST"])
    def datasources_test_ajax():
        ds = {
            "base_url": request.form.get("base_url"),
            "auth_type": request.form.get("auth_type") or "none",
            "secret_env": request.form.get("secret_env") or "",
            "verify_tls": 1 if request.form.get("verify_tls") else 0,
            "timeout": parse_int(request.form.get("timeout"), 10),
        }
        col = collectors.PrometheusCollector(ds, get_config().load_secrets())
        ok, msg = col.test_connection()
        jobs: list[str] = []
        instances: list[str] = []
        if ok:
            try:
                jobs = col.list_label_values("job")
            except Exception:  # noqa: BLE001
                jobs = []
            try:
                instances = col.list_label_values("instance", limit=50)
            except Exception:  # noqa: BLE001
                instances = []
        return jsonify({"ok": ok, "message": msg, "jobs": jobs, "instances": instances})

    # ---- 凭据
    _fingerprint_cache: dict[str, str] = {}

    def _credential_list() -> list[dict[str, Any]]:
        rows = vault.list_entries()
        missing = [r["key"] for r in rows if r["key"] not in _fingerprint_cache]
        if missing:
            with models.db() as conn:
                for key in missing:
                    try:
                        pem = vault.get_secret(conn, key)
                        _fingerprint_cache[key] = vault.fingerprint(pem)
                    except Exception:  # noqa: BLE001
                        _fingerprint_cache[key] = "（无法解析）"
        return [
            {
                "key": r["key"],
                "name": r.get("name") or "（未命名）",
                "note": r.get("note") or "",
                "created_at": r.get("created_at") or "",
                "fingerprint": _fingerprint_cache.get(r["key"], ""),
            }
            for r in rows
        ]

    @app.route("/credentials")
    def credentials():
        q = (request.args.get("q") or "").strip()
        page, per_page = page_args()
        where, params = [], []
        if q:
            where.append("(name LIKE ? OR note LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows, total, page, pages = paginate(
            f"SELECT key, name, note, created_at FROM vault_entries{clause} ORDER BY created_at DESC, name ASC",
            f"SELECT COUNT(*) AS c FROM vault_entries{clause}",
            params, page, per_page,
        )
        missing = [r["key"] for r in rows if r["key"] not in _fingerprint_cache]
        if missing:
            with models.db() as conn:
                for key in missing:
                    try:
                        _fingerprint_cache[key] = vault.fingerprint(vault.get_secret(conn, key))
                    except Exception:  # noqa: BLE001
                        _fingerprint_cache[key] = "（无法解析）"
        creds = [
            {
                "key": r["key"],
                "name": r.get("name") or "（未命名）",
                "note": r.get("note") or "",
                "created_at": r.get("created_at") or "",
                "fingerprint": _fingerprint_cache.get(r["key"], ""),
            }
            for r in rows
        ]
        usage: dict[str, list[str]] = {}
        for s in models.fetch_all("servers"):
            usage.setdefault(s.get("vault_key") or "", []).append(s.get("hostname") or s.get("ip") or "")
        return render_template(
            "credentials.html", credentials=creds, usage=usage, q=q,
            page=page, pages=pages, total=total, per_page=per_page,
        )

    @app.route("/credentials/upload", methods=["POST"])
    def credentials_upload():
        name = (request.form.get("name") or "").strip()
        note = (request.form.get("note") or "").strip()
        if not name:
            flash("凭据名必填", "danger")
            return redirect(url_for("credentials"))
        pem = ""
        file = request.files.get("keyfile")
        if file and file.filename:
            pem = file.read().decode("utf-8", "replace")
        else:
            pem = request.form.get("private_key") or ""
        if not pem.strip():
            flash("请上传或粘贴私钥", "danger")
            return redirect(url_for("credentials"))
        pem_bytes = vault.normalize_pem(pem.encode("utf-8"))
        try:
            fp = vault.fingerprint(pem_bytes)
        except ValueError as exc:
            flash(f"私钥解析失败：{exc}", "danger")
            return redirect(url_for("credentials"))
        with models.db() as conn:
            key = vault.store_secret(conn, pem_bytes, name, note)
            models.write_audit(conn, g.ip, "create", "credential", key, name, {"fingerprint": fp, "note": note})
        _fingerprint_cache[key] = fp
        flash(f"凭据「{name}」已保存（指纹 {fp[:24]}…）", "success")
        return redirect(url_for("credentials"))

    @app.route("/credentials/<key>/save", methods=["POST"])
    def credentials_save(key: str):
        name = (request.form.get("name") or "").strip()
        note = (request.form.get("note") or "").strip()
        if not name:
            flash("凭据名必填", "danger")
            return redirect(url_for("credentials"))
        with models.db() as conn:
            old = vault.get_entry(conn, key)
            if not old:
                abort(404)
            vault.update_entry(conn, key, name, note)
            models.write_audit(
                conn, g.ip, "update", "credential", key, name,
                {"old_name": old.get("name"), "new_name": name, "old_note": old.get("note"), "new_note": note},
            )
        flash("凭据信息已更新", "success")
        return redirect(url_for("credentials"))

    @app.route("/credentials/<key>/rekey", methods=["POST"])
    def credentials_rekey(key: str):
        pem = ""
        file = request.files.get("keyfile")
        if file and file.filename:
            pem = file.read().decode("utf-8", "replace")
        else:
            pem = request.form.get("private_key") or ""
        if not pem.strip():
            flash("请上传或粘贴新私钥", "danger")
            return redirect(url_for("credentials"))
        pem_bytes = vault.normalize_pem(pem.encode("utf-8"))
        try:
            new_fp = vault.fingerprint(pem_bytes)
        except ValueError as exc:
            flash(f"私钥解析失败：{exc}", "danger")
            return redirect(url_for("credentials"))
        with models.db() as conn:
            entry = vault.get_entry(conn, key)
            if not entry:
                abort(404)
            try:
                old_fp = vault.fingerprint(vault.get_secret(conn, key))
            except Exception:  # noqa: BLE001
                old_fp = ""
            vault.update_secret(conn, key, pem_bytes)
            models.write_audit(
                conn, g.ip, "rekey", "credential", key, entry.get("name") or key,
                {"old_fingerprint": old_fp, "new_fingerprint": new_fp},
            )
        _fingerprint_cache[key] = new_fp
        flash(f"凭据「{entry.get('name') or key}」私钥已更换（引用不变）", "success")
        return redirect(url_for("credentials"))

    @app.route("/credentials/<key>/delete", methods=["POST"])
    def credentials_delete(key: str):
        refs = references_to("credential", key)
        if refs:
            flash(i18n.t("common.err_referenced", refs="、".join(refs)), "danger")
            return redirect(url_for("credentials"))
        with models.db() as conn:
            entry = vault.get_entry(conn, key)
            name = (entry or {}).get("name") or key
            vault.delete_secret(conn, key)
            models.write_audit(conn, g.ip, "delete", "credential", key, name, {"deleted": True})
        _fingerprint_cache.pop(key, None)
        flash(f"凭据「{name}」已删除", "success")
        return redirect(url_for("credentials"))

    # ---- 脚本
    @app.route("/scripts")
    def scripts():
        name = (request.args.get("name") or "").strip()
        kind = (request.args.get("kind") or "").strip()
        desc = (request.args.get("desc") or "").strip()
        tag = (request.args.get("tag") or "").strip()
        sort = request.args.get("sort") or "updated_at"
        order = {
            "updated_at": "updated_at DESC, id DESC",
            "name": "name ASC",
            "id_desc": "id DESC",
            "id_asc": "id ASC",
        }.get(sort, "updated_at DESC, id DESC")
        page, per_page = page_args()
        where, params = [], []
        if name:
            where.append("name LIKE ?")
            params.append(f"%{name}%")
        if kind:
            where.append("kind=?")
            params.append(kind)
        if desc:
            where.append("desc LIKE ?")
            params.append(f"%{desc}%")
        if tag:
            where.append("tags_json LIKE ?")
            params.append(f'%"{tag}"%')
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows, total, page, pages = paginate(
            f"SELECT * FROM scripts{clause} ORDER BY {order}",
            f"SELECT COUNT(*) AS c FROM scripts{clause}",
            params, page, per_page,
        )
        all_tags: list[str] = []
        for r in models.fetch_all("scripts"):
            for t in _row_tags(r):
                if t not in all_tags:
                    all_tags.append(t)
        for r in rows:
            content = backup.read_script(r)
            try:
                r["meta_warn"] = bool(collectors.meta_warnings(content, r.get("kind") or "shell"))
            except Exception:  # noqa: BLE001
                r["meta_warn"] = False
            r["lname"], r["ldesc"], r["lmeta"] = i18n.localize_script(r)
            r["tags"] = _row_tags(r)
            if r.get("seed_key"):
                r["dirty"] = bool(content) and content_hash(content) != (r.get("seed_hash") or "")
            else:
                r["dirty"] = False
        # 使用情况计数：脚本 id -> 使用它的服务器数（无 N+1）
        usage_sets: dict[int, set[int]] = {}
        for sv in models.fetch_all("servers"):
            for x in json_or(sv.get("scripts_json"), []):
                usage_sets.setdefault(int(x), set()).add(int(sv["id"]))
        for b in models.fetch_all("server_datasources"):
            for x in json_or(b.get("scripts_json"), []):
                usage_sets.setdefault(int(x), set()).add(int(b["server_id"]))
        usage_counts = {k: len(v) for k, v in usage_sets.items()}
        return render_template(
            "scripts.html",
            scripts=rows, name=name, kind=kind, desc=desc, tag=tag, all_tags=all_tags, sort=sort,
            usage_counts=usage_counts,
            page=page, per_page=per_page, total=total, pages=pages,
        )

    @app.route("/scripts/<int:sid>/clone", methods=["POST"])
    def scripts_clone(sid: int):
        src = models.fetch_one("scripts", sid)
        if not src:
            abort(404)
        content = backup.read_script(src)
        new_name = (src.get("name") or "脚本") + " 副本"
        data = {
            "name": new_name,
            "filename": src.get("filename") or "",
            "kind": src.get("kind") or "shell",
            "desc": src.get("desc") or "",
            "updated_at": models.utcnow(),
        }
        new_id = save_object("script", None, data, g.ip, new_name, script_content=content)
        flash(i18n.t("scripts.cloned", name=src.get("name") or ""), "success")
        return redirect(url_for("script_detail", sid=new_id))

    @app.route("/scripts/help")
    def scripts_help():
        return render_template("scripts_help.html")

    @app.route("/scripts/new")
    def script_new():
        return render_template(
            "script_detail.html",
            script={"id": 0, "name": "", "filename": "", "kind": "shell", "desc": ""},
            content="",
            i18n_map={},
            languages=i18n.languages(),
            current_lang=i18n.current(),
        )

    def _unbind_script(sid: int, only_servers: set[int] | None = None) -> int:
        """移除脚本在所有（或指定服务器集合）服务器/数据源绑定中的使用。Remove usages of the script."""
        changed = 0
        now = models.utcnow()
        for sv in models.fetch_all("servers"):
            if only_servers is not None and int(sv["id"]) not in only_servers:
                continue
            ids = [int(x) for x in json_or(sv.get("scripts_json"), [])]
            if sid in ids:
                new = [x for x in ids if x != sid]
                save_object("server", sv["id"], {"scripts_json": json.dumps(new), "updated_at": now},
                            g.ip, sv.get("hostname") or "", {"unbind_script": sid})
                changed += 1
        for b in models.fetch_all("server_datasources"):
            if only_servers is not None and int(b["server_id"]) not in only_servers:
                continue
            ids = [int(x) for x in json_or(b.get("scripts_json"), [])]
            if sid in ids:
                new = [x for x in ids if x != sid]
                with models.db() as conn:
                    models.update(conn, "server_datasources", b["id"], {"scripts_json": json.dumps(new)})
                    models.write_audit(conn, g.ip, "update", "server_datasource", b["id"],
                                       f"server-{b['server_id']}", {"unbind_script": sid, "scripts_json": new})
                changed += 1
        return changed

    def _script_usage_list(sid: int) -> list[dict[str, Any]]:
        """Servers using the script (shell and/or datasource bindings), aggregated per server."""
        ds_names = {int(d["id"]): d["name"] for d in models.fetch_all("datasources")}
        usage: dict[int, dict[str, Any]] = {}
        for sv in models.fetch_all("servers"):
            if sid in [int(x) for x in json_or(sv.get("scripts_json"), [])]:
                row = usage.setdefault(int(sv["id"]), {"server_id": sv["id"], "name": sv.get("hostname") or sv.get("ip"), "shell": False, "datasources": []})
                row["shell"] = True
        for b in models.fetch_all("server_datasources"):
            if sid in [int(x) for x in json_or(b.get("scripts_json"), [])]:
                sid_srv = int(b["server_id"])
                sv = models.fetch_one("servers", sid_srv) or {}
                row = usage.setdefault(sid_srv, {"server_id": sid_srv, "name": sv.get("hostname") or sv.get("ip") or f"#{sid_srv}", "shell": False, "datasources": []})
                row["datasources"].append(ds_names.get(int(b["datasource_id"]), f"#{b['datasource_id']}"))
        return sorted(usage.values(), key=lambda x: x["name"])

    @app.route("/scripts/<int:sid>")
    def script_detail(sid: int):
        script = models.fetch_one("scripts", sid)
        if not script:
            abort(404)
        content = backup.read_script(script)
        script["lname"], script["ldesc"], script["lmeta"] = i18n.localize_script(script)
        script["dirty"] = bool(script.get("seed_key")) and bool(content) and content_hash(content) != (script.get("seed_hash") or "")
        # 使用情况：按“服务器”聚合（Shell 绑定 + 该服务器各数据源绑定中的 PromQL）。
        usage_list = _script_usage_list(sid)
        return render_template(
            "script_detail.html",
            script=script,
            content=content,
            i18n_map=i18n.parse_i18n(script),
            languages=i18n.languages(),
            current_lang=i18n.current(),
            usage=usage_list,
            back=request.args.get("back", ""),
            meta_warnings=collectors.meta_warnings(content, script.get("kind") or "shell"),
        )

    @app.route("/scripts/<int:sid>/usage")
    def script_usage(sid: int):
        script = models.fetch_one("scripts", sid)
        if not script:
            abort(404)
        q = (request.args.get("q") or "").strip().lower()
        all_usage = _script_usage_list(sid)
        usage_all = len(all_usage)
        usage = all_usage
        if q:
            usage = [u for u in usage if q in (u["name"] or "").lower() or any(q in (d or "").lower() for d in u["datasources"])]
        page, per_page = page_args()
        total = len(usage)
        pages = max(1, (total + per_page - 1) // per_page)
        page = min(max(1, page), pages)
        rows = usage[(page - 1) * per_page: page * per_page]
        script["lname"], script["ldesc"], script["lmeta"] = i18n.localize_script(script)
        return render_template(
            "script_usage.html", script=script, usage=rows, usage_total=total, usage_all=usage_all,
            q=q, page=page, pages=pages, total=total, per_page=per_page,
            back=request.args.get("back", ""),
        )

    @app.route("/scripts/<int:sid>/unbind", methods=["POST"])
    def scripts_unbind_all(sid: int):
        if not models.fetch_one("scripts", sid):
            abort(404)
        n = _unbind_script(sid)
        flash(i18n.t("scripts.unbound_all", n=n), "success")
        back = _safe_back(url_for("script_detail", sid=sid))
        return redirect(back)

    @app.route("/scripts/<int:sid>/unbind_selected", methods=["POST"])
    def scripts_unbind_selected(sid: int):
        if not models.fetch_one("scripts", sid):
            abort(404)
        servers = {int(x) for x in parse_ids(request.form.getlist("server_ids"))}
        n = _unbind_script(sid, only_servers=servers) if servers else 0
        flash(i18n.t("scripts.unbound_one", n=n), "success")
        back = (request.form.get("back") or "").strip()
        return redirect(back if back.startswith("/") else url_for("script_usage", sid=sid))

    @app.route("/scripts/<int:sid>/unbind/<int:server_id>", methods=["POST"])
    def scripts_unbind_server(sid: int, server_id: int):
        if not models.fetch_one("scripts", sid):
            abort(404)
        n = _unbind_script(sid, only_servers={server_id})
        flash(i18n.t("scripts.unbound_one", n=n), "success")
        back = _safe_back(url_for("script_detail", sid=sid))
        return redirect(back)

    @app.route("/scripts/<int:sid>/restore", methods=["POST"])
    def scripts_restore(sid: int):
        script = models.fetch_one("scripts", sid)
        if not script or not script.get("seed_key"):
            abort(404)
        item = _seed_item(script["seed_key"])
        if not item:
            flash("未找到对应的内置脚本定义", "danger")
            return redirect(url_for("script_detail", sid=sid))
        entry_zh = {"name": item["name"]["zh-CN"], "desc": item["desc"]["zh-CN"]}
        entry_en = {"name": item["name"]["en"], "desc": item["desc"]["en"]}
        items = item.get("items") or {}
        if items.get("zh-CN"):
            entry_zh["items"] = items["zh-CN"]
        if items.get("en"):
            entry_en["items"] = items["en"]
        data = {
            "name": item["name"]["zh-CN"],
            "filename": item["file"].split("/", 1)[1],
            "kind": item["kind"],
            "desc": item["desc"]["zh-CN"],
            "seed_key": item["key"],
            "seed_hash": content_hash(item["content"]),
            "i18n_json": json.dumps({"zh-CN": entry_zh, "en": entry_en}, ensure_ascii=False),
            "updated_at": models.utcnow(),
        }
        save_object("script", sid, data, g.ip, data["name"], script_content=item["content"])
        flash(i18n.t("scripts.restored"), "success")
        return redirect(url_for("script_detail", sid=sid))

    @app.route("/scripts/<int:sid>/save_as", methods=["POST"])
    def scripts_save_as(sid: int):
        src = models.fetch_one("scripts", sid)
        if not src:
            abort(404)
        content = backup.read_script(src)
        _, base_desc, _ = i18n.localize_script(src)
        new_name = (request.form.get("name") or "").strip() or ((src.get("name") or "script") + " copy")
        data = {
            "name": new_name,
            "filename": src.get("filename") or "",
            "kind": src.get("kind") or "shell",
            "desc": base_desc or src.get("desc") or "",
            "updated_at": models.utcnow(),
        }
        new_id = save_object("script", None, data, g.ip, new_name, script_content=content)
        flash(i18n.t("scripts.saved_as"), "success")
        return redirect(url_for("script_detail", sid=new_id))

    @app.route("/scripts/save", methods=["POST"])
    def scripts_save():
        sid = parse_int(request.form.get("id")) or None
        name = (request.form.get("name") or "").strip()
        kind = request.form.get("kind") or "shell"
        content = request.form.get("content") or ""
        if not name:
            flash(i18n.t("scripts.err_name_required"), "danger")
            return redirect(url_for("scripts"))
        if kind == "shell":
            import subprocess
            import tempfile

            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8") as fh:
                fh.write(content)
                tmp = fh.name
            try:
                proc = subprocess.run(["bash", "-n", tmp], capture_output=True, text=True)
                if proc.returncode != 0:
                    flash(i18n.t("scripts.err_bash_n", err=proc.stderr.strip()), "danger")
                    return redirect(url_for("scripts"))
            finally:
                os.unlink(tmp)
        else:
            errors = collectors.validate_promql(content)
            if errors:
                flash(i18n.t("scripts.err_promql", err="；".join(errors)), "danger")
                return redirect(url_for("scripts"))
        warns = collectors.meta_warnings(content, kind)
        meta_level = models.get_setting("require_script_metadata", "warn")
        if warns and meta_level == "enforce":
            flash(i18n.t("scripts.err_meta_enforce", err="；".join(warns)), "danger")
            return redirect(url_for("script_detail", sid=sid) if sid else url_for("scripts"))
        if warns and meta_level != "off":
            flash(i18n.t("scripts.warn_meta_saved", err="；".join(warns)), "warning")
        # Per-language name/desc/meta. The form's Basic fields edit the current
        # UI language; the translation panel edits the others.
        lang = (request.form.get("lang") or i18n.current() or i18n.BASE_LANG).strip()
        desc_val = (request.form.get("desc") or "").strip()
        cur = models.fetch_one("scripts", sid) if sid else None
        ij = _i18n_form_values(
            cur, lang, {"name": name, "desc": desc_val},
            {"name": "name", "desc": "desc", "meta": "meta_name"},
        )
        data = {
            "filename": (request.form.get("filename") or "").strip(),
            "kind": kind,
            "i18n_json": json.dumps(ij, ensure_ascii=False),
            "tags_json": json.dumps(_parse_tags(request.form.get("tags")), ensure_ascii=False),
            "updated_at": models.utcnow(),
        }
        # Base columns: user scripts always; built-ins only when editing the base language.
        if (not cur) or (not cur.get("seed_key")) or lang == i18n.BASE_LANG:
            data["name"] = name
            data["desc"] = desc_val
        new_id = save_object("script", sid, data, g.ip, name, script_content=content)
        flash(i18n.t("scripts.saved"), "success")
        return redirect(_safe_back(url_for("script_detail", sid=new_id)))

    @app.route("/scripts/<int:sid>/delete", methods=["POST"])
    def scripts_delete(sid: int):
        refs = references_to("script", sid)
        if refs:
            flash(i18n.t("common.err_referenced", refs="、".join(refs)), "danger")
            return redirect(url_for("scripts"))
        delete_object("script", sid, g.ip)
        flash(i18n.t("scripts.deleted"), "success")
        return redirect(url_for("scripts"))

    @app.route("/scripts/validate", methods=["POST"])
    def scripts_validate():
        content = request.form.get("content") or ""
        kind = request.form.get("kind") or "shell"
        if kind == "promql":
            errors = collectors.validate_promql(content)
            return jsonify({"ok": not errors, "errors": errors, "warnings": collectors.meta_warnings(content, kind)})
        import subprocess
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8") as fh:
            fh.write(content)
            tmp = fh.name
        try:
            proc = subprocess.run(["bash", "-n", tmp], capture_output=True, text=True)
            return jsonify({
                "ok": proc.returncode == 0,
                "errors": [proc.stderr.strip()] if proc.returncode else [],
                "warnings": collectors.meta_warnings(content, kind) if proc.returncode == 0 else [],
            })
        finally:
            os.unlink(tmp)

    @app.route("/scripts/<int:sid>/history")
    def scripts_history(sid: int):
        return _history_view("script", sid, "script_history.html", "脚本")

    # ---- 模型
    @app.route("/models")
    def models_page():
        q = (request.args.get("q") or "").strip()
        enabled = request.args.get("enabled") or ""
        page, per_page = page_args()
        where, params = [], []
        if q:
            where.append("(label LIKE ? OR model_id LIKE ?)")
            params.extend([f"%{q}%", f"%{q}%"])
        if enabled in ("0", "1"):
            where.append("enabled=?")
            params.append(int(enabled))
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows, total, page, pages = paginate(
            f"SELECT * FROM models{clause} ORDER BY id DESC",
            f"SELECT COUNT(*) AS c FROM models{clause}",
            params, page, per_page,
        )
        _dm = models.get_setting("default_model", "")
        _dm_row = models.fetch_one("models", int(_dm)) if _dm.isdigit() else None
        return render_template(
            "models.html", models=rows, default_model=_dm,
            default_model_label=(_dm_row or {}).get("label", ""),
            q=q, enabled=enabled, page=page, pages=pages, total=total, per_page=per_page,
        )

    @app.route("/models/save", methods=["POST"])
    def models_save():
        mid = parse_int(request.form.get("id")) or None
        label = (request.form.get("label") or "").strip()
        model_id = (request.form.get("model_id") or "").strip()
        base_url = (request.form.get("base_url") or "").strip()
        if not label or not model_id or not base_url:
            flash("名称/模型标识/地址必填", "danger")
            return redirect(url_for("models_page"))
        temperature = request.form.get("temperature")
        top_p = request.form.get("top_p")
        data = {
            "label": label,
            "provider": request.form.get("provider") or "openai_compat",
            "model_id": model_id,
            "base_url": base_url,
            "api_key_env": (request.form.get("api_key_env") or "").strip(),
            "temperature": float(temperature) if temperature not in (None, "") else None,
            "top_p": float(top_p) if top_p not in (None, "") else None,
            "enabled": 1 if request.form.get("enabled") else 0,
            "extra_json": (request.form.get("extra_json") or "{}").strip() or "{}",
            "data_policy": request.form.get("data_policy") or models.get_setting("default_data_policy", "cloud"),
            "sanitize_overrides": (request.form.get("sanitize_overrides") or "").strip(),
            "created_at": models.utcnow(),
        }
        save_object("model", mid, data, g.ip, label)
        if request.form.get("set_default"):
            set_setting_versioned("default_model", str(mid or ""), g.ip)
        flash("模型已保存", "success")
        return redirect(url_for("models_page"))

    @app.route("/models/<int:mid>/delete", methods=["POST"])
    def models_delete(mid: int):
        refs = references_to("model", mid)
        if refs:
            flash(i18n.t("common.err_referenced", refs="、".join(refs)), "danger")
            return redirect(url_for("models_page"))
        delete_object("model", mid, g.ip)
        flash("模型已删除", "success")
        return redirect(url_for("models_page"))

    @app.route("/models/<int:mid>/default", methods=["POST"])
    def models_default(mid: int):
        set_setting_versioned("default_model", str(mid), g.ip)
        flash("已设为默认模型", "success")
        return redirect(url_for("models_page"))

    @app.route("/models/<int:mid>/test", methods=["POST"])
    def models_test_saved(mid: int):
        model = models.fetch_one("models", mid)
        if not model:
            abort(404)
        ok, msg = model_client.test_connection(model, get_config().load_secrets())
        flash(("连通性测试通过：" if ok else "连通性测试失败：") + msg, "success" if ok else "danger")
        return redirect(url_for("models_page"))

    @app.route("/models/test", methods=["POST"])
    def models_test():
        model = {
            "model_id": request.form.get("model_id"),
            "base_url": request.form.get("base_url"),
            "api_key_env": request.form.get("api_key_env") or "",
            "extra_json": request.form.get("extra_json") or "",
            "temperature": None,
            "top_p": None,
        }
        ok, msg = model_client.test_connection(model, get_config().load_secrets())
        flash(("连通性测试通过：" if ok else "连通性测试失败：") + msg, "success" if ok else "danger")
        return redirect(request.referrer or url_for("models_page"))

    @app.route("/models/test_ajax", methods=["POST"])
    def models_test_ajax():
        model = {
            "model_id": request.form.get("model_id"),
            "base_url": request.form.get("base_url"),
            "api_key_env": request.form.get("api_key_env") or "",
            "extra_json": request.form.get("extra_json") or "",
            "temperature": None,
            "top_p": None,
        }
        secrets = get_config().load_secrets()
        ok, msg = model_client.test_connection(model, secrets)
        models_list: list[str] = []
        if ok:
            try:
                models_list = model_client.list_models(model, secrets)
            except Exception:  # noqa: BLE001
                models_list = []
        return jsonify({"ok": ok, "message": msg, "models": models_list})

    @app.route("/models/list_ajax", methods=["POST"])
    def models_list_ajax():
        model = {
            "base_url": request.form.get("base_url"),
            "api_key_env": request.form.get("api_key_env") or "",
            "extra_json": request.form.get("extra_json") or "",
        }
        try:
            items = model_client.list_models(model, get_config().load_secrets())
            return jsonify({"ok": True, "models": items})
        except Exception as exc:  # noqa: BLE001
            return jsonify({"ok": False, "error": str(exc), "models": []})

    # ---- 通知
    @app.route("/notifications")
    def notifications():
        q = (request.args.get("q") or "").strip()
        ntype = request.args.get("type") or ""
        enabled = request.args.get("enabled") or ""
        page, per_page = page_args()
        where, params = [], []
        if q:
            where.append("name LIKE ?")
            params.append(f"%{q}%")
        if ntype in ("smtp", "dingtalk"):
            where.append("type=?")
            params.append(ntype)
        if enabled in ("0", "1"):
            where.append("enabled=?")
            params.append(int(enabled))
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows, total, page, pages = paginate(
            f"SELECT * FROM notifications{clause} ORDER BY id DESC",
            f"SELECT COUNT(*) AS c FROM notifications{clause}",
            params, page, per_page,
        )
        all_rows = models.fetch_all("notifications")
        return render_template(
            "notifications.html", notifications=rows,
            enabled_count=sum(1 for n in all_rows if n.get("enabled")),
            total_all=len(all_rows),
            q=q, ntype=ntype, enabled=enabled,
            page=page, pages=pages, total=total, per_page=per_page,
        )

    @app.route("/notifications/<int:nid>/toggle", methods=["POST"])
    def notifications_toggle(nid: int):
        n = models.fetch_one("notifications", nid)
        if not n:
            abort(404)
        new = 0 if n.get("enabled") else 1
        save_object("notification", nid, {"enabled": new}, g.ip, n.get("name") or "", {"enabled": new})
        flash(f"通知「{n.get('name') or nid}」已{'启用' if new else '停用'}", "success")
        return redirect(url_for("notifications"))

    @app.route("/notifications/toggle_all", methods=["POST"])
    def notifications_toggle_all():
        enable = 1 if request.form.get("enable") else 0
        changed = 0
        for n in models.fetch_all("notifications"):
            if int(n.get("enabled") or 0) != enable:
                save_object("notification", n["id"], {"enabled": enable}, g.ip, n.get("name") or "", {"enabled": enable})
                changed += 1
        flash(f"已{'全部启用' if enable else '全部停用'}通知（变更 {changed} 条）", "success")
        return redirect(url_for("notifications"))

    @app.route("/notifications/save", methods=["POST"])
    def notifications_save():
        nid = parse_int(request.form.get("id")) or None
        name = (request.form.get("name") or "").strip()
        ntype = request.form.get("type") or "smtp"
        if not name:
            flash(i18n.t("notifications.err_name_required"), "danger")
            return redirect(url_for("notifications"))
        if ntype == "smtp":
            config = {
                "host": (request.form.get("smtp_host") or "").strip(),
                "port": parse_int(request.form.get("smtp_port"), 465),
                "user": (request.form.get("smtp_user") or "").strip(),
                "from": (request.form.get("smtp_from") or "").strip(),
                "to": [x.strip() for x in (request.form.get("smtp_to") or "").replace(";", ",").split(",") if x.strip()],
                "use_ssl": bool(request.form.get("smtp_ssl")),
                "use_tls": bool(request.form.get("smtp_tls")),
            }
            secret_env = (request.form.get("secret_env") or "SMTP_PASSWORD").strip()
        else:
            config = {
                "webhook_url": (request.form.get("webhook_url") or "").strip(),
                "at_mobiles": [x.strip() for x in (request.form.get("at_mobiles") or "").split(",") if x.strip()],
                "at_all": bool(request.form.get("at_all")),
            }
            secret_env = (request.form.get("secret_env") or "DINGTALK_SECRET").strip()
        data = {
            "type": ntype,
            "name": name,
            "config_json": json.dumps(config, ensure_ascii=False),
            "secret_env": secret_env,
            "enabled": 1 if request.form.get("enabled") else 0,
            "created_at": models.utcnow(),
        }
        save_object("notification", nid, data, g.ip, name)
        flash(i18n.t("notifications.saved"), "success")
        return redirect(url_for("notifications"))

    @app.route("/notifications/<int:nid>/delete", methods=["POST"])
    def notifications_delete(nid: int):
        delete_object("notification", nid, g.ip)
        flash(i18n.t("notifications.deleted"), "success")
        return redirect(url_for("notifications"))

    @app.route("/notifications/<int:nid>/test", methods=["POST"])
    def notifications_test(nid: int):
        n = models.fetch_one("notifications", nid)
        if not n:
            abort(404)
        ok, msg = notify.send_test(n, get_config().load_secrets())
        flash(
            i18n.t("notifications.test_ok") if ok else i18n.t("notifications.test_fail", err=msg),
            "success" if ok else "danger",
        )
        return redirect(url_for("notifications"))

    # ---- 定时任务
    def _schedule_targets_chips(s: dict[str, Any], maps: dict[str, dict[int, str]]) -> list[str]:
        tj = json_or(s.get("targets_json"), {})
        chips: list[str] = []
        if tj.get("all"):
            chips.append(i18n.t("schedules.chip_all"))
        if tj.get("applications"):
            chips.append(i18n.t("schedules.chip_apps", n=len(tj["applications"])))
        if tj.get("groups"):
            chips.append(i18n.t("schedules.chip_groups", n=len(tj["groups"])))
        if tj.get("servers"):
            chips.append(i18n.t("schedules.chip_servers", n=len(tj["servers"])))
        if tj.get("datasources"):
            chips.append(i18n.t("schedules.chip_datasources", n=len(tj["datasources"])))
        sc = json_or(s.get("scripts_json"), [])
        if sc:
            chips.append(i18n.t("schedules.chip_scripts", n=len(sc)))
        if not chips:
            chips.append(i18n.t("schedules.chip_none"))
        return chips

    def _schedule_form_ctx(s: dict[str, Any] | None) -> dict[str, Any]:
        servers = models.fetch_all("servers")
        group_servers: dict[int, list[int]] = {}
        for sv in servers:
            if sv.get("group_id"):
                group_servers.setdefault(int(sv["group_id"]), []).append(int(sv["id"]))
        return dict(
            s=s,
            groups=_picker_named(models.fetch_all("groups")),
            servers=servers,
            server_items=[{"id": sv["id"], "name": f"{sv.get('hostname')} ({sv.get('ip')})"} for sv in servers],
            datasources=models.fetch_all("datasources"),
            scripts=_picker_scripts(models.fetch_all("scripts")),
            applications=_picker_named([a for a in models.fetch_all("applications") if a.get("enabled", 1)]),
            app_servers=engine.application_servers(),
            group_servers=group_servers,
            all_server_ids=[int(x["id"]) for x in servers],
            freq=scheduler_mod.classify(s) if s else {"preset": "every30", "minute": "", "hour": "", "dow": ""},
        )

    @app.route("/schedules")
    def schedules():
        q = (request.args.get("q") or "").strip()
        enabled = request.args.get("enabled") or ""
        page, per_page = page_args()
        where, params = [], []
        if q:
            where.append("name LIKE ?")
            params.append(f"%{q}%")
        if enabled in ("0", "1"):
            where.append("enabled=?")
            params.append(int(enabled))
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows, total, page, pages = paginate(
            f"SELECT * FROM run_schedule{clause} ORDER BY id DESC",
            f"SELECT COUNT(*) AS c FROM run_schedule{clause}",
            params, page, per_page,
        )
        maps = dict(
            apps={int(a["id"]): a["name"] for a in models.fetch_all("applications")},
            groups={int(g["id"]): g["name"] for g in models.fetch_all("groups")},
            servers={int(sv["id"]): (sv.get("hostname") or sv.get("ip") or "") for sv in models.fetch_all("servers")},
            datasources={int(d["id"]): d["name"] for d in models.fetch_all("datasources")},
        )
        # 上次结果：按 schedule_id 批量取最近一条（避免 N+1）
        last: dict[int, dict[str, Any]] = {}
        sids = [int(r["id"]) for r in rows]
        if sids:
            qmarks = ",".join("?" for _ in sids)
            for r in models.query(
                f"SELECT * FROM run_history WHERE schedule_id IN ({qmarks}) ORDER BY id DESC", sids
            ):
                last.setdefault(int(r["schedule_id"]), r)
        for s in rows:
            s["freq"] = scheduler_mod.describe(s)
            s["chips"] = _schedule_targets_chips(s, maps)
            nr = scheduler_mod.next_runs(s, 1)
            s["next_at"] = nr[0].strftime("%Y-%m-%d %H:%M") if nr else ""
            s["last_run"] = last.get(int(s["id"]))
        all_rows = models.fetch_all("run_schedule")
        return render_template(
            "schedules.html",
            schedules=rows,
            enabled_count=sum(1 for s in all_rows if s.get("enabled")),
            total_all=len(all_rows),
            status_color={"success": "success", "partial": "warning", "error": "danger", "running": "info"},
            q=q, enabled=enabled, page=page, pages=pages, total=total, per_page=per_page,
        )

    @app.route("/schedules/new")
    def schedules_new():
        return render_template("schedule_detail.html", back=request.args.get("back", ""), **_schedule_form_ctx(None))

    @app.route("/schedules/<int:sid>")
    def schedule_detail(sid: int):
        s = models.fetch_one("run_schedule", sid)
        if not s:
            abort(404)
        return render_template("schedule_detail.html", back=request.args.get("back", ""), **_schedule_form_ctx(s))

    @app.route("/schedules/<int:sid>/toggle", methods=["POST"])
    def schedules_toggle(sid: int):
        s = models.fetch_one("run_schedule", sid)
        if not s:
            abort(404)
        new = 0 if s.get("enabled") else 1
        save_object("schedule", sid, {"enabled": new}, g.ip, s.get("name") or "", {"enabled": new})
        flash(i18n.t("schedules.toggled", name=s.get("name") or sid,
                     state=i18n.t("common.enabled") if new else i18n.t("common.disabled")), "success")
        return redirect(url_for("schedules"))

    @app.route("/schedules/toggle_all", methods=["POST"])
    def schedules_toggle_all():
        enable = 1 if request.form.get("enable") else 0
        changed = 0
        for s in models.fetch_all("run_schedule"):
            if int(s.get("enabled") or 0) != enable:
                save_object("schedule", s["id"], {"enabled": enable}, g.ip, s.get("name") or "", {"enabled": enable})
                changed += 1
        flash(i18n.t("schedules.toggled_all", state=i18n.t("common.enabled") if enable else i18n.t("common.disabled"), n=changed), "success")
        return redirect(url_for("schedules"))

    @app.route("/schedules/save", methods=["POST"])
    def schedules_save():
        sid = parse_int(request.form.get("id")) or None
        list_back = (request.form.get("back") or request.args.get("back") or "").strip()
        list_back = list_back if list_back.startswith("/") else ""
        back = (url_for("schedule_detail", sid=sid, back=list_back) if sid
                else url_for("schedules_new", back=list_back))
        name = (request.form.get("name") or "").strip()
        if not name:
            flash(i18n.t("schedules.err_name_required"), "danger")
            return redirect(back)
        targets = {
            "groups": parse_ids(request.form.getlist("target_groups")),
            "servers": parse_ids(request.form.getlist("target_servers")),
            "applications": parse_ids(request.form.getlist("target_applications")),
            "datasources": parse_ids(request.form.getlist("target_datasources")),
            "all": bool(request.form.get("target_all")),
        }
        if not targets["all"] and not any(targets[k] for k in ("groups", "servers", "applications", "datasources")):
            flash(i18n.t("schedules.err_no_target"), "danger")
            return redirect(back)
        cron = {
            "cron_min": (request.form.get("cron_min") or "*").strip() or "*",
            "cron_hour": (request.form.get("cron_hour") or "*").strip() or "*",
            "cron_dow": (request.form.get("cron_dow") or "*").strip() or "*",
        }
        if scheduler_mod.cron_error(cron):
            flash(i18n.t("schedules.err_cron"), "danger")
            return redirect(back)
        mode = request.form.get("mode") if request.form.get("mode") in ("model", "raw") else "model"
        if mode == "model":
            dm = models.get_setting("default_model", "")
            m = models.fetch_one("models", int(dm)) if dm.isdigit() else None
            if not m or not m.get("enabled", 1):
                flash(i18n.t("schedules.err_no_model"), "danger")
                return redirect(back)
        data = {
            "name": name,
            "targets_json": json.dumps(targets),
            "scripts_json": json.dumps(parse_ids(request.form.getlist("scripts"))),
            "mode": mode,
            "enabled": 1 if request.form.get("enabled") else 0,
            **cron,
        }
        save_object("schedule", sid, data, g.ip, name)
        flash(i18n.t("schedules.saved"), "success")
        return redirect(list_back or url_for("schedules"))

    @app.route("/schedules/<int:sid>/delete", methods=["POST"])
    def schedules_delete(sid: int):
        delete_object("schedule", sid, g.ip)
        flash(i18n.t("schedules.deleted"), "success")
        return redirect(url_for("schedules"))

    @app.route("/schedules/<int:sid>/run", methods=["POST"])
    def schedules_run(sid: int):
        s = models.fetch_one("run_schedule", sid)
        if not s:
            abort(404)
        if engine.is_running():
            flash(i18n.t("engine.err_busy"), "warning")
            return redirect(url_for("schedules"))
        targets = json_or(s.get("targets_json"), {})
        scripts = json_or(s.get("scripts_json"), [])
        mode = s.get("mode") or "model"
        if mode == "model":
            dm = models.get_setting("default_model", "")
            m = models.fetch_one("models", int(dm)) if dm.isdigit() else None
            if not m or not m.get("enabled", 1):
                flash(i18n.t("schedules.err_no_model"), "danger")
                return redirect(url_for("schedules"))
        operator_ip = g.ip
        prev_max = int(models.query("SELECT COALESCE(MAX(id), 0) AS m FROM run_history")[0]["m"])

        def _worker() -> None:
            try:
                engine.run(targets, scripts, trigger="schedule", schedule_id=sid, operator_ip=operator_ip, mode=mode)
            except Exception:  # noqa: BLE001
                log.exception("定时任务立即执行失败")

        threading.Thread(target=_worker, name=f"pypimeops-sched-run-{sid}", daemon=True).start()
        flash(i18n.t("schedules.run_submitted"), "success")
        return redirect(url_for("run_wait", after=prev_max))

    # ---- 立即执行
    @app.route("/run", methods=["GET", "POST"])
    def run_page():
        if request.method == "POST":
            if engine.is_running():
                flash("已有巡检正在执行，请稍后再试", "warning")
                return redirect(url_for("run_page"))
            targets = {
                "groups": parse_ids(request.form.getlist("target_groups")),
                "servers": parse_ids(request.form.getlist("target_servers")),
                "applications": parse_ids(request.form.getlist("target_applications")),
                "datasources": parse_ids(request.form.getlist("target_datasources")),
                "all": bool(request.form.get("target_all")),
            }
            scripts = parse_ids(request.form.getlist("scripts"))
            if not targets.get("all") and not targets["groups"] and not targets["servers"] and not targets["applications"]:
                flash("请至少选择应用/分组/服务器，或勾选全部", "danger")
                return redirect(url_for("run_page"))
            # 显式勾选 = 覆盖：对未绑定该脚本的所选目标给出警告（不阻断）
            if scripts:
                maps = engine._load_maps()
                chosen = engine._resolve_servers(targets, maps)
                binds = engine.script_server_bindings(maps)
                for sc_id in scripts:
                    sc = maps["scripts"].get(int(sc_id))
                    if not sc:
                        continue
                    bset = set(binds.get(int(sc_id), []))
                    missing = [s for s in chosen if int(s["id"]) not in bset]
                    if missing:
                        names = "、".join((s.get("hostname") or s.get("ip") or f"#{s['id']}") for s in missing[:5])
                        more = f" 等 {len(missing)} 台" if len(missing) > 5 else ""
                        action = "将在这些目标上覆盖运行" if (sc.get("kind") or "shell") == "shell" else "在这些目标上无绑定，将跳过"
                        flash(f"脚本「{sc.get('name')}」未绑定到 {names}{more}，{action}", "warning")
            mode = request.form.get("mode") or "model"
            if mode not in ("model", "raw"):
                mode = "model"
            if mode == "model":
                dm = models.get_setting("default_model", "")
                m = models.fetch_one("models", int(dm)) if dm.isdigit() else None
                if not m or not m.get("enabled", 1):
                    flash("未配置可用的默认模型；请先在「模型」页面配置并设为默认，或改用「仅原始结果」模式", "danger")
                    return redirect(url_for("run_page"))

            operator_ip = g.ip  # 在请求上下文中取出，供后台线程使用
            prev_max = int(models.query("SELECT COALESCE(MAX(id), 0) AS m FROM run_history")[0]["m"])

            def _worker():
                try:
                    engine.run(targets, scripts, trigger="manual", operator_ip=operator_ip, mode=mode)
                except Exception:  # noqa: BLE001
                    log.exception("手动执行失败")

            threading.Thread(target=_worker, name="pypimeops-manual-run", daemon=True).start()
            flash("巡检已提交后台执行", "success")
            return redirect(url_for("run_wait", after=prev_max))

        servers = models.fetch_all("servers")
        groups = _picker_named(models.fetch_all("groups"))
        server_items = [{"id": s["id"], "name": f"{s.get('hostname')} ({s.get('ip')})", "kind": ""} for s in servers]
        group_servers: dict[int, list[int]] = {}
        for s in servers:
            if s.get("group_id"):
                group_servers.setdefault(int(s["group_id"]), []).append(int(s["id"]))
        all_server_ids = [int(s["id"]) for s in servers]
        latest = models.query("SELECT summary FROM run_history ORDER BY id DESC LIMIT 1")
        issue_server_ids: list[int] = []
        if latest:
            sm = json_or(latest[0].get("summary"), {})
            names = {str(it.get("server")) for it in (sm.get("issues") or [])}
            issue_server_ids = [int(s["id"]) for s in servers if s.get("hostname") in names or s.get("ip") in names]
        return render_template(
            "run.html",
            servers=servers,
            server_items=server_items,
            groups=groups,
            datasources=models.fetch_all("datasources"),
            scripts=_picker_scripts(models.fetch_all("scripts")),
            script_targets=engine.script_server_bindings(),
            applications=_picker_named([a for a in models.fetch_all("applications") if a.get("enabled", 1)]),
            app_servers=engine.application_servers(),
            group_servers=group_servers,
            all_server_ids=all_server_ids,
            issue_server_ids=issue_server_ids,
            running=engine.is_running(),
        )

    @app.route("/run/status/<int:rid>")
    def run_status(rid: int):
        row = models.fetch_one("run_history", rid)
        if not row:
            return jsonify({"error": "not found"}), 404
        return jsonify(
            {
                "id": row["id"],
                "status": row["status"],
                "summary": json_or(row.get("summary"), {}),
                "report_file": row.get("report_file"),
                "finished": row.get("finished"),
            }
        )

    @app.route("/run/wait")
    def run_wait():
        after = parse_int(request.args.get("after"), 0)
        return render_template("run_wait.html", after=after)

    @app.route("/run/progress")
    def run_progress():
        after = parse_int(request.args.get("after"), 0)
        rows = models.query("SELECT * FROM run_history WHERE id > ? ORDER BY id DESC LIMIT 1", (after,))
        prog = engine.get_progress()
        if not rows:
            return jsonify({"found": False, "running": engine.is_running(), "progress": prog})
        row = rows[0]
        return jsonify(
            {
                "found": True,
                "running": row["status"] == "running",
                "id": row["id"],
                "status": row["status"],
                "started": row.get("started"),
                "finished": row.get("finished"),
                "error": row.get("error") or "",
                "report_url": url_for("report_detail", rid=row["id"]),
                "progress": prog,
                "summary": json_or(row.get("summary"), {}),
            }
        )

    # ---- 报告
    def _report_filter(src) -> tuple[list[str], list]:
        where, params = [], []
        status = (src.get("status") or "").strip()
        trigger = (src.get("trigger") or "").strip()
        start = (src.get("start") or "").strip()
        end = (src.get("end") or "").strip()
        result = (src.get("result") or "").strip()
        if status == "need":
            # 「需关注」= 报告含问题项 或 运行失败/部分失败（内容维度，兼容旧数据）
            # "Needs attention" = report has issues OR run failed/partial (content dimension, legacy-safe)
            where.append("(issue_count>0 OR status IN ('error','partial'))")
        elif status:
            where.append("status=?")
            params.append(status)
        if result in ("success", "partial", "error", "running"):
            where.append("status=?")
            params.append(result)
        if trigger in ("manual", "schedule"):
            where.append("trigger=?")
            params.append(trigger)
        if local_input_to_utc(start):
            where.append("started>=?")
            params.append(local_input_to_utc(start))
        if local_input_to_utc(end):
            where.append("started<=?")
            params.append(local_input_to_utc(end))
        return where, params

    @app.route("/reports")
    def reports():
        # 两个独立维度：内容（status=need/all）与运行结果（result）
        # Two independent dimensions: content (status=need/all) and run result (result)
        status = (request.args.get("status") if "status" in request.args else "need") or ""
        result = request.args.get("result") or ""
        trigger = request.args.get("trigger") or ""
        start = request.args.get("start") or ""
        end = request.args.get("end") or ""
        where, params = [], []
        # For "need" the window is trigger/time only; membership is decided per target
        # from its latest run (see the grouping branch below). 「需关注」窗口仅 trigger/时间。
        if result in ("success", "partial", "error", "running"):
            where.append("status=?")
            params.append(result)
        if trigger in ("manual", "schedule"):
            where.append("trigger=?")
            params.append(trigger)
        if local_input_to_utc(start):
            where.append("started>=?")
            params.append(local_input_to_utc(start))
        if local_input_to_utc(end):
            where.append("started<=?")
            params.append(local_input_to_utc(end))
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        total_all = (models.query("SELECT COUNT(*) AS c FROM run_history")[0]["c"] or 0)
        counts = {row["status"]: row["c"] for row in models.query("SELECT status, COUNT(*) AS c FROM run_history GROUP BY status")}

        def _decorate(r):
            sm = _localize_summary(json_or(r.get("summary"), {}))
            r["summary_obj"] = sm
            r["duration"] = _duration(r.get("started"), r.get("finished"))
            iss = sm.get("issues") or []
            r["fail_count"] = sum(1 for it in iss if (it.get("status") or "").upper() in ("FAIL", "ERROR"))
            r["warn_count"] = sum(1 for it in iss if (it.get("status") or "").upper() == "WARN")
            return r

        # 「需关注」按“巡检大目标类型”分组：应用巡检→按应用；分组巡检→按分组；服务器巡检→按服务器
        # "Needs attention" grouped by the run's target type: application / group / server
        if status == "need":
            # Judgement is per target's LATEST run in the current window (trigger/time),
            # computed from structured detail (target dimension). 「需关注」按目标最新一次运行判定。
            all_rows = [_decorate(dict(r)) for r in models.query(f"SELECT * FROM run_history{clause} ORDER BY id DESC", tuple(params))]
            _apps, _groups, _servers, _grp_srv = _report_target_maps()
            need, recovered = _group_runs_by_target(all_rows, _apps, _groups, _servers, _grp_srv, _detail_loader())
            result_filter = result in ("success", "partial", "error", "running")

            def _prep(entries):
                out = []
                for g in entries:
                    full = g["runs"]
                    disp = [x for x in full if (not result_filter) or x.get("status") == result]
                    if not disp:
                        continue
                    gg = dict(g)
                    gg["runs"] = disp[:50]  # 组内展示上限（更早可前端展开）
                    gg["count"] = len(disp)
                    out.append(gg)
                return out

            grouped = _prep(need) + _prep(recovered)
            return render_template(
                "reports.html", grouped=grouped, status=status, result=result,
                trigger=trigger, start=start, end=end,
                total=len(all_rows), total_all=total_all, counts=counts, need_count=len(need),
                status_color={"success": "success", "partial": "warning", "error": "danger", "running": "info"},
            )

        page, per_page = page_args()
        rows, total, page, pages = paginate(
            f"SELECT * FROM run_history{clause} ORDER BY id DESC",
            f"SELECT COUNT(*) AS c FROM run_history{clause}",
            params, page, per_page,
        )
        for r in rows:
            _decorate(r)
        return render_template(
            "reports.html", reports=rows, status=status, result=result, trigger=trigger, start=start, end=end,
            page=page, pages=pages, total=total, per_page=per_page, total_all=total_all,
            counts=counts, need_count=_need_target_count(),
            status_color={"success": "success", "partial": "warning", "error": "danger", "running": "info"},
        )

    @app.route("/reports/<int:rid>/download")
    def report_download(rid: int):
        row = models.fetch_one("run_history", rid)
        if not row:
            abort(404)
        # Regenerate from structured data when a language is requested and available.
        # 指定语言且存在结构化数据时，按该语言从结构化数据重渲染 `.md`。
        lang = (request.args.get("lang") or "").strip()
        detail = None
        drow = models.query("SELECT detail_json FROM run_results WHERE run_id=?", (rid,))
        if drow:
            try:
                detail = json.loads(drow[0]["detail_json"] or "{}")
            except ValueError:
                detail = None
        from flask import Response

        if lang and i18n.has(lang) and detail:
            prev = i18n.current()
            i18n.set_current(lang)
            try:
                summary = _localize_summary(json_or(row.get("summary"), {}))
                md = _render_report_md(row, summary, _localize_detail(detail))
            finally:
                i18n.set_current(prev)
        else:
            md = _read_report(row.get("report_file") or "")
        return Response(
            md,
            mimetype="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=pypimeops_report_{rid}.md"},
        )

    @app.route("/reports/<int:rid>")
    def report_detail(rid: int):
        row = models.fetch_one("run_history", rid)
        if not row:
            abort(404)
        content = _read_report(row.get("report_file") or "")
        detail = None
        drow = models.query("SELECT detail_json FROM run_results WHERE run_id=?", (rid,))
        if drow:
            try:
                detail = json.loads(drow[0]["detail_json"] or "{}")
            except ValueError:
                detail = None
        duration = ""
        try:
            _s = datetime.fromisoformat(row.get("started") or "")
            _f = datetime.fromisoformat(row.get("finished") or "")
            _sec = max(0, int((_f - _s).total_seconds()))
            duration = f"{_sec // 60}m{_sec % 60}s" if _sec >= 60 else f"{_sec}s"
        except (ValueError, TypeError):
            duration = ""
        detail = _localize_detail(detail)
        summary = _localize_summary(json_or(row.get("summary"), {}))
        return render_template(
            "report_detail.html", run=row, content=content,
            summary=summary, detail=detail, duration=duration,
        )

    def _read_report(filename: str) -> str:
        if not filename:
            return "（无报告文件）"
        cfg = get_config()
        safe = os.path.basename(filename)
        path = os.path.join(cfg.reports_dir, safe)
        if not os.path.abspath(path).startswith(os.path.abspath(cfg.reports_dir)):
            return "（非法路径）"
        if not os.path.isfile(path):
            return "（报告文件不存在）"
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()

    @app.route("/reports/<int:rid>/delete", methods=["POST"])
    def report_delete(rid: int):
        row = models.fetch_one("run_history", rid)
        if row:
            _delete_report_file(row.get("report_file") or "")
            with models.db() as conn:
                models.delete(conn, "run_history", rid)
                conn.execute("DELETE FROM run_results WHERE run_id=?", (rid,))
                models.write_audit(conn, g.ip, "delete", "report", rid, row.get("report_file") or "", {"deleted": True})
        flash("报告已删除", "success")
        back = (request.form.get("back") or "").strip()
        return redirect(back if back.startswith("/") else url_for("reports"))

    @app.route("/reports/batch_delete", methods=["POST"])
    def reports_batch_delete():
        scope = (request.form.get("scope") or "selected").strip()
        if scope == "all":
            rows = models.query("SELECT id, report_file FROM run_history")
        elif scope == "filtered":
            where, params = _report_filter(request.form)
            clause = (" WHERE " + " AND ".join(where)) if where else ""
            rows = models.query(f"SELECT id, report_file FROM run_history{clause}", tuple(params))
        else:
            ids = [i for i in (parse_int(x) for x in request.form.getlist("ids")) if i]
            if not ids:
                flash("未选择任何报告", "warning")
                return redirect(url_for("reports"))
            marks = ",".join("?" for _ in ids)
            rows = models.query(f"SELECT id, report_file FROM run_history WHERE id IN ({marks})", tuple(ids))
        count = 0
        for row in rows:
            _delete_report_file(row.get("report_file") or "")
            with models.db() as conn:
                models.delete(conn, "run_history", row["id"])
                conn.execute("DELETE FROM run_results WHERE run_id=?", (row["id"],))
                models.write_audit(
                    conn, g.ip, "delete", "report", row["id"], row.get("report_file") or "",
                    {"deleted": True, "batch_scope": scope},
                )
            count += 1
        flash(f"已删除 {count} 份报告", "success")
        back = (request.form.get("back") or "").strip()
        return redirect(back if back.startswith("/") else url_for("reports"))

    def _delete_report_file(filename: str) -> None:
        if not filename:
            return
        cfg = get_config()
        safe = os.path.basename(filename)
        path = os.path.join(cfg.reports_dir, safe)
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass

    # ---- 审计日志
    @app.route("/audit-logs")
    def audit_logs():
        page, per_page = page_args()
        action = request.args.get("action")
        action = "need" if action is None else (action or "")
        args2 = {k: val for k, val in request.args.items() if k != "action"}
        where, params = _audit_filters(args2)
        if action == "need":
            where.append(_AUDIT_NEED_SQL)
        elif action:
            where.append("action=?")
            params.append(action)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        total = models.query(f"SELECT COUNT(*) AS c FROM audit_log{clause}", params)[0]["c"]
        rows = models.query(
            f"SELECT * FROM audit_log{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [per_page, (page - 1) * per_page],
        )
        for r in rows:
            r["detail_obj"] = json_or(r.get("detail"), None)
        action_counts = {row["action"]: row["c"] for row in models.query("SELECT action, COUNT(*) AS c FROM audit_log GROUP BY action")}
        total_all = sum(action_counts.values())
        need_count = models.query(f"SELECT COUNT(*) AS c FROM audit_log WHERE {_AUDIT_NEED_SQL}")[0]["c"]
        return render_template(
            "audit_logs.html",
            logs=rows, page=page, per_page=per_page, total=total,
            pages=max(1, (total + per_page - 1) // per_page),
            action_counts=action_counts, need_count=need_count, total_all=total_all,
            audit_actions=_AUDIT_ACTIONS,
            action_cn=_AUDIT_ACTION_CN, action_color=_AUDIT_ACTION_COLOR, ttype_cn=_AUDIT_TTYPE_CN,
            cur_action=action,
        )

    @app.route("/audit-logs/export")
    def audit_export():
        fmt = request.args.get("format") or "csv"
        where, params = _audit_filters(request.args)
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        rows = models.query(f"SELECT * FROM audit_log{clause} ORDER BY id DESC LIMIT 5000", params)
        from flask import Response

        if fmt == "json":
            payload = json.dumps(rows, ensure_ascii=False, indent=2, default=str)
            return Response(
                payload, mimetype="application/json",
                headers={"Content-Disposition": "attachment; filename=audit_logs.json"},
            )
        import csv
        import io

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "ts", "ip", "action", "target_type", "target_id", "target_name", "detail", "status"])
        for r in rows:
            writer.writerow([r.get("id"), r.get("ts"), r.get("ip"), r.get("action"), r.get("target_type"),
                             r.get("target_id"), r.get("target_name"), r.get("detail"), r.get("status")])
        return Response(
            buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
        )

    @app.route("/audit-logs/<int:aid>/restore", methods=["POST"])
    def audit_restore(aid: int):
        row = models.fetch_one("audit_log", aid)
        if not row:
            abort(404)
        vid = row.get("version_id")
        if not vid:
            flash("该审计记录没有可恢复的备份版本（如运行/通知/导入等操作）", "warning")
            return redirect(request.referrer or url_for("audit_logs"))
        ok, msg = backup.restore(int(vid), g.ip)
        flash(msg, "success" if ok else "danger")
        return redirect(request.referrer or url_for("audit_logs"))

    # ---- 备份恢复
    @app.route("/backups")
    def backups():
        tab = (request.args.get("tab") or "objects").lower()
        if tab not in ("objects", "versions", "io"):
            tab = "objects"
        obj_type = request.args.get("object_type") or ""
        object_id = request.args.get("object_id") or ""
        action = request.args.get("action") or ""
        page, per_page = page_args()
        grouped = None
        versions: list[Any] = []
        total, pages = 0, 1
        if tab == "objects":
            where = ["id NOT IN (SELECT version_id FROM audit_log WHERE version_id IS NOT NULL)"]
            params: list[Any] = []
            if obj_type:
                where.append("object_type=?")
                params.append(obj_type)
            clause = " WHERE " + " AND ".join(where)
            grouped = models.query(
                f"SELECT object_type, object_id, COUNT(*) AS cnt, MAX(id) AS last_id,"
                f" MAX(version) AS last_ver, MAX(created_at) AS last_at"
                f" FROM backup_versions{clause} GROUP BY object_type, object_id ORDER BY last_id DESC LIMIT 500",
                params,
            )
            last_ids = [g["last_id"] for g in grouped]
            snapmap: dict[int, dict[str, Any]] = {}
            if last_ids:
                marks = ",".join("?" for _ in last_ids)
                for r in models.query(f"SELECT id, action, snapshot_json FROM backup_versions WHERE id IN ({marks})", last_ids):
                    snapmap[int(r["id"])] = r
            for g in grouped:
                r = snapmap.get(int(g["last_id"]), {})
                g["display_name"] = _obj_display_name(g["object_type"], backup.parse_snapshot(r))
                g["last_action"] = r.get("action", "")
            total = len(grouped)
        elif tab == "versions":
            total = backup.count_versions(obj_type or None, object_id or None, action or None, exclude_audited=True)
            pages = max(1, (total + per_page - 1) // per_page)
            page = min(max(1, page), pages)
            versions = backup.list_versions(
                obj_type or None, object_id or None, action or None,
                limit=per_page, offset=(page - 1) * per_page, exclude_audited=True,
            )
            for v in versions:
                v["display_name"] = _obj_display_name(v["object_type"], backup.parse_snapshot(v))
        obj_count = models.query(
            "SELECT COUNT(*) AS c FROM (SELECT 1 FROM backup_versions"
            " WHERE id NOT IN (SELECT version_id FROM audit_log WHERE version_id IS NOT NULL)"
            " GROUP BY object_type, object_id)"
        )[0]["c"]
        ver_count = backup.count_versions(exclude_audited=True)
        return render_template(
            "backups.html", tab=tab, grouped=grouped, versions=versions,
            object_type=obj_type, object_id=object_id, action=action,
            page=page, pages=pages, total=total, per_page=per_page,
            obj_count=obj_count, ver_count=ver_count,
            objtypes=["script", "server", "group", "datasource", "model", "notification", "schedule", "setting"],
            actions=["create", "update", "delete", "restore"],
            action_cn=_AUDIT_ACTION_CN, action_color=_AUDIT_ACTION_COLOR, ttype_cn=_AUDIT_TTYPE_CN,
        )

    @app.route("/backups/<int:vid>")
    def backup_detail(vid: int):
        row = backup.get_version(vid)
        if not row:
            abort(404)
        snapshot = backup.parse_snapshot(row)
        current = None
        missing: list[str] = []
        with models.db() as conn:
            current = backup.snapshot_object(conn, row["object_type"], row["object_id"])
            missing = backup.check_references(conn, row["object_type"], snapshot)
        diff = backup.diff_snapshots(current, snapshot)
        display_name = _obj_display_name(row["object_type"], current or snapshot) or "（已删除对象）"
        return render_template(
            "backup_detail.html", version=row, snapshot=snapshot, current=current, diff=diff, missing=missing,
            display_name=display_name,
        )

    @app.route("/backups/compare")
    def backup_compare():
        a = parse_int(request.args.get("a"))
        b = parse_int(request.args.get("b"))
        va = backup.get_version(a)
        vb = backup.get_version(b)
        if not va or not vb:
            abort(404)
        sa = backup.parse_snapshot(va)
        sb = backup.parse_snapshot(vb)
        diff = backup.diff_snapshots(sa, sb)
        return render_template(
            "backup_compare.html", va=va, vb=vb, sa=sa, sb=sb, diff=diff,
            name_a=_obj_display_name(va["object_type"], sa) or f"{va['object_type']}#{va['object_id']}",
            name_b=_obj_display_name(vb["object_type"], sb) or f"{vb['object_type']}#{vb['object_id']}",
        )

    @app.route("/backups/<int:vid>/restore", methods=["POST"])
    def backup_restore(vid: int):
        ok, msg = backup.restore(vid, g.ip)
        flash(msg, "success" if ok else "danger")
        return redirect(url_for("backup_detail", vid=vid))

    @app.route("/backups/export")
    def backup_export():
        data = backup.export_all()
        payload = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        with models.db() as conn:
            models.write_audit(conn, g.ip, "export", "backup", "", "all", {"size": len(payload)})
        from flask import Response

        return Response(
            payload,
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=pypimeops_backup.json"},
        )

    @app.route("/backups/import", methods=["POST"])
    def backup_import():
        mode = request.form.get("mode") or "daily"
        force = bool(request.form.get("force"))
        file = request.files.get("file")
        if not file or not file.filename:
            flash("请选择备份 JSON 文件", "danger")
            return redirect(url_for("backups"))
        try:
            data = json.loads(file.read().decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            flash("备份文件解析失败", "danger")
            return redirect(url_for("backups"))
        ok, msg = backup.import_all(data, mode=mode, force=force, operator_ip=g.ip)
        flash(msg, "success" if ok else "danger")
        return redirect(url_for("backups"))

    # ---- 设置
    @app.route("/settings")
    def settings_page():
        return render_template(
            "settings.html",
            settings=models.get_settings(),
            models=models.fetch_all("models"),
            sanitize_rules=sanitize._parse_rules(models.get_setting("sanitize_rules", "")),
            audit_count=models.query("SELECT COUNT(*) AS c FROM audit_log")[0]["c"],
            backup_count=models.query("SELECT COUNT(*) AS c FROM backup_versions")[0]["c"],
            report_count=models.query("SELECT COUNT(*) AS c FROM run_history")[0]["c"],
            log_file_count=len(applog.list_log_files()),
        )

    @app.route("/settings/save", methods=["POST"])
    def settings_save():
        keys = [
            "site_title",
            "default_language",
            "app_log_level",
            "allowed_ips",
            "default_model",
            "concurrency",
            "model_concurrency",
            "model_request_timeout",
            "model_retry_times",
            "audit_retention_days",
            "app_log_retention_days",
            "report_retention_days",
            "backup_retention_days",
            "default_data_policy",
            "require_script_metadata",
            "model_output_max_bytes",
            "model_batch_max_bytes",
            "ssh_connect_timeout",
            "ssh_command_timeout",
        ]
        new_lang = ""
        for key in keys:
            if key in request.form:
                val = (request.form.get(key) or "").strip()
                if key == "default_language":
                    new_lang = val
                set_setting_versioned(key, val, g.ip)
        for key in ("sanitize_enabled", "warn_push_enabled", "notify_oversize_enabled", "notify_ambiguous_enabled"):
            set_setting_versioned(key, "true" if request.form.get(key) else "false", g.ip)
        apply_log_level(models.get_setting("app_log_level", "INFO"))
        i18n.set_fallback(models.get_setting("default_language", "zh-CN") or "zh-CN")
        flash(i18n.t("settings.saved"), "success")
        resp = redirect(url_for("settings_page"))
        # The language dropdown stores a cookie that takes priority; keep it in
        # sync so the new default takes effect immediately.
        # 语言下拉会写 cookie 且优先级更高，这里同步，使新默认语言立即生效。
        if new_lang and i18n.has(new_lang):
            i18n.set_current(new_lang)
            resp.set_cookie("lang", new_lang, max_age=365 * 86400, samesite="Lax")
        return resp

    @app.route("/settings/reload_locales", methods=["POST"])
    def settings_reload_locales():
        i18n.reload()
        i18n.set_fallback(models.get_setting("default_language", "zh-CN") or "zh-CN")
        with models.db() as conn:
            models.write_audit(conn, g.ip, "update", "setting", "default_language", "reload_locales", {"loaded": [x["code"] for x in i18n.languages()]})
        flash("语言包已重新加载", "success")
        return redirect(url_for("settings_page"))

    @app.route("/settings/locale_template")
    def settings_locale_template():
        from flask import Response

        payload = json.dumps(i18n.template_dict(), ensure_ascii=False, indent=2, sort_keys=True)
        return Response(
            payload, mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=locale_template.json"},
        )

    @app.route("/settings/sanitize", methods=["POST"])
    def settings_sanitize():
        raw = (request.form.get("sanitize_rules") or "").strip()
        if raw:
            try:
                rules = json.loads(raw)
                if not isinstance(rules, list):
                    raise ValueError
            except ValueError:
                flash("脱敏规则需为 JSON 数组", "danger")
                return redirect(url_for("settings_page"))
            set_setting_versioned("sanitize_rules", json.dumps(rules, ensure_ascii=False), g.ip)
        else:
            set_setting_versioned("sanitize_rules", "", g.ip)
        flash("脱敏规则已保存", "success")
        return redirect(url_for("settings_page"))

    @app.route("/settings/sanitize/reset", methods=["POST"])
    def settings_sanitize_reset():
        set_setting_versioned("sanitize_rules", json.dumps(sanitize.default_rules(), ensure_ascii=False), g.ip)
        flash("已恢复内置脱敏规则", "success")
        return redirect(url_for("settings_page"))

    @app.route("/settings/cleanup", methods=["POST"])
    def settings_cleanup():
        kind = request.form.get("kind") or ""
        settings = models.get_settings()
        if kind == "audit":
            n = models.cleanup_audit(int(settings.get("audit_retention_days", 90)))
            flash(f"已清理审计日志 {n} 条", "success")
        elif kind == "backups":
            n = backup.cleanup(int(settings.get("backup_retention_days", 90)))
            flash(f"已清理版本备份 {n} 条", "success")
        elif kind == "reports":
            n = _cleanup_reports(int(settings.get("report_retention_days", 90)))
            flash(f"已清理报告 {n} 份", "success")
        elif kind == "applog":
            res = applog.cleanup(days=int(settings.get("app_log_retention_days", 7)))
            flash(f"已清理轮转日志 {res['deleted']} 个", "success")
        return redirect(url_for("settings_page"))

    def _cleanup_reports(retention_days: int) -> int:
        cutoff = datetime.now(timezone.utc).timestamp() - retention_days * 86400
        rows = models.fetch_all("run_history")
        count = 0
        for row in rows:
            try:
                ts = datetime.fromisoformat(row.get("started") or "")
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except (ValueError, TypeError):
                continue
            if ts.timestamp() < cutoff:
                _delete_report_file(row.get("report_file") or "")
                with models.db() as conn:
                    models.delete(conn, "run_history", row["id"])
                    conn.execute("DELETE FROM run_results WHERE run_id=?", (row["id"],))
                count += 1
        return count

    # ---- 应用日志
    @app.route("/logs")
    def logs_page():
        files = applog.list_log_files()
        selected = applog.safe_name(request.args.get("file") or applog.active_log())
        start = request.args.get("start") or ""
        end = request.args.get("end") or ""
        q = request.args.get("q") or ""
        limit = parse_int(request.args.get("limit"), 2000)
        mode = (request.args.get("mode") or "").lower()
        if mode not in ("realtime", "query"):
            mode = "query" if (start or end or q) else "realtime"
        if mode == "query":
            lines = applog.read_range(selected, start, end, q, limit)
        else:
            lines = applog.read_last(selected, limit)
        path = applog.log_path(selected)
        size = os.path.getsize(path) if os.path.isfile(path) else 0
        return render_template(
            "logs.html",
            files=files,
            selected=selected,
            lines=lines,
            start=start,
            end=end,
            q=q,
            limit=limit,
            offset=size,
            mode=mode,
            active_log=applog.active_log(),
            retention_days=models.get_setting("app_log_retention_days", "7"),
            log_level=models.get_setting("app_log_level", "INFO"),
        )

    @app.route("/logs/data")
    def logs_data():
        selected = applog.safe_name(request.args.get("file") or applog.active_log())
        start = request.args.get("start") or ""
        end = request.args.get("end") or ""
        q = request.args.get("q") or ""
        limit = parse_int(request.args.get("limit"), 2000)
        if start or end or q:
            lines = applog.read_range(selected, start, end, q, limit)
            path = applog.log_path(selected)
            offset = os.path.getsize(path) if os.path.isfile(path) else 0
        else:
            offset = parse_int(request.args.get("offset"), 0)
            lines, offset = applog.read_tail(selected, offset)
        return jsonify({"lines": lines, "offset": offset})

    @app.route("/logs/download")
    def logs_download():
        selected = applog.safe_name(request.args.get("file") or applog.active_log())
        start = request.args.get("start") or ""
        end = request.args.get("end") or ""
        q = request.args.get("q") or ""
        limit = parse_int(request.args.get("limit"), 5000)
        if start or end or q:
            lines = applog.read_range(selected, start, end, q, limit)
        else:
            lines = applog.read_last(selected, limit)
        from flask import Response

        return Response(
            "\n".join(lines),
            mimetype="text/plain",
            headers={"Content-Disposition": f"attachment; filename={selected}"},
        )

    @app.route("/logs/cleanup", methods=["POST"])
    def logs_cleanup():
        days = parse_int(request.form.get("days"), 0)
        remove_all = bool(request.form.get("remove_all"))
        truncate_current = bool(request.form.get("truncate_current"))
        if not days and not remove_all and not truncate_current:
            flash("请选择清理条件（按天/全部/清空当前）", "warning")
            return redirect(url_for("logs_page"))
        res = applog.cleanup(days=days or None, remove_all=remove_all, truncate_current=truncate_current)
        with models.db() as conn:
            models.write_audit(
                conn, g.ip, "cleanup", "applog", "", "应用日志",
                {"days": days, "remove_all": remove_all, "truncate_current": truncate_current, **res},
            )
        msg = f"已清理轮转日志 {res['deleted']} 个"
        if res["truncated"]:
            msg += "，并清空当前日志"
        flash(msg, "success")
        return redirect(url_for("logs_page", file=request.form.get("file") or applog.active_log()))

    @app.route("/logs/settings", methods=["POST"])
    def logs_settings():
        level = (request.form.get("app_log_level") or "").strip()
        days = (request.form.get("app_log_retention_days") or "").strip()
        if level in ("DEBUG", "INFO", "WARNING", "ERROR"):
            set_setting_versioned("app_log_level", level, g.ip)
            apply_log_level(level)
        if days:
            set_setting_versioned("app_log_retention_days", days, g.ip)
        flash("日志设置已保存", "success")
        return redirect(url_for("logs_page"))

    @app.route("/logs/delete", methods=["POST"])
    def logs_delete():
        name = request.form.get("file") or ""
        ok = applog.delete_file(name)
        with models.db() as conn:
            models.write_audit(conn, g.ip, "delete", "applog", name, name, {"deleted": ok})
        flash("已删除日志文件" if ok else "删除失败（活动日志不可删除）", "success" if ok else "warning")
        return redirect(url_for("logs_page"))

    # ---- 智能问答（只读，阶段一：上下文注入）
    _chat_store: dict[str, list[dict[str, Any]]] = {}

    def _chat_history() -> list[dict[str, Any]]:
        sid = session.get("chat_sid")
        if not sid:
            sid = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")
            session["chat_sid"] = sid
        return _chat_store.setdefault(sid, [])

    @app.route("/chatbot")
    def chatbot_page():
        settings = models.get_settings()
        dm = (settings.get("default_model") or "").strip()
        m = models.fetch_one("models", int(dm)) if dm.isdigit() else None
        model_ok = bool(m and m.get("enabled", 1))
        return render_template(
            "chatbot.html",
            history=_chat_history(),
            model_ok=model_ok,
            model_label=(m or {}).get("label") or "",
        )

    @app.route("/chatbot/ask", methods=["POST"])
    def chatbot_ask():
        question = (request.form.get("message") or "").strip()
        if not question:
            return jsonify({"error": "请输入问题"})
        hist = _chat_history()
        reply, err = chatbot.ask(question, hist)
        if err:
            return jsonify({"error": err})
        hist.append({"role": "user", "content": question[: chatbot.MAX_QUESTION]})
        hist.append({"role": "assistant", "content": reply})
        del hist[: max(0, len(hist) - chatbot.MAX_HISTORY * 2)]
        return jsonify({"reply": reply, "reply_html": str(render_markdown(reply))})

    @app.route("/chatbot/clear", methods=["POST"])
    def chatbot_clear():
        _chat_history().clear()
        flash("对话已清空", "success")
        return redirect(url_for("chatbot_page"))

    @app.route("/whitelist/ack", methods=["POST"])
    def whitelist_ack():
        set_setting_versioned("whitelist_ack", "true", g.ip)
        flash("已确认安全提示", "success")
        return redirect(request.referrer or url_for("dashboard"))

    # ---- 历史/恢复通用视图
    def _history_view(obj_type: str, obj_id: int, template: str, label: str):
        versions = backup.list_versions(obj_type, obj_id, limit=200)
        with models.db() as conn:
            current = backup.snapshot_object(conn, obj_type, obj_id)
        display_name = _obj_display_name(obj_type, current) or "（已删除对象）"
        return render_template(
            template, versions=versions, object_type=obj_type, object_id=obj_id, label=label,
            current=current, display_name=display_name,
        )

    @app.errorhandler(404)
    def _404(_e):
        return render_template("error.html", code=404, message="页面不存在"), 404

    @app.errorhandler(sqlite3.IntegrityError)
    def _integrity(exc):
        log.exception("数据库约束冲突：%s", exc)
        return render_template("error.html", code=409, message="数据库约束冲突（可能为重复数据），请返回重试"), 409

    @app.errorhandler(500)
    def _500(_e):
        return render_template("error.html", code=500, message="服务器内部错误"), 500

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PyPiMeOps Web")
    parser.add_argument("--config", default=None, help="config.yaml 路径（默认 ./config.yaml）")
    parser.add_argument("--host", default=None, help="覆盖 config.yaml 的 host")
    parser.add_argument("--port", type=int, default=None, help="覆盖 config.yaml 的 port")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    set_config(cfg)
    app = create_app()
    scheduler.poll_interval = cfg.poll_interval
    scheduler.start()

    host = args.host or cfg.host
    port = args.port or cfg.port
    log.info("PyPiMeOps 启动于 http://%s:%s（单进程）", host, port)
    app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
