"""只读智能问答（阶段一：上下文注入，无工具调用）。

- build_context(): 生成紧凑只读快照（有上限）
- ask(): 复用 model_client.analyze()，按 data_policy 脱敏后外发
- 只读、不审计、不执行任何写操作
"""
from __future__ import annotations

import json
import logging
from typing import Any

import i18n
import model_client
import models
import sanitize
from config import get_config

log = logging.getLogger("pypimeops.chatbot")

MAX_QUESTION = 2000
MAX_HISTORY = 20          # 参与上下文的历史消息条数上限
MAX_SERVERS = 200
MAX_RUNS = 10
MAX_ISSUES_PER_RUN = 5

def _conn_type(server: dict[str, Any], has_prom: bool) -> str:
    ssh = bool(server.get("port")) or bool((server.get("user") or "").strip()) or bool(server.get("vault_key")) or bool(
        json.loads(server.get("scripts_json") or "[]")
    )
    parts = []
    if ssh:
        parts.append("SSH")
    if has_prom:
        parts.append("Prometheus")
    return "+".join(parts) if parts else i18n.t("chatbot.conn_none")


def build_context() -> str:
    settings = models.get_settings()
    servers = models.fetch_all("servers")
    groups = {int(g["id"]): i18n.localize_named(g)[0] for g in models.fetch_all("groups")}
    apps = models.fetch_all("applications")
    app_members = models.fetch_all("application_members")
    bound = {int(r["server_id"]) for r in models.query("SELECT DISTINCT server_id FROM server_datasources")}
    runs = models.fetch_all("run_history", order="id DESC")[:MAX_RUNS]

    lines: list[str] = []
    lines.append(i18n.t("chatbot.ctx_stats_header"))
    lines.append(i18n.t(
        "chatbot.ctx_stats",
        servers=len(servers), groups=len(groups), apps=len(apps),
        scripts=len(models.fetch_all("scripts")), datasources=len(models.fetch_all("datasources")),
        models=len(models.fetch_all("models")), notifications=len(models.fetch_all("notifications")),
    ))

    lines.append("")
    lines.append(i18n.t("chatbot.ctx_servers_header"))
    for s in servers[:MAX_SERVERS]:
        lines.append(i18n.t(
            "chatbot.ctx_server_row",
            host=s.get("hostname"), ip=s.get("ip"),
            group=groups.get(int(s.get("group_id") or 0), "-"),
            conn=_conn_type(s, int(s["id"]) in bound),
            enabled=i18n.t("common.enabled") if s.get("enabled") else i18n.t("common.disabled"),
        ))
    if len(servers) > MAX_SERVERS:
        lines.append(i18n.t("chatbot.ctx_more_servers", n=len(servers) - MAX_SERVERS))

    grp_servers: dict[int, int] = {}
    for s in servers:
        gid = int(s.get("group_id") or 0)
        if gid:
            grp_servers[gid] = grp_servers.get(gid, 0) + 1
    latest_app_status: dict[int, str] = {}
    if runs:
        sm0 = json.loads(runs[0].get("summary") or "{}")
        for a in sm0.get("apps") or []:
            latest_app_status[a.get("id")] = a.get("status", "-")
    app_member_count: dict[int, int] = {}
    for m in app_members:
        aid = int(m["application_id"])
        if m["member_type"] == "server":
            app_member_count[aid] = app_member_count.get(aid, 0) + 1
        elif m["member_type"] == "group":
            app_member_count[aid] = app_member_count.get(aid, 0) + grp_servers.get(int(m["member_id"]), 0)
    lines.append("")
    lines.append(i18n.t("chatbot.ctx_apps_header"))
    for a in apps[:50]:
        aid = int(a["id"])
        lines.append(i18n.t(
            "chatbot.ctx_app_row",
            name=i18n.localize_named(a)[0], members=app_member_count.get(aid, 0),
            status=latest_app_status.get(aid, "-"),
        ))
    if len(apps) > 50:
        lines.append(i18n.t("chatbot.ctx_more_apps", n=len(apps) - 50))

    lines.append("")
    lines.append(i18n.t("chatbot.ctx_runs_header"))
    for r in runs:
        sm = json.loads(r.get("summary") or "{}")
        lines.append(i18n.t(
            "chatbot.ctx_run_row",
            id=r.get("id"), trigger=r.get("trigger"), mode=r.get("mode"), status=r.get("status"),
            started=models.local_str(r.get("started")), servers=sm.get("server_count", 0),
            errors=sm.get("error_count", 0), uncertain=sm.get("uncertain_count", 0),
        ))
        for it in (sm.get("issues") or [])[:MAX_ISSUES_PER_RUN]:
            _row = models.fetch_one("scripts", int(it["script_id"])) if it.get("script_id") else None
            _item = i18n.localize_item(_row, it.get("item_key")) if (_row and it.get("item_key")) else it.get("item")
            if it.get("item"):
                detail = i18n.t("chatbot.ctx_issue_item", item=_item, value=it.get("value", ""))
                if it.get("unit"):
                    detail += " " + it["unit"]
                if it.get("threshold"):
                    detail += i18n.t("chatbot.ctx_issue_threshold", threshold=it["threshold"])
                if it.get("excess"):
                    detail += i18n.t("chatbot.ctx_issue_excess", excess=it["excess"])
            else:
                detail = str(it.get("message", ""))[:120]
            lines.append(i18n.t(
                "chatbot.ctx_issue_row",
                status=it.get("status"), server=it.get("server"), script=it.get("script"), detail=detail,
            ))

    lines.append("")
    lines.append(i18n.t("chatbot.ctx_settings_header"))
    lines.append(i18n.t(
        "chatbot.ctx_settings",
        model=settings.get("default_model") or i18n.t("chatbot.not_set"),
        policy=settings.get("default_data_policy"),
        sanitize=i18n.t("chatbot.sanitize_on") if settings.get("sanitize_enabled") == "true" else i18n.t("chatbot.sanitize_off"),
    ))
    return "\n".join(lines)


def _context_for_model(settings: dict[str, str]) -> str:
    context = build_context()
    policy = settings.get("default_data_policy", "cloud")
    if policy == "local":
        return context
    enabled = str(settings.get("sanitize_enabled", "true")).lower() in ("1", "true", "yes")
    cleaned, _hits = sanitize.sanitize(context, settings.get("sanitize_rules") or "", None, enabled=enabled)
    return cleaned


def ask(question: str, history: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    """返回 (reply, error)。只读，不做任何写操作。"""
    settings = models.get_settings()
    dm = (settings.get("default_model") or "").strip()
    model = models.fetch_one("models", int(dm)) if dm.isdigit() else None
    if not model or not model.get("enabled", 1):
        return None, i18n.t("chatbot.err_no_model")

    secrets = get_config().load_secrets()
    context = _context_for_model(settings)

    messages: list[dict[str, str]] = [
        {"role": "system", "content": i18n.t("chatbot.system_prompt") + "\n\n" + i18n.t("chatbot.ctx_begin") + "\n" + context + "\n" + i18n.t("chatbot.ctx_end")}
    ]
    for m in history[-MAX_HISTORY:]:
        role = m.get("role")
        if role in ("user", "assistant"):
            messages.append({"role": role, "content": str(m.get("content", ""))[:4000]})
    messages.append({"role": "user", "content": (question or "")[:MAX_QUESTION]})

    try:
        reply = model_client.analyze(
            model,
            messages,
            secrets,
            timeout=int(settings.get("model_request_timeout", 60)),
            retries=int(settings.get("model_retry_times", 2)),
        )
        return (reply or "").strip() or i18n.t("chatbot.empty_reply"), None
    except Exception as exc:  # noqa: BLE001
        log.exception("chatbot 模型调用失败")
        return None, i18n.t("chatbot.err_call", err=exc)
