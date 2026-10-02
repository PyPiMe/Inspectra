"""通知适配器：SMTP / 钉钉统一接口。

- 每次 run 聚合为一条通知（状态汇总 + 异常清单）
- 多条通知可同时启用，告警时全部触发
- 发送失败重试 2 次，仍失败返回失败信息（由引擎写日志/审计/报告标注）
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import smtplib
import time
import urllib.parse
from email.mime.text import MIMEText
from email.header import Header
from typing import Any

import requests

import i18n
import models

RETRY_TIMES = 2


def _default_lang() -> str:
    try:
        return (models.get_setting("default_language", "zh-CN") or "zh-CN").strip() or "zh-CN"
    except Exception:  # noqa: BLE001
        return "zh-CN"


def _localize_summary_for(summary: dict[str, Any], lang: str) -> dict[str, Any]:
    """Deep-copy summary and resolve app/script names for a language. 深拷贝并按语言解析名称。"""
    s = copy.deepcopy(summary or {})
    for a in s.get("apps") or []:
        aid = a.get("id")
        if aid:
            row = models.fetch_one("applications", int(aid))
            if row:
                a["name"] = i18n.localize_named(row, lang)[0]
        elif a.get("name") in ("未归属", "__unassigned__"):
            a["name"] = i18n.t_for(lang, "reports2.unassigned")
    for it in s.get("issues") or []:
        aids = it.get("app_ids") or []
        if aids:
            names = []
            for aid in aids:
                row = models.fetch_one("applications", int(aid))
                names.append(i18n.localize_named(row, lang)[0] if row else f"#{aid}")
            it["app"] = "、".join(names)
        elif it.get("app") in ("未归属", "__unassigned__"):
            it["app"] = i18n.t_for(lang, "reports2.unassigned")
        sid = it.get("script_id")
        if sid:
            row = models.fetch_one("scripts", int(sid))
            if row:
                it["script"] = i18n.localize_script(row, lang)[0]
                if it.get("item_key"):
                    it["item"] = i18n.localize_item(row, it["item_key"], lang)
    return s


def _site_title() -> str:
    try:
        return (models.get_setting("site_title", "PyPiMeOps") or "PyPiMeOps").strip() or "PyPiMeOps"
    except Exception:  # noqa: BLE001
        return "PyPiMeOps"


def _parse_json(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw or "{}")
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def send_smtp(notification: dict[str, Any], secrets: dict[str, str], subject: str, body: str, lang: str | None = None) -> None:
    lang = lang or _default_lang()
    cfg = _parse_json(notification.get("config_json"))
    password = secrets.get(notification.get("secret_env") or "SMTP_PASSWORD", "")
    host = cfg.get("host")
    port = int(cfg.get("port") or 465)
    from_addr = cfg.get("from") or cfg.get("from_addr") or ""
    to_addrs = cfg.get("to") or []
    if isinstance(to_addrs, str):
        to_addrs = [a.strip() for a in to_addrs.replace(";", ",").split(",") if a.strip()]
    if not host or not from_addr or not to_addrs:
        raise ValueError(i18n.t_for(lang, "notify.err_smtp_config"))

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = Header(subject, "utf-8")
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)

    use_ssl = bool(cfg.get("use_ssl", port == 465))
    use_tls = bool(cfg.get("use_tls", False))
    if use_ssl:
        server = smtplib.SMTP_SSL(host, port, timeout=20)
    else:
        server = smtplib.SMTP(host, port, timeout=20)
    try:
        if use_tls and not use_ssl:
            server.starttls()
        if password:
            server.login(cfg.get("user") or from_addr, password)
        server.sendmail(from_addr, to_addrs, msg.as_string())
    finally:
        try:
            server.quit()
        except Exception:  # noqa: BLE001
            pass


def send_dingtalk(notification: dict[str, Any], secrets: dict[str, str], subject: str, body: str, lang: str | None = None) -> None:
    lang = lang or _default_lang()
    cfg = _parse_json(notification.get("config_json"))
    webhook = cfg.get("webhook_url") or ""
    if not webhook:
        raise ValueError(i18n.t_for(lang, "notify.err_dingtalk_webhook"))
    secret = secrets.get(notification.get("secret_env") or "DINGTALK_SECRET", "")
    url = webhook
    if secret:
        ts = str(int(time.time() * 1000))
        string_to_sign = f"{ts}\n{secret}"
        sign = urllib.parse.quote_plus(
            base64.b64encode(
                hmac.new(secret.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256).digest()
            ).decode("utf-8")
        )
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}timestamp={ts}&sign={sign}"

    payload: dict[str, Any] = {
        "msgtype": "text",
        "text": {"content": f"{subject}\n\n{body}"},
    }
    at = cfg.get("at_mobiles") or []
    if at or cfg.get("at_all"):
        payload["at"] = {"atMobiles": at, "isAtAll": bool(cfg.get("at_all"))}
    resp = requests.post(url, json=payload, timeout=20)
    data = resp.json() if resp.content else {}
    if resp.status_code != 200 or data.get("errcode") not in (0, None):
        raise ValueError(i18n.t_for(lang, "notify.err_dingtalk_failed", status=resp.status_code, data=data))


def send_one(notification: dict[str, Any], secrets: dict[str, str], subject: str, body: str, lang: str | None = None) -> None:
    lang = lang or _default_lang()
    ntype = (notification.get("type") or "").lower()
    if ntype == "smtp":
        send_smtp(notification, secrets, subject, body, lang)
    elif ntype == "dingtalk":
        send_dingtalk(notification, secrets, subject, body, lang)
    else:
        raise ValueError(i18n.t_for(lang, "notify.err_unknown_type", type=ntype))


def send_with_retry(
    notification: dict[str, Any],
    secrets: dict[str, str],
    subject: str,
    body: str,
    retries: int = RETRY_TIMES,
    lang: str | None = None,
) -> tuple[bool, str]:
    last = ""
    for attempt in range(retries + 1):
        try:
            send_one(notification, secrets, subject, body, lang)
            return True, ""
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
            if attempt < retries:
                time.sleep(2**attempt)
    return False, last


def send_test(notification: dict[str, Any], secrets: dict[str, str]) -> tuple[bool, str]:
    lang = _default_lang()
    return send_with_retry(
        notification,
        secrets,
        subject="[" + _site_title() + "] " + i18n.t_for(lang, "notify.test_subject"),
        body=i18n.t_for(lang, "notify.test_body"),
        lang=lang,
    )


def send_all(
    notifications: list[dict[str, Any]],
    secrets: dict[str, str],
    summary: dict[str, Any],
    targets_label: str = "",
) -> list[dict[str, Any]]:
    """向全部启用通知按其语言发送；返回失败清单 [{"id","name","error"}]。

    Send to all enabled notifications, each in its own language.
    """
    failures: list[dict[str, Any]] = []
    for n in notifications:
        if not n.get("enabled", 1):
            continue
        lang = _default_lang()
        subject, body = build_alert(summary, targets_label, lang)
        ok, err = send_with_retry(n, secrets, subject, body, lang=lang)
        if not ok:
            failures.append({"id": n.get("id"), "name": n.get("name"), "error": err})
    return failures


def build_event(events: list, run_id: int, targets_label: str = "", lang: str | None = None) -> tuple[str, str]:
    """Build an event notification (oversize / ambiguity) in a language. 组装事件通知。"""
    lang = lang or _default_lang()
    subject = i18n.t_for(lang, "notify.event_subject", site=_site_title())
    lines = [i18n.t_for(lang, "notify.event_header")]
    for kind, n in events:
        if kind == "oversize":
            lines.append("- " + i18n.t_for(lang, "notify.event_oversize", n=n))
        elif kind == "ambiguous":
            lines.append("- " + i18n.t_for(lang, "notify.event_ambiguous", n=n))
    lines.append(i18n.t_for(lang, "notify.event_run", id=run_id))
    if targets_label:
        lines.append(i18n.t_for(lang, "notify.target_line", target=targets_label))
    return subject, "\n".join(lines)


def send_events(notifications: list[dict[str, Any]], secrets: dict[str, str], events: list,
                run_id: int, targets_label: str = "") -> list[dict[str, Any]]:
    """Send an event notification to all enabled notifications (default language)."""
    lang = _default_lang()
    subject, body = build_event(events, run_id, targets_label, lang)
    failures: list[dict[str, Any]] = []
    for n in notifications:
        if not n.get("enabled", 1):
            continue
        ok, err = send_with_retry(n, secrets, subject, body, lang=lang)
        if not ok:
            failures.append({"id": n.get("id"), "name": n.get("name"), "error": err})
    return failures


def build_alert(summary: dict[str, Any], targets_label: str = "", lang: str | None = None) -> tuple[str, str]:
    """由 run summary 组装聚合告警（按语言本地化应用/脚本名与固定文案）。"""
    lang = lang or _default_lang()
    s = _localize_summary_for(summary or {}, lang)
    status = s.get("status") or "unknown"
    status_label = i18n.t_for(lang, "status." + status, default=status)
    subject = i18n.t_for(lang, "notify.subject", site=_site_title(), status=status_label)
    if targets_label:
        subject += " - " + targets_label
    mode_label = i18n.t_for(lang, "notify.mode_raw" if s.get("mode") == "raw" else "notify.mode_model")
    issues = s.get("issues") or []
    lines = [
        i18n.t_for(lang, "notify.status_line", status=status_label),
        i18n.t_for(lang, "notify.mode_line", mode=mode_label),
        i18n.t_for(lang, "notify.target_line", target=targets_label or i18n.t_for(lang, "notify.target_all")),
        i18n.t_for(lang, "notify.time_line", start=models.local_str(s.get("started")), end=models.local_str(s.get("finished"))),
        i18n.t_for(lang, "notify.counts_line", servers=s.get("server_count", 0), errors=s.get("error_count", 0), issues=len(issues)),
        "",
        i18n.t_for(lang, "notify.issues_header"),
    ]
    if issues:
        by_app: dict[str, list[dict[str, Any]]] = {}
        for it in issues[:200]:
            by_app.setdefault(it.get("app") or i18n.t_for(lang, "reports2.unassigned"), []).append(it)
        for app, items in by_app.items():
            lines.append(i18n.t_for(lang, "notify.app_section", app=app))
            shown_sugg: set[str] = set()
            for it in items[:100]:
                st = i18n.t_for(lang, "status." + (it.get("status") or "").lower(), default=it.get("status") or "")
                head = i18n.t_for(lang, "notify.issue_head", status=st, server=it.get("server"), script=it.get("script"))
                if it.get("item"):
                    unit = it.get("unit") or ""
                    detail = i18n.t_for(lang, "notify.item_detail", item=it["item"], value=it.get("value") or "")
                    if unit:
                        detail += " " + unit
                    if it.get("threshold"):
                        detail += i18n.t_for(lang, "notify.item_threshold", threshold=it["threshold"])
                    if it.get("excess"):
                        detail += i18n.t_for(lang, "notify.item_excess", excess=it["excess"])
                    lines.append(head)
                    lines.append("    " + detail)
                else:
                    lines.append(head + i18n.t_for(lang, "notify.colon") + (it.get("message") or ""))
                sug = it.get("suggestion") or ""
                if sug and it.get("server") not in shown_sugg:
                    shown_sugg.add(it.get("server"))
                    lines.append("    " + i18n.t_for(lang, "notify.suggestion", suggestion=sug))
    else:
        lines.append(i18n.t_for(lang, "notify.no_issues"))
    if s.get("notify_failures"):
        lines.append("")
        lines.append(i18n.t_for(lang, "notify.notify_failed", info=s["notify_failures"]))
    return subject, "\n".join(lines)
