"""通知适配器：SMTP / 钉钉统一接口。

- 每次 run 聚合为一条通知（状态汇总 + 异常清单）
- 多条通知可同时启用，告警时全部触发
- 发送失败重试 2 次，仍失败返回失败信息（由引擎写日志/审计/报告标注）
"""
from __future__ import annotations

import base64
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

import models

RETRY_TIMES = 2


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


def send_smtp(notification: dict[str, Any], secrets: dict[str, str], subject: str, body: str) -> None:
    cfg = _parse_json(notification.get("config_json"))
    password = secrets.get(notification.get("secret_env") or "SMTP_PASSWORD", "")
    host = cfg.get("host")
    port = int(cfg.get("port") or 465)
    from_addr = cfg.get("from") or cfg.get("from_addr") or ""
    to_addrs = cfg.get("to") or []
    if isinstance(to_addrs, str):
        to_addrs = [a.strip() for a in to_addrs.replace(";", ",").split(",") if a.strip()]
    if not host or not from_addr or not to_addrs:
        raise ValueError("SMTP 配置不完整（host/from/to 必填）")

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


def send_dingtalk(notification: dict[str, Any], secrets: dict[str, str], subject: str, body: str) -> None:
    cfg = _parse_json(notification.get("config_json"))
    webhook = cfg.get("webhook_url") or ""
    if not webhook:
        raise ValueError("钉钉配置缺少 webhook_url")
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
        raise ValueError(f"钉钉发送失败：{resp.status_code} {data}")


def send_one(notification: dict[str, Any], secrets: dict[str, str], subject: str, body: str) -> None:
    ntype = (notification.get("type") or "").lower()
    if ntype == "smtp":
        send_smtp(notification, secrets, subject, body)
    elif ntype == "dingtalk":
        send_dingtalk(notification, secrets, subject, body)
    else:
        raise ValueError(f"未知通知类型：{ntype}")


def send_with_retry(
    notification: dict[str, Any],
    secrets: dict[str, str],
    subject: str,
    body: str,
    retries: int = RETRY_TIMES,
) -> tuple[bool, str]:
    last = ""
    for attempt in range(retries + 1):
        try:
            send_one(notification, secrets, subject, body)
            return True, ""
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
            if attempt < retries:
                time.sleep(2**attempt)
    return False, last


def send_test(notification: dict[str, Any], secrets: dict[str, str]) -> tuple[bool, str]:
    return send_with_retry(
        notification,
        secrets,
        subject=f"[{_site_title()}] 通知连通性测试",
        body="这是一条来自 PyPiMeOps 的测试消息。收到即表示通知配置可用。",
    )


def send_all(
    notifications: list[dict[str, Any]],
    secrets: dict[str, str],
    subject: str,
    body: str,
) -> list[dict[str, Any]]:
    """向全部启用通知发送；返回失败清单 [{"id","name","error"}]。"""
    failures: list[dict[str, Any]] = []
    for n in notifications:
        if not n.get("enabled", 1):
            continue
        ok, err = send_with_retry(n, secrets, subject, body)
        if not ok:
            failures.append({"id": n.get("id"), "name": n.get("name"), "error": err})
    return failures


def build_alert(summary: dict[str, Any], targets_label: str = "") -> tuple[str, str]:
    """由 run summary 组装聚合告警（状态汇总 + 异常清单）。"""
    status = summary.get("status") or "unknown"
    subject = f"[{_site_title()}] 巡检告警（{status}）" + (f" - {targets_label}" if targets_label else "")
    mode_label = "模型分析" if summary.get("mode") != "raw" else "仅原始结果"
    lines = [
        f"巡检状态：{status}",
        f"分析模式：{mode_label}",
        f"目标：{targets_label or '全部所选对象'}",
        f"开始：{models.local_str(summary.get('started'))}  结束：{models.local_str(summary.get('finished'))}",
        f"服务器：{summary.get('server_count', 0)}  异常：{summary.get('error_count', 0)}  不确定：{summary.get('uncertain_count', 0)}",
        "",
        "异常清单：",
    ]
    issues = summary.get("issues") or []
    if issues:
        by_app: dict[str, list[dict[str, Any]]] = {}
        for it in issues[:200]:
            by_app.setdefault(it.get("app") or "未归属", []).append(it)
        for app, items in by_app.items():
            lines.append(f"【{app}】")
            for it in items[:100]:
                lines.append(f"- [{it.get('status')}] {it.get('server')} / {it.get('script')}: {it.get('message', '')}")
    else:
        lines.append("- （无）")
    if summary.get("notify_failures"):
        lines.append("")
        lines.append(f"告警发送失败：{summary['notify_failures']}")
    return subject, "\n".join(lines)
