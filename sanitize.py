"""敏感数据脱敏层（默认开启）。

- 内置规则 + 自定义增删（settings.sanitize_rules）
- 命中替换为占位符，返回命中摘要
- 仅作用于送模型的输入；reports/ 始终归档原始完整输出
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

import i18n

DEFAULT_RULES: list[dict[str, Any]] = [
    {"name": "private_key", "enabled": True, "pattern": r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"},
    {"name": "password", "enabled": True, "pattern": r"(?i)\b(password|passwd|pwd|pass)\b\s*[:=]\s*\S+"},
    {"name": "secret_token", "enabled": True, "pattern": r"(?i)\b(secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth)\b\s*[:=]\s*\S+"},
    {"name": "bearer", "enabled": True, "pattern": r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"},
    {"name": "aws_key", "enabled": True, "pattern": r"\bAKIA[0-9A-Z]{16}\b"},
    {"name": "jwt", "enabled": True, "pattern": r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"},
    {"name": "email", "enabled": True, "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"},
    {"name": "ipv4", "enabled": True, "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b"},
    {"name": "internal_host", "enabled": True, "pattern": r"\b[A-Za-z0-9_\-]+\.(?:internal|local|lan|corp|intra)\b"},
]


def default_rules() -> list[dict[str, Any]]:
    return [dict(r) for r in DEFAULT_RULES]


def _parse_rules(raw: str | None) -> list[dict[str, Any]]:
    if not raw:
        return default_rules()
    try:
        rules = json.loads(raw)
        if isinstance(rules, list) and rules:
            out = []
            for r in rules:
                if isinstance(r, dict) and r.get("pattern"):
                    out.append(
                        {
                            "name": r.get("name") or "custom",
                            "enabled": bool(r.get("enabled", True)),
                            "pattern": r["pattern"],
                        }
                    )
            return out or default_rules()
    except (ValueError, TypeError):
        pass
    return default_rules()


def _parse_overrides(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def sanitize(
    text: str,
    rules_raw: str | None = None,
    overrides_raw: str | None = None,
    enabled: bool = True,
) -> tuple[str, list[dict[str, Any]]]:
    """返回 (脱敏后文本, 命中摘要)。命中摘要：[{"name":.., "count":..}]"""
    if not enabled or not text:
        return text, []

    rules = _parse_rules(rules_raw)
    overrides = _parse_overrides(overrides_raw)
    disabled = set(overrides.get("disable") or [])
    extra = overrides.get("extra") or []

    active = [r for r in rules if r.get("enabled", True) and r["name"] not in disabled]
    for e in extra:
        if isinstance(e, dict) and e.get("pattern"):
            active.append({"name": e.get("name") or "custom", "pattern": e["pattern"]})

    result = text
    hits: list[dict[str, Any]] = []
    for rule in active:
        name = rule["name"]
        try:
            pattern = re.compile(rule["pattern"], re.MULTILINE)
        except re.error:
            continue
        result, count = pattern.subn(f"[REDACTED:{name}]", result)
        if count:
            hits.append({"name": name, "count": count})
    return result, hits


def summarize_hits(hits: Iterable[dict[str, Any]]) -> str:
    parts = [f"{h['name']}×{h['count']}" for h in hits]
    total = sum(int(h.get("count", 0)) for h in hits)
    if not parts:
        return i18n.t("sanitize.none")
    return i18n.t("sanitize.summary", total=total, parts="、".join(parts))
