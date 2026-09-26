"""轻量多语言（i18n）：JSON 语言包，无第三方依赖。

- 内置语言包：`locales/*.json`（源语言 zh-CN + 示例 en）
- 用户语言包：`locales/custom/*.json`（覆盖同名 key，不入 git）
- key：语义英文，如 `nav.reports` / `common.save`
- 回退链：当前语言 → 默认语言(settings.default_language) → zh-CN → key 本身
- 加载：启动扫描；可 `reload()` 手动重载
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
from typing import Any

log = logging.getLogger(__name__)

BASE_LANG = "zh-CN"

_builtin_dir: str = ""
_custom_dir: str = ""
_locales: dict[str, dict[str, str]] = {}
_names: dict[str, str] = {}
_fallback: str = BASE_LANG
_cur: contextvars.ContextVar[str] = contextvars.ContextVar("lang", default=BASE_LANG)


def _scan(dirpath: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    if not dirpath or not os.path.isdir(dirpath):
        return out
    for fn in sorted(os.listdir(dirpath)):
        if fn.startswith("_") or not fn.endswith(".json"):
            continue
        code = fn[:-5]
        try:
            with open(os.path.join(dirpath, fn), encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                out[code] = {str(k): str(v) for k, v in data.items()}
        except Exception as exc:  # noqa: BLE001
            log.warning("语言包加载失败 %s: %s", fn, exc)
    return out


def init(builtin_dir: str, custom_dir: str) -> None:
    global _builtin_dir, _custom_dir
    _builtin_dir, _custom_dir = builtin_dir, custom_dir
    reload()


def reload() -> None:
    global _locales, _names
    merged: dict[str, dict[str, str]] = {}
    for d in (_builtin_dir, _custom_dir):
        for code, pack in _scan(d).items():
            merged.setdefault(code, {}).update(pack)  # custom 覆盖内置
    if BASE_LANG not in merged:
        merged[BASE_LANG] = {}
    _locales = merged
    _names = {code: (pack.get("language.name") or code) for code, pack in merged.items()}


def languages() -> list[dict[str, str]]:
    return [{"code": c, "name": _names.get(c, c)} for c in sorted(_locales.keys())]


def has(code: str) -> bool:
    return code in _locales


def set_fallback(code: str) -> None:
    global _fallback
    _fallback = code if code in _locales else BASE_LANG


def set_current(code: str) -> None:
    _cur.set(code if code in _locales else _fallback)


def current() -> str:
    return _cur.get()


def t(key: str, **kw: Any) -> str:
    for lang in (current(), _fallback, BASE_LANG):
        text = _locales.get(lang, {}).get(key)
        if text is not None:
            if kw:
                try:
                    return text.format(**kw)
                except (KeyError, IndexError, ValueError):
                    return text
            return text
    return key


def js_dict() -> dict[str, str]:
    """供前端注入的 JS 词条（key 以 `js.` 开头）。"""
    out: dict[str, str] = {}
    for lang in (_fallback, BASE_LANG, current()):
        for k, v in _locales.get(lang, {}).items():
            if k.startswith("js."):
                out[k] = v
    return out


def missing_keys(code: str) -> list[str]:
    base = set(_locales.get(BASE_LANG, {}))
    return sorted(base - set(_locales.get(code, {})))


def template_dict() -> dict[str, str]:
    """导出语言模板：以 zh-CN 原文为值。"""
    return dict(_locales.get(BASE_LANG, {}))
