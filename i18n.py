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


def parse_i18n(row: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Parse an object's i18n_json into {lang: {name, desc, meta_name, ...}}. 解析多语言字段。"""
    try:
        data = json.loads(row.get("i18n_json") or "{}")
    except (ValueError, TypeError):
        data = {}
    if not isinstance(data, dict):
        return {}
    return {str(k): v for k, v in data.items() if isinstance(v, dict)}


def _pick(ij: dict[str, Any], lang: str, key: str, base: str) -> str:
    """Fallback chain: requested lang -> en -> base literal. 回退链：当前 → en → 基座。"""
    for code in (lang, "en", BASE_LANG):
        entry = ij.get(code)
        if isinstance(entry, dict) and entry.get(key):
            return entry[key]
    return base


def localize_script(row: dict[str, Any], lang: str | None = None) -> tuple[str, str, str]:
    """Resolve a script's (name, desc, meta_name) for a language.

    Unified fallback: requested lang -> en -> base literal (name/desc; meta falls
    back to the base name, i.e. the script body `# NAME`).
    解析脚本展示名称/说明/元数据名：统一回退 当前 → en → 基座。
    """
    lang = lang or current()
    ij = parse_i18n(row)
    base_name = row.get("name") or ""
    base_desc = row.get("desc") or ""
    base_meta = row.get("meta_name") or base_name
    return (
        _pick(ij, lang, "name", base_name),
        _pick(ij, lang, "desc", base_desc),
        _pick(ij, lang, "meta_name", base_meta),
    )


def localize_item(row: dict[str, Any], key: str, lang: str | None = None) -> str:
    """Resolve an item display name from the script's per-language `items` map.

    按脚本 `i18n_json[lang].items[<key>]` 解析指标项展示名；缺失回退 key 本身。
    """
    lang = lang or current()
    key = str(key or "")
    if not key:
        return ""
    ij = parse_i18n(row)
    for code in (lang, "en", BASE_LANG):
        entry = ij.get(code)
        if isinstance(entry, dict):
            items = entry.get("items")
            if isinstance(items, dict) and items.get(key):
                return items[key]
    return key


def localize_named(row: dict[str, Any], lang: str | None = None) -> tuple[str, str]:
    """Resolve (name, desc) for config objects (applications/groups) via i18n_json.

    解析配置对象（应用/分组）名称与说明。
    """
    lang = lang or current()
    ij = parse_i18n(row)
    return (
        _pick(ij, lang, "name", row.get("name") or ""),
        _pick(ij, lang, "desc", row.get("desc") or ""),
    )


def tn(key: str, n: Any, **kw: Any) -> str:
    """Plural-aware translate: use `<key>.one`/`<key>.other` when present in the
    current language, else fall back to `t(key)`. 复数：当前语言有 `.one/.other` 时用之，否则回退。

    仅在**当前语言包**里找复数键，避免回退链跨语言串味。
    """
    try:
        plural_key = key + (".one" if int(n) == 1 else ".other")
    except (TypeError, ValueError):
        return t(key, n=n, **kw)
    text = _locales.get(current(), {}).get(plural_key)
    if text is not None:
        kw.setdefault("n", n)
        try:
            return text.format(**kw)
        except (KeyError, IndexError, ValueError):
            return text
    return t(key, n=n, **kw)


def t_for(lang: str, key: str, default: str | None = None, **kw: Any) -> str:
    """Translate a key for an explicit language (fallback: default → zh-CN → default/key).

    指定语言翻译（不回退到 zh-CN 之外），供通知等后台线程使用。
    """
    for code in (lang, _fallback, BASE_LANG):
        text = _locales.get(code, {}).get(key)
        if text is not None:
            if kw:
                try:
                    return text.format(**kw)
                except (KeyError, IndexError, ValueError):
                    return text
            return text
    return default if default is not None else key


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
