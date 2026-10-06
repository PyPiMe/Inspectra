"""执行引擎：连通采集、并发调度、模型分析、归档、告警。

约束：全局单 run 互斥（定时与手动统一）；引擎阈值/SSH 非零退出码为硬事实，优先于模型 status。
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any

import applog
import backup
import collectors
import i18n
import model_client
import models
import notify
import sanitize
import vault
from config import get_config

log = logging.getLogger("pypimeops.engine")

# Language-neutral marker for the "unassigned" application bucket (localized on display).
# 未归属应用桶的语言中立标记（展示时本地化）。
UNASSIGNED = "__unassigned__"

_run_lock = threading.Lock()
_current_run_id: int | None = None
_current_started: str | None = None

_progress_lock = threading.Lock()
_progress: dict[str, Any] = {}


def _set_progress(phase: str, label: str, done: int = 0, total: int = 0) -> None:
    with _progress_lock:
        _progress.clear()
        _progress.update({"phase": phase, "label": label, "done": int(done), "total": int(total)})


def _clear_progress() -> None:
    with _progress_lock:
        _progress.clear()


def get_progress() -> dict[str, Any]:
    with _progress_lock:
        return dict(_progress)


class RunBusy(RuntimeError):
    pass


class RunAborted(RuntimeError):
    pass


def is_running() -> bool:
    return _run_lock.locked()


def current_run_id() -> int | None:
    return _current_run_id


# ------------------------------------------------------------ 输出预处理/截断

_KEY_RE = re.compile(r"(ERROR|FAIL|CRIT|EXCEPTION|FATAL|WARN)", re.IGNORECASE)


def _collapse_repeats(lines: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(lines):
        j = i + 1
        while j < len(lines) and lines[j] == lines[i]:
            j += 1
        count = j - i
        out.append(f"{lines[i]} (×{count})" if count > 1 else lines[i])
        i = j
    return out


def preprocess_output(text: str, max_bytes: int) -> tuple[str, bool]:
    """送模型前的截断：重复行折叠 + 关键行保护 + 首尾保留（前60%/后40%）+ 整行对齐。"""
    if text is None:
        return "", False
    raw = text.encode("utf-8", "replace")
    if max_bytes <= 0 or len(raw) <= max_bytes:
        return text, False

    lines = _collapse_repeats(text.splitlines())
    key_lines = [ln for ln in lines if _KEY_RE.search(ln)]
    normal_lines = [ln for ln in lines if not _KEY_RE.search(ln)]

    head_budget = int(max_bytes * 0.6)
    tail_budget = max_bytes - head_budget

    def _take(items: list[str], budget: int) -> list[str]:
        acc: list[str] = []
        used = 0
        for ln in items:
            b = len(ln.encode("utf-8", "replace")) + 1
            if used + b > budget:
                break
            acc.append(ln)
            used += b
        return acc

    head = _take(key_lines + normal_lines, head_budget)
    tail_source = list(reversed(normal_lines + key_lines))
    tail = list(reversed(_take(tail_source, tail_budget)))
    omitted = max(0, len(lines) - len(head) - len(tail))
    body = "\n".join(head)
    if omitted:
        body += f"\n[... 省略 {omitted} 行 ...]\n"
    body += "\n".join(tail)
    return body, True


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


# ------------------------------------------------------------ 目标解析

def _load_maps() -> dict[str, dict[int, dict[str, Any]]]:
    maps: dict[str, dict[int, dict[str, Any]]] = {}
    for table in ("groups", "servers", "scripts", "datasources", "models", "notifications"):
        maps[table] = {int(r["id"]): r for r in models.fetch_all(table)}
    return maps


def _resolve_servers(targets: dict[str, Any], maps: dict[str, dict[int, dict[str, Any]]]) -> list[dict[str, Any]]:
    servers = maps["servers"]
    if targets.get("all"):
        chosen = [s for s in servers.values() if s.get("enabled", 1)]
    else:
        ids: set[int] = set()
        for sid in targets.get("servers", []) or []:
            ids.add(int(sid))
        for gid in targets.get("groups", []) or []:
            for s in servers.values():
                if int(s.get("group_id") or 0) == int(gid):
                    ids.add(int(s["id"]))
        app_ids = [int(x) for x in (targets.get("applications") or [])]
        if app_ids:
            amap = application_servers(maps)
            for aid in app_ids:
                ids.update(amap.get(aid, []))
        chosen = [servers[i] for i in ids if i in servers and servers[i].get("enabled", 1)]
    return sorted(chosen, key=lambda s: int(s["id"]))


def application_servers(maps: dict[str, dict[int, dict[str, Any]]] | None = None) -> dict[int, list[int]]:
    """应用 → 成员展开后的服务器 id 列表（服务器成员 + 分组成员展开）。

    Application id -> expanded member server ids (direct servers + group members).
    """
    maps = maps or _load_maps()
    servers = maps["servers"]
    grp: dict[int, list[int]] = {}
    for s in servers.values():
        gid = int(s.get("group_id") or 0)
        if gid:
            grp.setdefault(gid, []).append(int(s["id"]))
    out: dict[int, set[int]] = {}
    for m in models.fetch_all("application_members"):
        aid = int(m["application_id"])
        if m["member_type"] == "server":
            out.setdefault(aid, set()).add(int(m["member_id"]))
        elif m["member_type"] == "group":
            for sid in grp.get(int(m["member_id"]), []):
                out.setdefault(aid, set()).add(sid)
    return {k: sorted(v) for k, v in out.items()}


def _parse_ids(raw: Any) -> list[int]:
    try:
        val = json.loads(raw) if isinstance(raw, str) else (raw or [])
        return [int(x) for x in val if str(x).strip() not in ("", "None")]
    except (ValueError, TypeError):
        return []


def script_server_bindings(maps: dict[str, dict[int, dict[str, Any]]] | None = None) -> dict[int, list[int]]:
    """脚本 → 绑定服务器 id 列表（Shell：服务器 scripts_json；PromQL：启用绑定的 scripts_json）。

    Shell scripts → bound servers (server.scripts_json); PromQL scripts → servers of enabled bindings.
    """
    maps = maps or _load_maps()
    out: dict[int, set[int]] = {}
    for s in maps["servers"].values():
        sid = int(s["id"])
        for i in _parse_ids(s.get("scripts_json")):
            out.setdefault(i, set()).add(sid)
    for b in models.fetch_all("server_datasources"):
        if not b.get("enabled", 1):
            continue
        for i in _parse_ids(b.get("scripts_json")):
            out.setdefault(i, set()).add(int(b["server_id"]))
    return {k: sorted(v) for k, v in out.items()}


def _ip_instance_regex(ip: str) -> str:
    """由服务器 IP 推导 instance 正则：`192[.]168[.]4[.]34(:[0-9]+)?`（避免 PromQL 反斜杠转义）。"""
    ip = (ip or "").strip()
    safe = ip.replace(".", "[.]")
    return f"{safe}(:[0-9]+)?"


def _instance_selector(server: dict[str, Any], group: dict[str, Any] | None, binding: dict[str, Any],
                       datasource: dict[str, Any] | None = None) -> tuple[str, str]:
    """三层匹配：prom_instance → 组级+数据源+关联表 labels → servers.ip 推导。

    返回 (matcher 串, 来源)。matcher 用于替换脚本中的 `$instance`，可为多个匹配器（逗号分隔）。
    """
    explicit = (binding.get("prom_instance") or "").strip()
    if explicit:
        return collectors.instance_matcher(explicit), "explicit"
    labels: dict[str, str] = {}
    if group:
        try:
            labels.update(json.loads(group.get("prom_labels_json") or "{}"))
        except (ValueError, TypeError):
            pass
    if datasource:
        try:
            labels.update(json.loads(datasource.get("labels_json") or "{}"))
        except (ValueError, TypeError):
            pass
    try:
        labels.update(json.loads(binding.get("labels_json") or "{}"))
    except (ValueError, TypeError):
        pass
    if labels.get("instance"):
        return collectors.instance_matcher(str(labels["instance"])), "labels"
    if labels:
        # 组级/关联表标签存在但无 instance：以 ip 推导 instance，其余标签一并拼入 matcher
        parts = [f'{k}="{v}"' for k, v in labels.items()]
        parts.append(collectors.instance_matcher(_ip_instance_regex(server.get("ip") or "")))
        return ",".join(parts), "labels+ip"
    return collectors.instance_matcher(_ip_instance_regex(server.get("ip") or "")), "ip"


# ------------------------------------------------------------ 采集

def _run_ssh(server: dict[str, Any], script: dict[str, Any], content: str, settings: dict[str, str], secrets: dict[str, str]) -> collectors.CollectResult:
    if not int(server.get("port") or 0):
        return collectors.CollectResult(
            server_id=int(server["id"]),
            server_name=server.get("hostname") or server.get("ip"),
            source="ssh",
            script_id=int(script["id"]),
            script_name=collectors.script_display(script),
            kind="shell",
            status="ERROR",
            hard_fact=True,
            error=i18n.t("engine.err_no_ssh_port"),
        )
    try:
        with models.db() as conn:
            pem = vault.get_secret(conn, server.get("vault_key") or "")
    except Exception as exc:  # noqa: BLE001
        return collectors.CollectResult(
            server_id=int(server["id"]),
            server_name=server.get("hostname") or server.get("ip"),
            source="ssh",
            script_id=int(script["id"]),
            script_name=collectors.script_display(script),
            kind="shell",
            status="ERROR",
            hard_fact=True,
            error=i18n.t("engine.err_vault", err=exc),
        )
    collector = collectors.SSHCollector(
        connect_timeout=int(settings.get("ssh_connect_timeout", 10)),
        command_timeout=int(settings.get("ssh_command_timeout", 60)),
        known_hosts=get_config().known_hosts,
    )
    return collector.run(server, vault.normalize_pem(pem), content, script)


def _run_promql(
    server: dict[str, Any],
    script: dict[str, Any],
    content: str,
    binding: dict[str, Any],
    datasource: dict[str, Any],
    group: dict[str, Any] | None,
    secrets: dict[str, str],
) -> collectors.CollectResult:
    selector, _origin = _instance_selector(server, group, binding, datasource)
    collector = collectors.PrometheusCollector(datasource, secrets)

    def _fail(status: str, error: str) -> collectors.CollectResult:
        return collectors.CollectResult(
            server_id=int(server["id"]),
            server_name=server.get("hostname") or server.get("ip"),
            source="prometheus",
            script_id=int(script.get("id") or 0),
            script_name=collectors.script_display(script),
            kind="promql",
            status=status,
            hard_fact=(status == "ERROR"),
            error=error,
        )

    # 虚拟化标识：填 id 或名字；解析出 id，并在未显式指定 prom_instance 时用解析到的 exporter 去重
    guest_matcher: str | None = None
    # 仅在脚本确实使用 $guest 时才解析虚拟化标识（避免 keepalived 等脚本被 vm 解析牵连）
    vm = (server.get("vm_ident") or "").strip() if "$guest" in (content or "") else ""
    if vm:
        try:
            infos = collector.resolve_guest(vm)
        except Exception as exc:  # noqa: BLE001
            return _fail("ERROR", i18n.t("engine.err_vm_resolve", vm=vm, err=exc))
        ids = sorted({i["id"] for i in infos if i.get("id")})
        if not ids:
            return _fail("UNKNOWN", i18n.t("engine.err_vm_notfound", vm=vm))
        if len(ids) > 1:
            return _fail("UNKNOWN", i18n.t("engine.err_vm_multi", vm=vm, ids="、".join(ids)))
        gid = ids[0]
        guest_matcher = f'id="{collectors.promql_escape(gid)}"'
        explicit = (binding.get("prom_instance") or "").strip()
        if not explicit and _origin == "ip":
            insts = [i["instance"] for i in infos if i.get("id") == gid and i.get("instance")]
            if insts:
                selector = collectors.instance_matcher(insts[0])

    return collector.run(
        server, script, content, selector,
        check_instances="$instance" in (content or ""),
        guest_matcher=guest_matcher,
        auto_instance=(_origin in ("ip", "labels+ip")) and not guest_matcher,
    )


# ------------------------------------------------------------ 模型分析

def _system_prompt() -> str:
    """Model system prompt in the run language. 按运行语言返回模型系统提示词。"""
    return i18n.t("engine.system_prompt")


def _data_prefix() -> str:
    return i18n.t("engine.data_prefix")


def _data_suffix() -> str:
    return i18n.t("engine.data_suffix")


def _exceeding_text(r: collectors.CollectResult) -> str | None:
    """提取单条采集结果中「越界」的条目文本（WARN/FAIL）；无越界但有错误时回退错误。"""
    items = r.meta.get("items") or []
    lines: list[str] = []
    for it in items:
        if it.get("status") not in ("WARN", "FAIL"):
            continue
        unit = (it.get("unit") or r.meta.get("UNIT") or "").strip()
        lines.append(i18n.t(
            "report_md.exceed_line",
            status=_st(it.get("status")), script=r.script_name, item=it.get("name") or "",
            value=it.get("value"), unit=(" " + unit) if unit else "",
            threshold=it.get("threshold") or it.get("warn") or "-",
        ))
    if not lines and r.status in ("ERROR", "UNKNOWN") and r.error:
        lines.append(i18n.t("report_md.exceed_error", status=_st(r.status), script=r.script_name, err=r.error))
    return "\n".join(lines) if lines else None


def _analyze_batch(
    model: dict[str, Any],
    batch: list[dict[str, Any]],
    settings: dict[str, str],
    secrets: dict[str, str],
) -> dict[str, Any]:
    max_bytes = int(settings.get("model_output_max_bytes", 8192))
    batch_max = int(settings.get("model_batch_max_bytes", 32768))
    chunks: list[str] = []
    any_truncated = False
    for item in batch:
        out, truncated = preprocess_output(item["text"], max_bytes)
        any_truncated = any_truncated or truncated
        flag = " [truncated]" if truncated else ""
        chunks.append(f"### server_id={item['server_id']}{flag}\n{out}")
    data_text = "\n\n".join(chunks)
    if len(data_text.encode("utf-8", "replace")) > batch_max:
        data_text, _ = preprocess_output(data_text, batch_max)
        any_truncated = True

    messages = [
        {"role": "system", "content": _system_prompt()},
        {"role": "user", "content": _data_prefix() + data_text + _data_suffix()},
    ]
    content = model_client.analyze(
        model,
        messages,
        secrets,
        timeout=int(settings.get("model_request_timeout", 60)),
        retries=int(settings.get("model_retry_times", 2)),
    )
    parsed = model_client.extract_json(content)
    return {"raw": content, "parsed": parsed, "truncated": any_truncated}


# ------------------------------------------------------------ 报告

def _st(status: Any) -> str:
    """Status label in the current run language. 当前运行语言的状态标签。"""
    st = str(status or "")
    key = "status." + st.lower()
    val = i18n.t(key)
    return val if val != key else st


def _app_display(name: Any) -> str:
    """Display name for an app bucket (unassigned marker -> localized label). 应用展示名。"""
    if str(name) == UNASSIGNED:
        return i18n.t("reports2.unassigned")
    return str(name or "")


def _mode_label(mode: Any) -> str:
    m = str(mode or "")
    key = "mode." + m.lower()
    val = i18n.t(key)
    return val if val != key else m


def _source_label(source: Any) -> str:
    s = str(source or "")
    key = "source." + s.lower()
    val = i18n.t(key)
    return val if val != key else s


_META_KEYS = ("MODE", "WINDOW", "STEP", "THRESHOLD", "WARN", "UNIT", "DISPLAY")


def _fmt_human_value(item: str, val_str: str) -> str:
    """数值人话化：bytes→KB/MB/…；大整数加千分位；其余原样。"""
    try:
        v = float(val_str)
    except (ValueError, TypeError):
        return val_str
    low = (item or "").lower()
    if "bytes" in low or low.endswith("_bytes"):
        units = ["B", "KB", "MB", "GB", "TB", "PB"]
        i = 0
        while abs(v) >= 1024 and i < len(units) - 1:
            v /= 1024.0
            i += 1
        return f"{v:.1f} {units[i]}" if i > 0 else f"{int(v)} B"
    if v == int(v) and abs(v) >= 10000:
        return f"{int(v):,}"
    return val_str


def _excess_label(it: dict[str, Any]) -> str:
    """超限幅度：绝对差 +（数值有意义时）百分比。"""
    val = collectors._as_float(it.get("value"))
    cond = collectors.parse_condition(it.get("threshold") or "") or collectors.parse_condition(it.get("warn") or "")
    if val is None or not cond:
        return ""
    lim = collectors._as_float(cond[1])
    if lim is None:
        return ""
    delta = abs(val - lim)
    base = collectors._fmt_num(delta)
    if lim:
        return f"{base}（{delta / abs(lim) * 100:.1f}%）"
    return base


def _disp_value(it: dict[str, Any], default_unit: str = "") -> str:
    """统一人话模板的「值」列：值+单位；越界时附超限幅度。"""
    val = str(it.get("value", ""))
    unit = (it.get("unit") or default_unit or "").strip()
    if unit.lower() == "mixed":
        unit = ""
    shown = _fmt_human_value(it.get("name", ""), val)
    if unit:
        try:
            shown = f"{collectors._fmt_num(float(val))} {unit}"
        except (ValueError, TypeError):
            shown = f"{val} {unit}".strip()
    if it.get("status") in ("WARN", "FAIL"):
        lab = _excess_label(it)
        if lab:
            shown += i18n.t("report_md.item_over", v=lab)
    return shown


def _items_table(items: list[dict[str, Any]], default_unit: str = "") -> list[str]:
    header = "| " + " | ".join([
        i18n.t("report_md.th_item"), i18n.t("report_md.th_value"),
        i18n.t("report_md.th_threshold"), i18n.t("report_md.th_verdict"),
    ]) + " |"
    out = [header, "|----|----|------|------|"]
    for it in items:
        thr = it.get("threshold") or it.get("warn") or ""
        out.append(f"| {it.get('name', '-')} | {_disp_value(it, default_unit)} | {thr or '-'} | {_st(it.get('status'))} |")
    return out


def _is_bad_result(r: dict[str, Any]) -> bool:
    """异常结果：状态为 WARN/FAIL/ERROR/UNKNOWN 或带错误。"""
    return r.get("status") in ("WARN", "FAIL", "ERROR", "UNKNOWN") or bool(r.get("error"))


def _script_detail_lines(r: dict[str, Any]) -> list[str]:
    """单个脚本结果块（异常项或信息面板）。"""
    raw = r.get("output") or ""
    meta = r.get("meta") or {}
    out = [i18n.t("report_md.script", name=r["script_name"])]
    bits = [
        i18n.t("report_md.bit_status", status=_st(r["status"])),
        i18n.t("report_md.bit_source", source=_source_label(r["source"])),
    ]
    mode = (meta.get("MODE") or "").lower()
    if mode:
        bits.append(i18n.t("report_md.bit_mode", mode=_mode_label(mode)))
    unit = (meta.get("UNIT") or "").strip()
    if unit and unit.lower() != "mixed":
        bits.append(i18n.t("report_md.bit_unit", unit=unit))
    if meta.get("THRESHOLD"):
        bits.append(i18n.t("report_md.bit_threshold", threshold=meta["THRESHOLD"]))
    out.append("> " + i18n.t("report_md.bit_sep").join(bits))
    if r.get("advice"):
        out.append(i18n.t("report_md.advice", v=r["advice"]))
    if r.get("error"):
        out.append(i18n.t("report_md.error", err=r["error"]))
    hits = r.get("sanitize_hits") or ""
    if hits and hits != i18n.t("sanitize.none"):
        out.append(i18n.t("report_md.sanitize", hits=hits))
    out.append("")
    items = r.get("items") or []
    if items:
        out.extend(_items_table(items, unit))
    else:
        out.append("```text")
        out.append(raw.rstrip("\n"))
        out.append("```")
    return out


def _build_detail(app_groups: list[dict[str, Any]]) -> dict[str, Any]:
    """把应用/服务器/脚本/条目结构化，供报告详情页交互式渲染。"""
    apps: list[dict[str, Any]] = []
    for a in app_groups:
        servers: list[dict[str, Any]] = []
        for s in a["servers"]:
            results: list[dict[str, Any]] = []
            for r in s.get("results", []):
                items = r.get("items") or []
                meta = r.get("meta") or {}
                entry: dict[str, Any] = {
                    # script_id lets reports re-resolve the display name at view time.
                    # script_id 用于报告展示时按查看者语言重新解析脚本名。
                    "script_id": r.get("script_id") or 0,
                    "script": r.get("script_name") or "",
                    "source": r.get("source") or "",
                    "status": r.get("status") or "",
                    "error": r.get("error") or "",
                    "meta": {k: meta.get(k) for k in _META_KEYS if meta.get(k)},
                    "items": [
                        {
                            "key": it.get("key") or it.get("name") or "",
                            "name": it.get("name") or "",
                            "value": str(it.get("value", "")),
                            "unit": it.get("unit") or "",
                            "threshold": it.get("threshold") or it.get("warn") or "",
                            "status": it.get("status") or "",
                            "excess": _excess_label(it),
                        }
                        for it in items
                    ],
                }
                if not items:
                    entry["raw"] = (r.get("output") or "")[:4000]
                results.append(entry)
            servers.append(
                {
                    "server_id": s.get("id") or 0,
                    "name": s.get("name") or "",
                    "status": s.get("status") or "",
                    "attention": s.get("attention") or "",
                    "conclusion": s.get("conclusion") or "",
                    "consequence": s.get("consequence") or "",
                    "suggestion": s.get("suggestion") or "",
                    "skipped": bool(s.get("skipped")),
                    "results": results,
                }
            )
        apps.append({
            "application_id": a.get("application_id") or 0,
            "name": a["name"],
            "status": a["status"],
            "servers": servers,
        })
    return {"apps": apps}


def _report_markdown(ctx: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(i18n.t("report_md.title", site=ctx.get("site_title") or "PyPiMeOps", id=ctx["run_id"]))
    lines.append("")
    lines.append(i18n.t("report_md.trigger", trigger=ctx["trigger"]))
    lines.append(i18n.t("report_md.mode", mode=i18n.t("notify.mode_raw" if ctx.get("mode") == "raw" else "notify.mode_model")))
    lines.append(i18n.t("report_md.started", t=models.local_str(ctx["started"])))
    lines.append(i18n.t("report_md.finished", t=models.local_str(ctx["finished"])))
    try:
        _s = datetime.fromisoformat(ctx["started"])
        _f = datetime.fromisoformat(ctx["finished"])
        _sec = max(0, int((_f - _s).total_seconds()))
        lines.append(i18n.t("report_md.duration", t=(f"{_sec // 60}m{_sec % 60}s" if _sec >= 60 else f"{_sec}s")))
    except (ValueError, TypeError):
        pass
    if ctx.get("mode") != "raw":
        lines.append(i18n.t("report_md.policy", policy=ctx["policy"]))
    lines.append(i18n.t("report_md.targets", targets=ctx["targets_label"]))
    if ctx.get("selected_count") is not None:
        line = i18n.t("report_md.servers", selected=ctx["selected_count"], executed=ctx["executed_count"])
        if ctx.get("skipped_count"):
            line += i18n.t("report_md.skipped", skipped=ctx["skipped_count"])
        lines.append(line)
    app_groups = ctx.get("app_groups") or []

    def _bad_count(servers: list[dict[str, Any]]) -> int:
        return sum(1 for s in servers for r in s.get("results", []) if _is_bad_result(r))

    lines.append("")
    lines.append(i18n.t("report_md.summary_header"))
    lines.append("")
    lines.append("| " + " | ".join([
        i18n.t("report_md.th_app"), i18n.t("report_md.th_status"),
        i18n.t("report_md.th_servers"), i18n.t("report_md.th_issues"),
    ]) + " |")
    lines.append("|------|------|--------|------|")
    for a in app_groups:
        lines.append(f"| {_app_display(a['name'])} | {_st(a['status'])} | {len(a['servers'])} | {_bad_count(a['servers'])} |")
    lines.append("")
    lines.append(i18n.t("report_md.detail_header"))
    for a in app_groups:
        lines.append("")
        lines.append(i18n.t("report_md.app", name=_app_display(a["name"]), status=_st(a["status"])))
        lines.append("")
        lines.append("| " + " | ".join([
            i18n.t("report_md.th_servers"), i18n.t("report_md.th_status"), i18n.t("report_md.th_issues"),
        ]) + " |")
        lines.append("|--------|------|------|")
        for s in a["servers"]:
            n = _bad_count([s]) if s.get("results") else (1 if s.get("skipped") else 0)
            lines.append(f"| {s['name']} | {_st(s['status'])} | {n} |")
        for s in a["servers"]:
            lines.append("")
            lines.append(i18n.t("report_md.server", name=s["name"], status=_st(s["status"])))
            note = s.get("conclusion") or ""
            if note:
                lines.append(i18n.t("report_md.conclusion", v=note))
            if s.get("consequence"):
                lines.append(i18n.t("report_md.consequence", v=s["consequence"]))
            if s.get("suggestion"):
                lines.append(i18n.t("report_md.suggestion", v=s["suggestion"]))
            if s.get("attention"):
                lines.append(i18n.t("report_md.attention", v=s["attention"]))
            if not s["results"]:
                lines.append(i18n.t("report_md.skipped_note") if s.get("skipped") else i18n.t("report_md.no_result"))
                continue
            good: list[str] = []
            for r in s["results"]:
                if _is_bad_result(r) or collectors.is_display(r.get("meta") or {}):
                    lines.append("")
                    lines.extend(_script_detail_lines(r))
                else:
                    good.append(r["script_name"])
            if good:
                lines.append("")
                lines.append(i18n.t("report_md.other_ok", n=len(good), names="、".join(good)))
    if ctx.get("notify_failures"):
        lines.append("")
        lines.append(i18n.t("report_md.notify_failed", v=ctx["notify_failures"]))
    return "\n".join(lines) + "\n"


def _write_report(run_id: int, content: str) -> str:
    cfg = get_config()
    os.makedirs(cfg.reports_dir, exist_ok=True)
    now = datetime.now()
    fname = now.strftime("%Y%m%d_%H%M%S_") + f"{now.microsecond // 1000:03d}.md"
    path = os.path.join(cfg.reports_dir, fname)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return fname


# ------------------------------------------------------------ 主流程

def begin_scheduled(schedule_id: int) -> bool:
    """Acquire the run lock for a scheduled run and register last_fired_at on success.

    定时任务：非阻塞抢占全局 run 锁，**抢到才登记** last_fired_at；失败返回 False（不消耗本轮触发）。
    """
    if not _run_lock.acquire(blocking=False):
        return False
    try:
        with models.db() as conn:
            conn.execute("UPDATE run_schedule SET last_fired_at=? WHERE id=?", (models.utcnow(), int(schedule_id)))
    except Exception:  # noqa: BLE001
        _run_lock.release()
        raise
    return True


def run(
    targets: dict[str, Any],
    scripts: list[int] | None = None,
    trigger: str = "manual",
    schedule_id: int | None = None,
    operator_ip: str = "",
    mode: str = "model",
    lock_held: bool = False,
) -> dict[str, Any]:
    global _current_run_id, _current_started

    mode = (mode or "model").lower()
    if mode not in ("model", "raw"):
        mode = "model"

    i18n.set_current(models.get_setting("default_language", i18n.BASE_LANG))

    # lock_held=True：调用方（begin_scheduled）已持锁，避免二次加锁。
    if not lock_held:
        if not _run_lock.acquire(blocking=False):
            raise RunBusy(i18n.t("engine.err_busy"))

    started = models.utcnow()
    _current_started = started
    run_id = 0
    try:
        with models.db() as conn:
            run_id = models.insert(
                conn,
                "run_history",
                {
                    "started": started,
                    "schedule_id": schedule_id,
                    "trigger": trigger,
                    "mode": mode,
                    "targets_json": json.dumps(targets, ensure_ascii=False),
                    "scripts_json": json.dumps(scripts or [], ensure_ascii=False),
                    "status": "running",
                },
            )
            models.write_audit(conn, operator_ip, "run", "run", run_id, trigger, {"targets": targets, "scripts": scripts or [], "mode": mode})
        _current_run_id = run_id
        _set_progress("init", i18n.t("run.phase_init"), 0, 0)

        settings = models.get_settings()
        secrets = get_config().load_secrets()
        maps = _load_maps()

        # 应用映射：成员可含服务器或分组；一台服务器可归属多个应用；无归属进「未归属」
        _apps = {int(a["id"]): a for a in models.fetch_all("applications") if a.get("enabled", 1)}
        _group_servers: dict[int, set[int]] = {}
        for _s in maps["servers"].values():
            _gid = int(_s.get("group_id") or 0)
            if _gid:
                _group_servers.setdefault(_gid, set()).add(int(_s["id"]))
        # Store application ids (language-neutral); resolve names at view time.
        # 存应用 id（语言中立），展示时再按查看语言解析名称。
        app_names = {aid: a.get("name") or "" for aid, a in _apps.items()}
        server_apps: dict[int, list[int]] = {}
        for _m in models.fetch_all("application_members"):
            _app = _apps.get(int(_m["application_id"]))
            if not _app:
                continue
            if _m["member_type"] == "server":
                server_apps.setdefault(int(_m["member_id"]), []).append(int(_app["id"]))
            elif _m["member_type"] == "group":
                for _sid in _group_servers.get(int(_m["member_id"]), set()):
                    server_apps.setdefault(_sid, []).append(int(_app["id"]))

        # 模型分析模式必须有可用模型；仅原始结果模式不需要
        model = None
        if mode == "model":
            default_model_id = (settings.get("default_model") or "").strip()
            model = maps["models"].get(int(default_model_id)) if default_model_id.isdigit() else None
            if not model or not model.get("enabled", 1):
                raise RunAborted(i18n.t("engine.err_no_model"))

        servers = _resolve_servers(targets, maps)
        if not servers:
            raise RunAborted(i18n.t("engine.err_no_servers"))

        explicit = [maps["scripts"][i] for i in (scripts or []) if i in maps["scripts"]]
        explicit_shell = [s for s in explicit if (s.get("kind") or "shell") == "shell"]
        explicit_promql = [s for s in explicit if (s.get("kind") or "shell") == "promql"]

        ds_filter = set(int(x) for x in (targets.get("datasources") or []))
        bindings = models.fetch_all("server_datasources")
        binding_by_server: dict[int, list[dict[str, Any]]] = {}
        for b in bindings:
            # 保留全部绑定（含禁用），禁用与否在执行时判断：
            # 显式选择的 promql 脚本忽略绑定的 enabled/脚本列表（临时覆盖绑定）
            if ds_filter and int(b.get("datasource_id") or 0) not in ds_filter:
                continue
            binding_by_server.setdefault(int(b["server_id"]), []).append(b)

        # 构造采集任务
        tasks: list[dict[str, Any]] = []
        for server in servers:
            sid = int(server["id"])
            group = maps["groups"].get(int(server.get("group_id") or 0))
            shell_scripts = explicit_shell or [maps["scripts"][i] for i in _parse_ids(server.get("scripts_json")) if i in maps["scripts"]]
            for script in shell_scripts:
                content = backup.read_script(script)
                tasks.append({"type": "ssh", "server": server, "script": script, "content": content, "group": group})
            for binding in binding_by_server.get(sid, []):
                datasource = maps["datasources"].get(int(binding["datasource_id"]))
                if not datasource or not datasource.get("enabled", 1):
                    continue
                if explicit_promql:
                    prom_scripts = explicit_promql
                else:
                    if not binding.get("enabled", 1):
                        continue
                    prom_scripts = [maps["scripts"][i] for i in _parse_ids(binding.get("scripts_json")) if i in maps["scripts"]]
                for script in prom_scripts:
                    tasks.append(
                        {
                            "type": "promql",
                            "server": server,
                            "script": script,
                            "content": backup.read_script(script),
                            "binding": binding,
                            "datasource": datasource,
                            "group": group,
                        }
                    )

        concurrency = max(1, min(30, int(settings.get("concurrency", 10))))
        results: list[collectors.CollectResult] = []
        _set_progress("collect", i18n.t("run.phase_collect"), 0, len(tasks))
        collected = 0
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {}
            for task in tasks:
                if task["type"] == "ssh":
                    fut = pool.submit(_run_ssh, task["server"], task["script"], task["content"], settings, secrets)
                else:
                    fut = pool.submit(
                        _run_promql,
                        task["server"],
                        task["script"],
                        task["content"],
                        task["binding"],
                        task["datasource"],
                        task["group"],
                        secrets,
                    )
                futures[fut] = task
                time.sleep(random.uniform(0.05, 0.2))  # 批次间抖动，规避 MaxStartups 限流
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as exc:  # noqa: BLE001
                    task = futures[fut]
                    results.append(
                        collectors.CollectResult(
                            server_id=int(task["server"]["id"]),
                            server_name=task["server"].get("hostname") or task["server"].get("ip"),
                            source=task["type"],
                            script_id=int(task["script"]["id"]),
                            script_name=collectors.script_display(task["script"]),
                            kind=task["script"].get("kind") or "shell",
                            status="ERROR",
                            hard_fact=True,
                            error=i18n.t("engine.err_task", err=exc),
                        )
                    )
                collected += 1
                _set_progress("collect", i18n.t("run.phase_collect"), collected, len(tasks))

        # 脱敏 + 归档原始输出（仅模型分析模式需要脱敏）
        sanitize_enabled = str(settings.get("sanitize_enabled", "true")).lower() in ("1", "true", "yes")
        rules_raw = settings.get("sanitize_rules") or ""
        policy = settings.get("default_data_policy", "cloud")
        for r in results:
            r.meta["output"] = r.output
            r.meta["server_name"] = r.server_name
            if mode != "model":
                r.meta["sanitize_hits"] = []
                continue
            if (model.get("data_policy") or policy) == "local":
                r.meta["sanitized_output"] = r.output
                r.meta["sanitize_hits"] = []
            else:
                sanitized, hits = sanitize.sanitize(
                    r.output,
                    rules_raw,
                    model.get("sanitize_overrides"),
                    enabled=sanitize_enabled,
                )
                r.meta["sanitized_output"] = sanitized
                r.meta["sanitize_hits"] = hits

        # Localize script display names in the run language on the main thread
        # (worker threads don't inherit contextvars). 主线程按运行语言本地化脚本名。
        for r in results:
            _row = maps["scripts"].get(int(r.script_id or 0))
            if _row:
                r.script_name = collectors.script_display(_row)
                for it in (r.meta.get("items") or []):
                    _k = it.get("name") or ""
                    it["key"] = _k
                    it["name"] = i18n.localize_item(_row, _k)

        # PromQL instance ambiguity events (flag set by collectors). 实例歧义事件计数。
        ambiguous_hits = sum(1 for r in results if (r.meta or {}).get("ambiguous"))

        # 按服务器分组
        by_server: dict[int, list[collectors.CollectResult]] = {}
        for r in results:
            by_server.setdefault(r.server_id, []).append(r)

        # 模型分析（分批 + model_concurrency）；仅原始结果模式跳过
        model_concurrency = max(1, int(settings.get("model_concurrency", 3)))
        batch_size = max(5, min(10, int(settings.get("ssh_batch_size", 10))))
        batch_items: list[list[dict[str, Any]]] = []
        if mode == "model":
            use_local = (model.get("data_policy") or policy) == "local"
            flat = []
            for r in results:
                text = _exceeding_text(r)
                if not text:
                    continue
                if not use_local:
                    text, _hits = sanitize.sanitize(
                        text, rules_raw, model.get("sanitize_overrides"), enabled=sanitize_enabled
                    )
                flat.append({"server_id": r.server_id, "server_name": r.server_name, "text": text})
            for i in range(0, len(flat), batch_size):
                batch_items.append(flat[i : i + batch_size])

        model_results: dict[str, dict[str, Any]] = {}
        model_raw_chunks: list[str] = []
        model_errors: list[str] = []
        if mode == "model":
            _set_progress("model", i18n.t("run.phase_model"), 0, len(batch_items))
        analyzed = 0
        oversize_hits = 0
        if batch_items:
            with ThreadPoolExecutor(max_workers=model_concurrency) as pool:
                futs = [pool.submit(_analyze_batch, model, b, settings, secrets) for b in batch_items]
                for fut in as_completed(futs):
                    try:
                        res = fut.result()
                        if res.get("truncated"):
                            oversize_hits += 1
                        model_raw_chunks.append(res["raw"])
                        if res["parsed"]:
                            for k, v in res["parsed"].items():
                                if isinstance(v, dict):
                                    model_results[str(k)] = v
                        else:
                            model_errors.append(i18n.t("engine.err_model_json"))
                    except Exception as exc:  # noqa: BLE001
                        model_errors.append(str(exc))
                    analyzed += 1
                    _set_progress("model", i18n.t("run.phase_model"), analyzed, len(batch_items))

        # 回填与仲裁
        known_ids = set(str(r.server_id) for r in results)
        for extra in set(model_results) - known_ids:
            with models.db() as conn:
                models.write_audit(conn, operator_ip, "model_extra_id", "run", run_id, trigger, {"server_id": extra})

        servers_out: list[dict[str, Any]] = []
        issues: list[dict[str, Any]] = []
        error_count = 0
        skipped_count = 0
        for server in servers:
            sid = int(server["id"])
            rs = by_server.get(sid, [])
            app_ids = server_apps.get(sid) or []
            app_label = "、".join(app_names.get(i, f"#{i}") for i in app_ids) or UNASSIGNED
            server_name = server.get("hostname") or server.get("ip") or f"server-{sid}"
            if not rs:
                # 已选中但无可执行项（无 Shell 脚本、无启用的数据源绑定）
                skipped_count += 1
                servers_out.append(
                    {
                        "id": sid,
                        "name": server_name,
                        "status": "UNKNOWN",
                        "engine_status": "UNKNOWN",
                        "attention": "",
                        "conclusion": i18n.t("engine.skipped_note"),
                        "consequence": "",
                        "suggestion": "",
                        "skipped": True,
                        "results": [],
                    }
                )
                continue
            # 服务器状态 = 引擎硬事实（模型不决定状态）
            engine_status = collectors.aggregate_status([r.status for r in rs])
            m = model_results.get(str(sid)) or {}
            if collectors.severity_rank(engine_status) >= collectors.severity_rank("FAIL"):
                error_count += 1
            # 问题清单：逐条越界项（WARN/FAIL）或采集错误
            for r in rs:
                hit = False
                for it in r.meta.get("items") or []:
                    st = it.get("status")
                    if st not in ("WARN", "FAIL"):
                        continue
                    hit = True
                    unit = (it.get("unit") or r.meta.get("UNIT") or "").strip()
                    issues.append(
                        {
                            "status": st,
                            "app": app_label,
                            "app_ids": list(app_ids),
                            "server": server_name,
                            "server_id": sid,
                            "script_id": int(r.script_id or 0),
                            "script": r.script_name,
                            "item": it.get("name") or "",
                            "item_key": it.get("key") or it.get("name") or "",
                            "value": str(it.get("value", "")),
                            "unit": unit,
                            "threshold": it.get("threshold") or it.get("warn") or "",
                            "excess": _excess_label(it),
                            "message": "",
                            "suggestion": m.get("suggestion") or "",
                        }
                    )
                if not hit and r.status in ("ERROR", "UNKNOWN") and r.error:
                    issues.append(
                        {
                            "status": r.status,
                            "app": app_label,
                            "app_ids": list(app_ids),
                            "server": server_name,
                            "server_id": sid,
                            "script_id": int(r.script_id or 0),
                            "script": r.script_name,
                            "item": "",
                            "value": "",
                            "unit": "",
                            "threshold": "",
                            "excess": "",
                            "message": r.error,
                            "suggestion": m.get("suggestion") or "",
                        }
                    )
            servers_out.append(
                {
                    "id": sid,
                    "name": server_name,
                    "status": engine_status,
                    "engine_status": engine_status,
                    "attention": m.get("attention") or "",
                    "conclusion": m.get("conclusion") or "",
                    "consequence": m.get("consequence") or "",
                    "suggestion": m.get("suggestion") or "",
                    "skipped": False,
                    "results": [
                        {
                            "source": r.source,
                            "script_id": int(r.script_id or 0),
                            "script_name": r.script_name,
                            "status": r.status,
                            "error": r.error,
                            "output": r.meta.get("output", r.output),
                            "sanitize_hits": sanitize.summarize_hits(r.meta.get("sanitize_hits", [])),
                            "items": r.meta.get("items") or [],
                            "meta": {k: r.meta.get(k) for k in _META_KEYS},
                            # Author advice, localized in the run language for the archived .md
                            # (not persisted in detail_json; re-resolved at view time).
                            # 作者建议（按运行语言，用于归档 .md；不入 detail_json，查看时再解析）。
                            "advice": i18n.localize_advice(
                                maps["scripts"].get(int(r.script_id or 0)) or {},
                                base=(r.meta or {}).get("ADVICE") or "",
                            ),
                        }
                        for r in rs
                    ],
                }
            )

        finished = models.utcnow()
        statuses = [s["status"] for s in servers_out]
        if any(collectors.severity_rank(s) >= collectors.severity_rank("FAIL") for s in statuses):
            run_status = "partial" if any(s == "OK" for s in statuses) else "error"
        else:
            run_status = "success"

        targets_label = "、".join(s["name"] for s in servers_out[:5]) + ("…" if len(servers_out) > 5 else "")
        # Bucket by application id (None = unassigned); names resolved at view time.
        # 按应用 id 分桶（None=未归属），名称展示时解析。
        _app_buckets: dict[Any, list[dict[str, Any]]] = {}
        for s in servers_out:
            ids = server_apps.get(int(s["id"])) or []
            if not ids:
                _app_buckets.setdefault(None, []).append(s)
            else:
                for aid in ids:
                    _app_buckets.setdefault(aid, []).append(s)
        app_groups = [
            {
                "application_id": aid or 0,
                "name": app_names.get(aid, UNASSIGNED) if aid else UNASSIGNED,
                "servers": _app_buckets[aid],
                "status": collectors.aggregate_status([x["status"] for x in _app_buckets[aid]]),
            }
            for aid in sorted(_app_buckets, key=lambda x: (x is None, x if x is not None else 0))
        ]
        summary = {
            "status": run_status,
            "mode": mode,
            "started": started,
            "finished": finished,
            "targets_label": targets_label,
            "server_count": len(servers_out),
            "selected_count": len(servers),
            "executed_count": len(servers_out) - skipped_count,
            "skipped_count": skipped_count,
            "error_count": error_count,
            "uncertain_count": 0,
            "issues": issues,
            "model_errors": model_errors,
            "apps": [
                {"id": a.get("application_id") or 0, "name": a["name"], "status": a["status"], "server_count": len(a["servers"])}
                for a in app_groups
            ],
        }
        ctx = {
            "run_id": run_id,
            "trigger": trigger,
            "mode": mode,
            "started": started,
            "finished": finished,
            "policy": policy,
            "targets_label": targets_label,
            "site_title": (settings.get("site_title") or "").strip() or "PyPiMeOps",
            "servers": servers_out,
            "app_groups": app_groups,
            "selected_count": len(servers),
            "executed_count": len(servers_out) - skipped_count,
            "skipped_count": skipped_count,
        }
        _set_progress("report", i18n.t("run.phase_report"), 0, 1)
        report = _report_markdown(ctx)
        report_file = _write_report(run_id, report)
        _set_progress("report", i18n.t("run.phase_report"), 1, 1)

        # 告警：ERROR/连接失败/命令异常/partial；WARN 受开关控制
        should_notify = False
        if error_count or run_status == "partial":
            should_notify = True
        if statuses and all(s == "WARN" for s in statuses) and str(settings.get("warn_push_enabled", "true")).lower() in ("1", "true", "yes"):
            should_notify = True
        notify_failures: list[dict[str, Any]] = []
        if should_notify:
            notifications = [n for n in maps["notifications"].values() if n.get("enabled", 1)]
            if notifications:
                notify_failures = notify.send_all(notifications, secrets, summary, targets_label)
                if notify_failures:
                    log.error("告警发送失败：%s", notify_failures)
                    with models.db() as conn:
                        models.write_audit(conn, operator_ip, "notify_failed", "run", run_id, trigger, notify_failures, "error")
            else:
                # 无启用通知：仅日志落盘
                subject, body = notify.build_alert(summary, targets_label)
                log.warning("告警（未启用通知，仅日志）：%s\n%s", subject, body)

        # Event notifications (independent switches): output oversize / instance ambiguity.
        # 事件通知（独立开关）：输出超限 / 实例歧义。
        def _on(key: str) -> bool:
            return str(settings.get(key, "true")).lower() in ("1", "true", "yes")

        events: list[tuple[str, int]] = []
        if oversize_hits and _on("notify_oversize_enabled"):
            events.append(("oversize", oversize_hits))
        if ambiguous_hits and _on("notify_ambiguous_enabled"):
            events.append(("ambiguous", ambiguous_hits))
        if events:
            ev_notifications = [n for n in maps["notifications"].values() if n.get("enabled", 1)]
            if ev_notifications:
                ev_fail = notify.send_events(ev_notifications, secrets, events, run_id, targets_label)
                with models.db() as conn:
                    models.write_audit(conn, operator_ip, "notify_event", "run", run_id, trigger,
                                       {"events": events, "failures": ev_fail}, "error" if ev_fail else "ok")
            else:
                log.warning("事件（未启用通知，仅日志）：%s", events)

        with models.db() as conn:
            conn.execute(
                "UPDATE run_history SET finished=?, status=?, policy=?, sanitize_hits=?, summary=?, issue_count=?, report_file=? WHERE id=?",
                (
                    finished,
                    run_status,
                    policy,
                    json.dumps(summary, ensure_ascii=False),
                    json.dumps(summary, ensure_ascii=False),
                    len(issues),
                    report_file,
                    run_id,
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO run_results (run_id, detail_json, created_at) VALUES (?,?,?)",
                (run_id, json.dumps(_build_detail(app_groups), ensure_ascii=False), finished),
            )
        summary["notify_failures"] = notify_failures
        summary["report_file"] = report_file
        summary["run_id"] = run_id
        return summary
    except Exception as exc:  # noqa: BLE001
        if run_id:
            with models.db() as conn:
                conn.execute(
                    "UPDATE run_history SET finished=?, status=?, error=? WHERE id=?",
                    (models.utcnow(), "error", str(exc), run_id),
                )
        log.exception("run 失败")
        raise
    finally:
        _current_run_id = None
        _current_started = None
        _clear_progress()
        _run_lock.release()


def cleanup_retention() -> dict[str, int]:
    settings = models.get_settings()
    return {
        "audit": models.cleanup_audit(int(settings.get("audit_retention_days", 90))),
        "backups": backup.cleanup(int(settings.get("backup_retention_days", 90))),
        "app_logs": applog.cleanup(days=int(settings.get("app_log_retention_days", 7)))["deleted"],
    }
