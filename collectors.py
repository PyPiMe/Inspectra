"""采集器抽象：SSHCollector(paramiko) / PrometheusCollector(HTTP)。

统一返回 CollectResult，供引擎做阈值仲裁、脱敏、模型分析与归档。
"""
from __future__ import annotations

import io
import os
import re
from dataclasses import dataclass, field
from typing import Any

import i18n
import requests

SEVERITY = {"OK": 0, "UNKNOWN": 1, "WARN": 2, "FAIL": 3, "ERROR": 4}


def severity_rank(status: str) -> int:
    return SEVERITY.get((status or "UNKNOWN").upper(), 1)


def script_display(script: dict[str, Any]) -> str:
    """Localized script display name in the current run language. 按运行语言解析脚本展示名。"""
    try:
        return i18n.localize_script(script)[0] or (script.get("name") or "")
    except Exception:  # noqa: BLE001
        return script.get("name") or ""


def aggregate_status(statuses: list[str]) -> str:
    """服务器状态聚合：最高严重级（ERROR > FAIL > WARN > UNKNOWN > OK）。"""
    if not statuses:
        return "UNKNOWN"
    return max(statuses, key=severity_rank).upper()


@dataclass
class CollectResult:
    server_id: int
    server_name: str
    source: str
    script_id: int
    script_name: str
    kind: str
    status: str
    output: str = ""
    error: str = ""
    hard_fact: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "server_name": self.server_name,
            "source": self.source,
            "script_id": self.script_id,
            "script_name": self.script_name,
            "kind": self.kind,
            "status": self.status,
            "output": self.output,
            "error": self.error,
            "hard_fact": self.hard_fact,
            "meta": self.meta,
        }


# ------------------------------------------------------------------ 元数据解析

_DUR_RE = re.compile(r"^(\d+)([smhd])$")


def parse_duration(text: str) -> int | None:
    text = (text or "").strip()
    m = _DUR_RE.match(text)
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def parse_script_meta(content: str) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "NAME": "", "MODE": "instant", "WINDOW": "", "STEP": "1m",
        "THRESHOLD": "", "WARN": "", "UNIT": "", "DISPLAY": "",
    }
    for line in (content or "").splitlines():
        s = line.strip()
        if not s.startswith("#"):
            continue
        s = s.lstrip("#").strip()
        if ":" not in s:
            continue
        key, _, val = s.partition(":")
        key = key.strip().upper()
        if key in meta:
            meta[key] = val.strip()
    return meta


_NUM_CMP_RE = re.compile(r"^\s*(>=|<=|==|!=|>|<)\s*(-?\d+(?:\.\d+)?)\s*$")
_STR_CMP_RE = re.compile(r"^\s*(==|!=)\s*(\S+)\s*$")
_ITEM_MODS = ("threshold", "warn", "unit")


def parse_condition(text: str) -> tuple[str, str] | None:
    """解析阈值条件：数值比较（>90）或字符串比较（!=active）。"""
    m = _NUM_CMP_RE.match(text or "")
    if m:
        return m.group(1), m.group(2)
    m = _STR_CMP_RE.match(text or "")
    if m:
        return m.group(1), m.group(2)
    return None


def parse_threshold(text: str) -> tuple[str, float] | None:
    """兼容旧接口：仅数值阈值。"""
    m = _NUM_CMP_RE.match(text or "")
    if not m:
        return None
    return m.group(1), float(m.group(2))


def _as_float(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def eval_condition(op: str, limit: str, value: str) -> bool:
    """判断 value 是否越界（True=越界）。数值优先，否则字符串相等/不等。"""
    lf, vf = _as_float(limit), _as_float(value)
    if lf is not None and vf is not None:
        return {
            ">": vf > lf, ">=": vf >= lf, "<": vf < lf,
            "<=": vf <= lf, "==": vf == lf, "!=": vf != lf,
        }.get(op, False)
    if op == "==":
        return str(value) == str(limit)
    if op == "!=":
        return str(value) != str(limit)
    return False


def eval_threshold(op: str, limit: float, value: float) -> bool:
    """兼容旧接口：数值阈值判定。"""
    return eval_condition(op, str(limit), str(value))


def condition_label(op: str, limit: str) -> str:
    return f"{op}{limit}"


def is_display(meta: dict[str, Any]) -> bool:
    """`# DISPLAY: true` 表示仅展示、不判定。"""
    return str((meta or {}).get("DISPLAY") or "").strip().lower() in ("1", "true", "yes", "on")


def parse_items(output: str) -> list[dict[str, Any]]:
    """把结构化输出解析为条目。

    - PromQL：`<instance> item=<名> threshold=>90 = <值>`（修饰符从标签提取，`item` 作名称）
    - Shell：`key=value [threshold=>90] [warn=>80] [unit=%]`，一行可含多对
    """
    items: list[dict[str, Any]] = []
    for line in (output or "").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # PromQL 风格：`... = <值>`（等号两侧有空格；label 可为空）
        m = re.match(r"^\s*(?P<left>.*?)\s+=\s+(?P<val>\S+)\s*$", line)
        if m:
            mods: dict[str, str] = {}
            item_name = ""
            inst = ""
            others: list[str] = []
            for t in m.group("left").split():
                if "=" in t:
                    k, _, v = t.partition("=")
                    if k in _ITEM_MODS:
                        mods[k] = v
                    elif k == "item":
                        item_name = v
                    else:
                        others.append(v)
                else:
                    inst = t
            name = item_name or " ".join(others) or inst or "-"
            items.append({"name": name, "value": m.group("val"), **mods})
            continue
        s = line.strip()
        mods = {}
        pairs: list[tuple[str, str]] = []
        for tok in s.split():
            if "=" not in tok:
                continue
            k, _, v = tok.partition("=")
            if k in _ITEM_MODS:
                mods[k] = v
            else:
                pairs.append((k, v))
        for k, v in pairs:
            items.append({"name": k, "value": v, **mods})
    return items


def evaluate(output: str, meta: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """通用求值：解析条目并按 CRIT/WARN 阈值判定，返回 (整体状态, 条目列表)。

    - `DISPLAY: true` → 仅展示（条目 INFO、整体 OK）
    - 每条目可用行内 `threshold=`/`warn=` 覆盖头部
    - 整体状态 = 各条目最高严重级（FAIL > WARN > OK）
    """
    meta = meta or {}
    display = is_display(meta)
    items = parse_items(output)
    if not items:
        return ("OK" if display else "UNKNOWN"), []
    crit = parse_condition(meta.get("THRESHOLD") or "")
    warn = parse_condition(meta.get("WARN") or "")
    overall = "OK"
    for it in items:
        if display:
            it["status"] = "INFO"
            continue
        t = parse_condition(it.get("threshold") or "") or crit
        w = parse_condition(it.get("warn") or "") or warn
        if t:
            it["threshold"] = condition_label(*t)
        if w:
            it["warn"] = condition_label(*w)
        if t and eval_condition(t[0], t[1], it["value"]):
            it["status"] = "FAIL"
        elif w and eval_condition(w[0], w[1], it["value"]):
            it["status"] = "WARN"
        else:
            it["status"] = "OK"
        if severity_rank(it["status"]) > severity_rank(overall):
            overall = it["status"]
    return overall, items


def meta_warnings(content: str, kind: str = "promql") -> list[str]:
    """元数据警告（不阻断保存）：NAME 必填；THRESHOLD 建议；纯信息类用 DISPLAY 豁免。"""
    meta = parse_script_meta(content)
    if is_display(meta):
        return []
    warns: list[str] = []
    if not meta.get("NAME"):
        warns.append(i18n.t("meta.warn_name"))
    if not meta.get("THRESHOLD"):
        warns.append(i18n.t("meta.warn_threshold"))
    if not meta.get("UNIT"):
        warns.append(i18n.t("meta.warn_unit"))
    return warns


def validate_promql(content: str) -> list[str]:
    """校验 promql 头部元数据，返回错误列表（空=通过）。"""
    errors: list[str] = []
    meta = parse_script_meta(content)
    if not meta["NAME"]:
        errors.append(i18n.t("meta.err_name"))
    mode = (meta["MODE"] or "instant").lower()
    if mode not in ("instant", "range"):
        errors.append(i18n.t("meta.err_mode"))
    if mode == "range":
        if not meta["WINDOW"] or parse_duration(meta["WINDOW"]) is None:
            errors.append(i18n.t("meta.err_window"))
        if meta["STEP"] and parse_duration(meta["STEP"]) is None:
            errors.append(i18n.t("meta.err_step"))
    for key in ("THRESHOLD", "WARN"):
        if meta.get(key) and parse_condition(meta[key]) is None:
            errors.append(i18n.t("meta.err_condition", key=key))
    return errors


def extract_query(content: str) -> str:
    """去掉头部元数据注释（`#` 开头）与空行，得到真正的 PromQL 查询语句。"""
    return "\n".join(ln for ln in (content or "").splitlines() if not ln.lstrip().startswith("#")).strip()


def promql_escape(value: str) -> str:
    """把正则安全嵌入 PromQL 双引号字符串：反斜杠需写成 `\\\\`、双引号转义。

    PromQL 词法器只接受有限转义（`\\\\`、`\\"`、`\\n` 等），`\\.`/`\\d` 会报 unknown escape，
    因此必须先把正则里的反斜杠加倍，交给 RE2 解释。
    """
    return (value or "").replace("\\", "\\\\").replace('"', '\\"')


def instance_matcher(regex: str) -> str:
    """构造 `instance=~"<regex>"` 匹配器（已做 PromQL 转义）。"""
    return f'instance=~"{promql_escape(regex)}"'


def inject_instance(content: str, matcher: str | None) -> str:
    """把 `$instance` 占位符替换为给定的匹配器串（可为多个匹配器，逗号分隔）。"""
    if not matcher:
        return content
    return content.replace("$instance", matcher)


def _prom_error(resp) -> str:
    """从 Prometheus 响应中提取错误信息。"""
    try:
        data = resp.json()
        if isinstance(data, dict) and data.get("error"):
            return str(data["error"])
    except (ValueError, TypeError):
        pass
    return (resp.text or "").strip()[:300]


def _fmt_num(v: float) -> str:
    """数值可读化：整数不带 .0；浮点最多保留 4 位小数并去尾零。"""
    try:
        if v == int(v) and abs(v) < 1e15:
            return str(int(v))
    except (ValueError, OverflowError):
        pass
    return f"{round(v, 4):g}"



# ------------------------------------------------------------------ SSH 采集

def _load_pkey(pem: bytes):
    import paramiko

    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey, paramiko.DSSKey):
        try:
            return cls.from_private_key(io.StringIO(pem.decode("utf-8")))
        except Exception:  # noqa: BLE001
            continue
    raise ValueError(i18n.t("collect.err_pem"))


class SSHCollector:
    def __init__(self, connect_timeout: int = 10, command_timeout: int = 60, known_hosts: str | None = None):
        self.connect_timeout = int(connect_timeout)
        self.command_timeout = int(command_timeout)
        self.known_hosts = known_hosts

    def _client(self):
        import paramiko

        client = paramiko.SSHClient()
        if self.known_hosts and os.path.isfile(self.known_hosts):
            client.load_host_keys(self.known_hosts)
        # TOFU：缺失主机密钥自动信任，密钥变更由 paramiko 抛 BadHostKeyException 阻断
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return client

    def run(
        self,
        server: dict[str, Any],
        private_key: bytes,
        command: str,
        script: dict[str, Any],
    ) -> CollectResult:
        import paramiko

        sid = int(server["id"])
        sname = server.get("hostname") or server.get("ip") or f"server-{sid}"
        base = CollectResult(
            server_id=sid,
            server_name=sname,
            source="ssh",
            script_id=int(script.get("id") or 0),
            script_name=script.get("name") or "",
            kind="shell",
            status="UNKNOWN",
        )
        client = self._client()
        stdin = stdout = stderr = None
        try:
            pkey = _load_pkey(private_key)
            client.connect(
                hostname=server.get("ip") or server.get("hostname"),
                port=int(server.get("port") or 22),
                username=server.get("user") or "",
                pkey=pkey,
                timeout=self.connect_timeout,
                banner_timeout=self.connect_timeout,
                auth_timeout=self.connect_timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            if self.known_hosts:
                try:
                    os.makedirs(os.path.dirname(self.known_hosts) or ".", exist_ok=True)
                    client.get_host_keys().save(self.known_hosts)
                except OSError:
                    pass
            stdin, stdout, stderr = client.exec_command(command, timeout=self.command_timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            code = stdout.channel.recv_exit_status()
            base.output = out
            if code != 0:
                base.status = "ERROR"
                base.hard_fact = True
                base.error = i18n.t("collect.cmd_exit", code=code) + (i18n.t("collect.cmd_exit_err", err=err.strip()) if err.strip() else "")
            else:
                base.status = "OK"
                if err.strip():
                    base.output = out + ("\n" if out and not out.endswith("\n") else "") + f"[stderr]\n{err}"
                base.meta = parse_script_meta(command)
                status, items = evaluate(base.output, base.meta)
                if items:
                    base.status = status
                    base.hard_fact = status == "FAIL"
                    base.meta["items"] = items
        except paramiko.BadHostKeyException:
            base.status = "ERROR"
            base.hard_fact = True
            base.error = i18n.t("collect.err_hostkey")
        except paramiko.AuthenticationException:
            base.status = "ERROR"
            base.hard_fact = True
            base.error = i18n.t("collect.err_auth")
        except Exception as exc:  # noqa: BLE001
            base.status = "ERROR"
            base.hard_fact = True
            base.error = i18n.t("collect.err_ssh_exc", err=exc)
        finally:
            # 先关闭通道文件，再关客户端：避免 close 后 ChannelFile.__del__ 向已断开的
            # transport 发送 EOF 而抛出 "'NoneType' object has no attribute 'time'"
            for fh in (stdin, stdout, stderr):
                try:
                    if fh is not None:
                        fh.close()
                except Exception:  # noqa: BLE001
                    pass
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass
        return base


# ------------------------------------------------------------------ Prometheus 采集

class PrometheusCollector:
    def __init__(self, datasource: dict[str, Any], secrets: dict[str, str] | None = None):
        self.ds = datasource
        self.secrets = secrets or {}
        self.timeout = int(datasource.get("timeout") or 10)
        self.verify = bool(datasource.get("verify_tls", 1))

    def _auth(self):
        auth_type = (self.ds.get("auth_type") or "none").lower()
        if auth_type == "none":
            return None, {}
        secret = self.secrets.get(self.ds.get("secret_env") or "", "")
        if not secret:
            raise ValueError(i18n.t("collect.err_no_secret", env=self.ds.get("secret_env")))
        if auth_type == "basic":
            user, _, pwd = secret.partition(":")
            return (user, pwd), {}
        if auth_type == "bearer":
            return None, {"Authorization": f"Bearer {secret}"}
        return None, {}

    def test_connection(self) -> tuple[bool, str]:
        base = (self.ds.get("base_url") or "").rstrip("/")
        try:
            auth, headers = self._auth()
            resp = requests.get(
                f"{base}/api/v1/status/config",
                auth=auth,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify,
            )
            if resp.status_code == 200 and resp.json().get("status") == "success":
                return True, i18n.t("collect.conn_ok")
            return False, f"HTTP {resp.status_code}"
        except Exception as exc:  # noqa: BLE001
            return False, i18n.t("collect.conn_fail", err=exc)

    def list_label_values(self, label: str, limit: int = 200) -> list[str]:
        """拉取某标签的全部取值（如 job / instance），用于表单下拉。"""
        base = (self.ds.get("base_url") or "").rstrip("/")
        auth, headers = self._auth()
        resp = requests.get(
            f"{base}/api/v1/label/{label}/values",
            auth=auth, headers=headers, timeout=self.timeout, verify=self.verify,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}")
        payload = resp.json()
        if payload.get("status") != "success":
            raise RuntimeError(str(payload.get("error")))
        vals = [str(v) for v in (payload.get("data") or [])]
        return vals[:limit]

    def resolve_guest(self, ident: str) -> list[dict[str, Any]]:
        """把虚拟化标识（id 或名字）解析为 [{id, instance}]（去重）。

        `pve_guest_info` 同时带 `id`/`name`/`instance`(exporter) 标签，可用于去重。
        """
        base = (self.ds.get("base_url") or "").rstrip("/")
        esc = promql_escape(ident)
        if "/" in ident:
            matchers = [f'id="{esc}"']
        elif ident.isdigit():
            matchers = [f'id="qemu/{esc}"', f'id="lxc/{esc}"', f'name="{esc}"']
        else:
            matchers = [f'name="{esc}"']
        auth, headers = self._auth()
        out: list[dict[str, Any]] = []
        for matcher in matchers:
            resp = requests.get(
                f"{base}/api/v1/query", params={"query": f"pve_guest_info{{{matcher}}}"},
                auth=auth, headers=headers, timeout=self.timeout, verify=self.verify,
            )
            if resp.status_code != 200:
                raise RuntimeError(f"HTTP {resp.status_code}: {_prom_error(resp)}")
            payload = resp.json()
            if payload.get("status") != "success":
                raise RuntimeError(str(payload.get("error")))
            seen: set[tuple] = set()
            for item in (payload.get("data") or {}).get("result") or []:
                m = item.get("metric") or {}
                gid, inst = m.get("id"), m.get("instance")
                if gid and (gid, inst) not in seen:
                    seen.add((gid, inst))
                    out.append({"id": gid, "instance": inst})
            if out:
                break
        return out

    def run(
        self,
        server: dict[str, Any],
        script: dict[str, Any],
        content: str,
        instance_matcher: str | None,
        ambiguous: bool = False,
        check_instances: bool = False,
        guest_matcher: str | None = None,
        auto_instance: bool = False,
    ) -> CollectResult:
        sid = int(server["id"])
        sname = server.get("hostname") or server.get("ip") or f"server-{sid}"
        meta = parse_script_meta(content)
        base = CollectResult(
            server_id=sid,
            server_name=sname,
            source="prometheus",
            script_id=int(script.get("id") or 0),
            script_name=script.get("name") or "",
            kind="promql",
            status="UNKNOWN",
            meta=meta,
        )
        if ambiguous:
            base.status = "UNKNOWN"
            base.error = i18n.t("collect.err_ambiguous")
            base.meta["ambiguous"] = True
            return base

        # 仅取 PromQL 语句体（去掉 # 头部元数据注释），再注入 $instance / $guest 匹配器
        query = extract_query(content)
        if instance_matcher:
            query = query.replace("$instance", instance_matcher)
        if guest_matcher:
            query = query.replace("$guest", guest_matcher)
        if "$guest" in query:
            base.status = "ERROR"
            base.hard_fact = True
            base.error = i18n.t("collect.err_guest_noconfig")
            return base
        if not query:
            base.status = "ERROR"
            base.hard_fact = True
            base.error = i18n.t("collect.err_empty_query")
            return base
        base.meta["query"] = query
        mode = (meta.get("MODE") or "instant").lower()
        base_url = (self.ds.get("base_url") or "").rstrip("/")
        try:
            auth, headers = self._auth()
            if mode == "range":
                window = parse_duration(meta.get("WINDOW") or "5m") or 300
                step = parse_duration(meta.get("STEP") or "1m") or 60
                import time as _time

                end = int(_time.time())
                params = {"query": query, "start": end - window, "end": end, "step": step}
                url = f"{base_url}/api/v1/query_range"
            else:
                params = {"query": query}
                url = f"{base_url}/api/v1/query"
            resp = requests.get(url, params=params, auth=auth, headers=headers, timeout=self.timeout, verify=self.verify)
            if resp.status_code != 200:
                base.status = "ERROR"
                base.hard_fact = True
                base.error = i18n.t("collect.err_query_http", code=resp.status_code, err=_prom_error(resp))
                base.output = f"query: {query}\n{base.error}"
                return base
            payload = resp.json()
            if payload.get("status") != "success":
                base.status = "ERROR"
                base.hard_fact = True
                base.error = i18n.t("collect.err_query_status", err=payload.get("error"))
                return base
            result = (payload.get("data") or {}).get("result") or []
        except Exception as exc:  # noqa: BLE001
            base.status = "ERROR"
            base.hard_fact = True
            base.error = i18n.t("collect.err_query_exc", err=exc)
            return base

        if not result:
            base.status = "UNKNOWN"
            base.error = i18n.t("collect.err_no_data")
            hint = i18n.t("collect.no_data_hint") if auto_instance else ""
            base.output = f"query: {query}\n" + i18n.t("collect.no_data_output", hint=hint)
            return base

        if check_instances:
            instances = {(item.get("metric") or {}).get("instance") for item in result}
            instances.discard(None)
            instances.discard("")
            if len(instances) > 1:
                base.status = "UNKNOWN"
                base.error = i18n.t("collect.err_ambiguous")
                base.meta["ambiguous"] = True
                return base

        series_values: list[tuple[str, float]] = []
        for item in result:
            metric = item.get("metric") or {}
            label = metric.get("instance") or metric.get("__name__") or ""
            extra = {k: v for k, v in metric.items() if k not in ("__name__", "job", "instance")}
            if extra:
                label = (label + " " + " ".join(f"{k}={v}" for k, v in sorted(extra.items()))).strip()
            if mode == "range":
                values = item.get("values") or []
                if not values:
                    continue
                raw = values[-1][1]
            else:
                val = item.get("value")
                if not val:
                    continue
                raw = val[1]
            try:
                series_values.append((label, float(raw)))
            except (TypeError, ValueError):
                series_values.append((label, float("nan")))

        if not series_values:
            base.status = "UNKNOWN"
            base.error = i18n.t("collect.err_no_data")
            return base

        lines = [f"{label} = {_fmt_num(value)}" for label, value in series_values]
        unit = meta.get("UNIT") or ""
        header = f"# {meta.get('NAME') or script.get('name') or 'query'} (MODE={mode}{', UNIT=' + unit if unit else ''})"
        base.output = header + "\n" + "\n".join(lines)
        status, items = evaluate(base.output, meta)
        base.status = status
        base.hard_fact = status == "FAIL"
        base.meta["items"] = items
        if status == "FAIL":
            breached = [it for it in items if it.get("status") == "FAIL"]
            detail = "、".join(
                f"{it['name']}={_fmt_num(_as_float(it['value'])) if _as_float(it['value']) is not None else it['value']}"
                for it in breached
            )
            base.error = i18n.t("collect.err_threshold", detail=detail)
        return base
