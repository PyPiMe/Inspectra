"""采集器抽象：SSHCollector(paramiko) / PrometheusCollector(HTTP)。

统一返回 CollectResult，供引擎做阈值仲裁、脱敏、模型分析与归档。
"""
from __future__ import annotations

import io
import os
import re
from dataclasses import dataclass, field
from typing import Any

import requests

SEVERITY = {"OK": 0, "UNKNOWN": 1, "WARN": 2, "FAIL": 3, "ERROR": 4}


def severity_rank(status: str) -> int:
    return SEVERITY.get((status or "UNKNOWN").upper(), 1)


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
    meta: dict[str, Any] = {"NAME": "", "MODE": "instant", "WINDOW": "", "STEP": "1m", "THRESHOLD": "", "UNIT": ""}
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


_THRESHOLD_RE = re.compile(r"^\s*(>=|<=|==|!=|>|<)\s*(-?\d+(?:\.\d+)?)\s*$")


def parse_threshold(text: str) -> tuple[str, float] | None:
    m = _THRESHOLD_RE.match(text or "")
    if not m:
        return None
    return m.group(1), float(m.group(2))


def eval_threshold(op: str, limit: float, value: float) -> bool:
    if op == ">":
        return value > limit
    if op == ">=":
        return value >= limit
    if op == "<":
        return value < limit
    if op == "<=":
        return value <= limit
    if op == "==":
        return value == limit
    if op == "!=":
        return value != limit
    return False


def validate_promql(content: str) -> list[str]:
    """校验 promql 头部元数据，返回错误列表（空=通过）。"""
    errors: list[str] = []
    meta = parse_script_meta(content)
    if not meta["NAME"]:
        errors.append("缺少 `# NAME` 元数据")
    mode = (meta["MODE"] or "instant").lower()
    if mode not in ("instant", "range"):
        errors.append("`# MODE` 仅支持 instant|range")
    if mode == "range":
        if not meta["WINDOW"] or parse_duration(meta["WINDOW"]) is None:
            errors.append("`MODE=range` 需要合法 `# WINDOW`（如 5m）")
        if meta["STEP"] and parse_duration(meta["STEP"]) is None:
            errors.append("`# STEP` 需为合法时长（如 1m）")
    if meta["THRESHOLD"] and parse_threshold(meta["THRESHOLD"]) is None:
        errors.append("`# THRESHOLD` 格式应为 `>90` / `<=1` 等单条件")
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
    raise ValueError("无法解析 SSH 私钥（仅支持 OpenSSH 格式密钥）")


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
                base.error = f"命令退出码 {code}" + (f"：{err.strip()}" if err.strip() else "")
            else:
                base.status = "OK"
                if err.strip():
                    base.output = out + ("\n" if out and not out.endswith("\n") else "") + f"[stderr]\n{err}"
        except paramiko.BadHostKeyException:
            base.status = "ERROR"
            base.hard_fact = True
            base.error = "主机密钥已变更，连接被阻断（known_hosts TOFU）"
        except paramiko.AuthenticationException:
            base.status = "ERROR"
            base.hard_fact = True
            base.error = "SSH 认证失败"
        except Exception as exc:  # noqa: BLE001
            base.status = "ERROR"
            base.hard_fact = True
            base.error = f"SSH 采集异常：{exc}"
        finally:
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
            raise ValueError(f"数据源缺少凭据：secrets.env 未设置 {self.ds.get('secret_env')}")
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
                return True, "连接成功"
            return False, f"HTTP {resp.status_code}"
        except Exception as exc:  # noqa: BLE001
            return False, f"连接失败：{exc}"

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
        if "/" in ident:
            matcher = f'id="{promql_escape(ident)}"'
        else:
            matcher = f'name="{promql_escape(ident)}"'
        query = f"pve_guest_info{{{matcher}}}"
        auth, headers = self._auth()
        resp = requests.get(
            f"{base}/api/v1/query", params={"query": query}, auth=auth, headers=headers,
            timeout=self.timeout, verify=self.verify,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}: {_prom_error(resp)}")
        payload = resp.json()
        if payload.get("status") != "success":
            raise RuntimeError(str(payload.get("error")))
        out: list[dict[str, Any]] = []
        seen: set[tuple] = set()
        for item in (payload.get("data") or {}).get("result") or []:
            m = item.get("metric") or {}
            gid, inst = m.get("id"), m.get("instance")
            if gid and (gid, inst) not in seen:
                seen.add((gid, inst))
                out.append({"id": gid, "instance": inst})
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
            base.error = "instance selector 命中多个实例（ambiguous），请填写显式 prom_instance"
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
            base.error = "脚本使用 $guest，但服务器未配置「虚拟化标识」"
            return base
        if not query:
            base.status = "ERROR"
            base.hard_fact = True
            base.error = "脚本无可执行的 PromQL 语句（仅注释或为空）"
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
                base.error = f"查询失败 HTTP {resp.status_code}: {_prom_error(resp)}"
                base.output = f"query: {query}\n{base.error}"
                return base
            payload = resp.json()
            if payload.get("status") != "success":
                base.status = "ERROR"
                base.hard_fact = True
                base.error = f"查询返回错误：{payload.get('error')}"
                return base
            result = (payload.get("data") or {}).get("result") or []
        except Exception as exc:  # noqa: BLE001
            base.status = "ERROR"
            base.hard_fact = True
            base.error = f"查询异常：{exc}"
            return base

        if not result:
            base.status = "UNKNOWN"
            base.error = "无数据"
            hint = "；该实例由服务器 IP 自动推导，若目标实例以主机名暴露，请在绑定中填写 prom_instance 或数据源默认标签" if auto_instance else ""
            base.output = f"query: {query}\n无数据（Prometheus 返回空结果：请核对实例标签与指标名是否存在{hint}）"
            return base

        if check_instances:
            instances = {(item.get("metric") or {}).get("instance") for item in result}
            instances.discard(None)
            instances.discard("")
            if len(instances) > 1:
                base.status = "UNKNOWN"
                base.error = "instance selector 命中多个实例（ambiguous），请填写显式 prom_instance"
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
            base.error = "无数据"
            return base

        lines = [f"{label} = {_fmt_num(value)}" for label, value in series_values]
        threshold = parse_threshold(meta.get("THRESHOLD") or "")
        if threshold:
            op, limit = threshold
            breached = [(lbl, v) for lbl, v in series_values if eval_threshold(op, limit, v)]
            if breached:
                base.status = "FAIL"
                base.hard_fact = True
                detail = "、".join(f"{lbl}={_fmt_num(v)}" for lbl, v in breached)
                base.error = f"阈值越界（{op}{limit}）：{detail}"
            else:
                base.status = "OK"
        else:
            base.status = "OK"
        unit = meta.get("UNIT") or ""
        header = f"# {meta.get('NAME') or script.get('name') or 'query'} (MODE={mode}{', UNIT=' + unit if unit else ''})"
        base.output = header + "\n" + "\n".join(lines)
        return base
