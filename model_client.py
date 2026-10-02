"""模型适配层：openai_compat 统一接口 + 多供应商分发（预留扩展位）。

合并 base_url + Authorization: Bearer 即直连 OpenAI 兼容联盟成员官方 API。
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

import requests

import i18n

PROVIDER_PRESETS: dict[str, dict[str, str]] = {
    "deepseek": {"label": "DeepSeek", "base_url": "https://api.deepseek.com", "api_key_env": "DEEPSEEK_API_KEY", "extra_json": '{"thinking": {"type": "disabled"}}', "temperature": "0.3", "top_p": ""},
    "openai": {"label": "OpenAI", "base_url": "https://api.openai.com/v1", "api_key_env": "OPENAI_API_KEY", "extra_json": "", "temperature": "0.2", "top_p": "1"},
    "qwen": {"label": "通义千问", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1", "api_key_env": "DASHSCOPE_API_KEY", "extra_json": "", "temperature": "0.3", "top_p": "0.8"},
    "kimi": {"label": "Kimi", "base_url": "https://api.moonshot.cn/v1", "api_key_env": "MOONSHOT_API_KEY", "extra_json": "", "temperature": "0.3", "top_p": ""},
    "glm": {"label": "GLM", "base_url": "https://open.bigmodel.cn/api/paas/v4", "api_key_env": "ZHIPU_API_KEY", "extra_json": "", "temperature": "0.3", "top_p": ""},
    "ollama": {"label": "Ollama(本地)", "base_url": "http://127.0.0.1:11434/v1", "api_key_env": "", "extra_json": "", "temperature": "0.2", "top_p": "1"},
    "custom": {"label": "自定义", "base_url": "", "api_key_env": "", "extra_json": "", "temperature": "", "top_p": ""},
}

# extra_json 模板（下拉选择，可手改）
EXTRA_JSON_TEMPLATES: list[dict[str, str]] = [
    {"label": "（无）", "value": ""},
    {"label": "DeepSeek 关闭思考", "value": '{"thinking": {"type": "disabled"}}'},
    {"label": "reasoning_effort=low", "value": '{"reasoning_effort": "low"}'},
    {"label": "reasoning_effort=high", "value": '{"reasoning_effort": "high"}'},
    {"label": "OpenAI JSON 模式", "value": '{"response_format": {"type": "json_object"}}'},
]


class ModelError(RuntimeError):
    pass


def api_key(model: dict[str, Any], secrets: dict[str, str]) -> str:
    env = (model.get("api_key_env") or "").strip()
    if not env:
        return ""
    return secrets.get(env, "")


def resolve_key(model: dict[str, Any], secrets: dict[str, str]) -> str:
    """取 API key；若配置了 api_key_env 但 secrets.env 中缺失/为空则给出明确错误。

    本地无鉴权端点（如 Ollama）请清空 api_key_env 字段。
    """
    env = (model.get("api_key_env") or "").strip()
    if not env:
        return ""
    key = (secrets.get(env) or "").strip()
    if not key:
        hint = ""
        # 常见误用：把真实 key 填进了“环境变量名”字段
        if env.startswith(("sk-", "sk_")) or (len(env) >= 32 and "_" not in env and " " not in env):
            hint = i18n.t("model.err_key_field_hint")
        raise ModelError(i18n.t("model.err_no_key", env=env, hint=hint))
    return key


def _endpoint(base_url: str) -> str:
    base = (base_url or "").rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    return f"{base}/chat/completions"


def _error_detail(resp: "requests.Response") -> str:
    text = (resp.text or "").strip()
    try:
        data = resp.json()
        err = data.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
        if isinstance(err, str) and err:
            return err
        if data.get("message"):
            return str(data["message"])
    except (ValueError, TypeError):
        pass
    return text[:300]


def _merge_extra(payload: dict[str, Any], model: dict[str, Any], extra: dict[str, Any] | None) -> None:
    """合并供应商特有参数：先 model.extra_json，再调用方 extra（后者优先）。

    例：DeepSeek 关闭思考 `{"thinking": {"type": "disabled"}}`；`{"reasoning_effort": "low"}`。
    """
    raw = model.get("extra_json")
    data: Any = None
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, str) and raw.strip():
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            data = None
    if isinstance(data, dict):
        payload.update(data)
    if extra:
        payload.update(extra)


def analyze(
    model: dict[str, Any],
    messages: list[dict[str, str]],
    secrets: dict[str, str],
    timeout: int = 60,
    retries: int = 2,
    extra: dict[str, Any] | None = None,
) -> str:
    """调用模型，失败按指数退避重试；最终失败抛 ModelError。"""
    key = resolve_key(model, secrets)
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    payload: dict[str, Any] = {"model": model.get("model_id"), "messages": messages}
    if model.get("temperature") is not None:
        payload["temperature"] = model["temperature"]
    if model.get("top_p") is not None:
        payload["top_p"] = model["top_p"]
    _merge_extra(payload, model, extra)

    last_err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            resp = requests.post(
                _endpoint(model.get("base_url") or ""),
                headers=headers,
                json=payload,
                timeout=timeout,
            )
            if resp.status_code != 200:
                raise ModelError(f"HTTP {resp.status_code}: {_error_detail(resp)}")
            data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                raise ModelError(i18n.t("model.err_no_choices", data=str(data)[:300]))
            message = choices[0].get("message", {}) or {}
            return message.get("content") or message.get("reasoning_content") or ""
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            if attempt < retries:
                time.sleep(2**attempt)
    raise ModelError(i18n.t("model.err_request_failed", retries=retries, err=last_err))


def test_connection(model: dict[str, Any], secrets: dict[str, str], timeout: int = 60) -> tuple[bool, str]:
    try:
        content = analyze(
            model,
            [{"role": "user", "content": "ping"}],
            secrets,
            timeout=timeout,
            retries=0,
            extra={"max_tokens": 64},
        )
        return True, i18n.t("model.conn_ok", content=content[:100] or i18n.t("model.empty_response"))
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def list_models(model: dict[str, Any], secrets: dict[str, str], timeout: int = 15) -> list[str]:
    """尝试从 OpenAI 兼容端点拉取可用模型 id 列表（GET {base_url}/models）。"""
    base = (model.get("base_url") or "").rstrip("/")
    headers: dict[str, str] = {}
    try:
        key = resolve_key(model, secrets)
    except ModelError:
        key = ""
    if key:
        headers["Authorization"] = f"Bearer {key}"
    resp = requests.get(f"{base}/models", headers=headers, timeout=timeout)
    if resp.status_code != 200:
        raise ModelError(f"HTTP {resp.status_code}: {_error_detail(resp)}")
    data = resp.json()
    out: list[str] = []
    for item in data.get("data") or []:
        mid = item.get("id") if isinstance(item, dict) else None
        if mid and mid not in out:
            out.append(mid)
    return out


_FENCE_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


def extract_json(content: str) -> dict[str, Any] | None:
    """从模型输出提取结构化 JSON（容忍 ```json 代码块与前后说明文字）。"""
    if not content:
        return None
    candidates: list[str] = []
    m = _FENCE_RE.search(content)
    if m:
        candidates.append(m.group(1))
    start = content.find("{")
    end = content.rfind("}")
    if start != -1 and end > start:
        candidates.append(content[start : end + 1])
    for text in candidates:
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
        except (ValueError, TypeError):
            continue
    return None
