"""应用日志工具：列出/读取/清理 logs/ 下的运行日志。

- 供 Web「应用日志」页与保留清理使用
- 仅允许访问 logs/ 目录内的文件，防路径遍历
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta
from typing import Any

from config import get_config

ACTIVE_LOG = "pypimeops.log"
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d{3}")


def safe_name(name: str) -> str:
    """仅接受 logs/ 目录内的文件名（basename），否则回退到活动日志。"""
    base = os.path.basename((name or "").strip())
    if not base or base.startswith("."):
        return ACTIVE_LOG
    return base


def log_path(name: str) -> str:
    cfg = get_config()
    return os.path.join(cfg.logs_dir, safe_name(name))


def active_log() -> str:
    return ACTIVE_LOG


def list_log_files() -> list[dict[str, Any]]:
    cfg = get_config()
    out: list[dict[str, Any]] = []
    if not os.path.isdir(cfg.logs_dir):
        return out
    for name in os.listdir(cfg.logs_dir):
        path = os.path.join(cfg.logs_dir, name)
        if not os.path.isfile(path):
            continue
        st = os.stat(path)
        out.append(
            {
                "name": name,
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "active": name == ACTIVE_LOG,
            }
        )
    out.sort(key=lambda x: (not x["active"], x["name"]))
    return out


def parse_line_ts(line: str) -> datetime | None:
    m = _TS_RE.match(line or "")
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def _read_last_bytes(path: str, max_bytes: int) -> str:
    if not os.path.isfile(path):
        return ""
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        if size > max_bytes:
            fh.seek(size - max_bytes)
            fh.readline()  # 丢弃可能被截断的首行
        return fh.read().decode("utf-8", "replace")


def read_last(name: str, limit: int = 2000) -> list[str]:
    limit = max(1, min(int(limit or 2000), 5000))
    text = _read_last_bytes(log_path(name), limit * 400 + 8192)
    return text.splitlines()[-limit:]


def read_tail(name: str, offset: int) -> tuple[list[str], int]:
    """从字节偏移追加读取；未成行（无换行结尾）的内容不返回、不推进偏移。"""
    path = log_path(name)
    if not os.path.isfile(path):
        return [], 0
    size = os.path.getsize(path)
    if offset < 0 or offset > size:
        offset = 0
    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read()
    new_offset = offset + len(data)
    if data and not data.endswith(b"\n"):
        idx = data.rfind(b"\n")
        if idx == -1:
            return [], offset
        data = data[: idx + 1]
        new_offset = offset + idx + 1
    return data.decode("utf-8", "replace").splitlines(), new_offset


def read_range(name: str, start: str | None, end: str | None, keyword: str | None, limit: int = 5000) -> list[str]:
    """按时间范围 + 关键词过滤（行时间戳位于 [start, end]）。"""
    limit = max(1, min(int(limit or 5000), 10000))
    t0 = _parse_dt(start)
    t1 = _parse_dt(end)
    kw = (keyword or "").strip().lower()
    path = log_path(name)
    if not os.path.isfile(path):
        return []
    out: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if kw and kw not in line.lower():
                continue
            ts = parse_line_ts(line)
            if ts is not None:
                if t0 and ts < t0:
                    continue
                if t1 and ts > t1:
                    continue
            out.append(line)
    return out[-limit:]


def _parse_dt(text: str | None) -> datetime | None:
    text = (text or "").strip().replace("T", " ")
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def cleanup(
    days: int | None = None,
    remove_all: bool = False,
    truncate_current: bool = False,
) -> dict[str, int]:
    """清理日志：删除轮转文件（可选按天/全部）+ 可选清空当前日志。"""
    cfg = get_config()
    deleted = 0
    if os.path.isdir(cfg.logs_dir):
        cutoff = None
        if days and days > 0:
            cutoff = datetime.now() - timedelta(days=days)
        for name in list(os.listdir(cfg.logs_dir)):
            path = os.path.join(cfg.logs_dir, name)
            if not os.path.isfile(path) or name == ACTIVE_LOG:
                continue
            try:
                if remove_all:
                    os.remove(path)
                    deleted += 1
                elif cutoff is not None and datetime.fromtimestamp(os.path.getmtime(path)) < cutoff:
                    os.remove(path)
                    deleted += 1
            except OSError:
                continue
    truncated = 0
    if truncate_current:
        path = os.path.join(cfg.logs_dir, ACTIVE_LOG)
        try:
            if os.path.isfile(path):
                with open(path, "w", encoding="utf-8"):
                    pass
                truncated = 1
        except OSError:
            pass
    return {"deleted": deleted, "truncated": truncated}

