"""内置调度线程：每 poll_interval 秒扫描 run_schedule 表。

- 统一按 PyPiMeOps 主机本地时区校验与触发
- last_fired_at 保证同分钟仅触发一次
- run_history.schedule_id 检查该任务是否有进行中的 run
- 全局单 run 互斥（与手动统一）
"""
from __future__ import annotations

import json
import logging
import re
import threading
from datetime import datetime, timedelta, timezone
from typing import Any

import engine
import i18n
import models

log = logging.getLogger("pypimeops.scheduler")

_WEEKDAY_KEYS = ["weekday.0", "weekday.1", "weekday.2", "weekday.3", "weekday.4", "weekday.5", "weekday.6"]


def _match_field(expr: str, value: int, lo: int, hi: int) -> bool:
    expr = (expr or "*").strip()
    if expr in ("", "*"):
        return True
    for part in expr.split(","):
        part = part.strip()
        if not part:
            continue
        step = 1
        if "/" in part:
            base, _, step_s = part.partition("/")
            try:
                step = int(step_s)
            except ValueError:
                step = 1
            part = base
        if part in ("*", ""):
            start, end = lo, hi
        elif "-" in part:
            a, _, b = part.partition("-")
            try:
                start, end = int(a), int(b)
            except ValueError:
                continue
        else:
            try:
                start = end = int(part)
            except ValueError:
                continue
        if start <= value <= end and (value - start) % max(1, step) == 0:
            return True
    return False


def _matches(schedule: dict[str, Any], now: datetime) -> bool:
    return (
        _match_field(schedule.get("cron_min", "*"), now.minute, 0, 59)
        and _match_field(schedule.get("cron_hour", "*"), now.hour, 0, 23)
        and _match_field(schedule.get("cron_dow", "*"), now.weekday(), 0, 6)
    )


def _same_minute(iso_ts: str | None, now_utc: datetime) -> bool:
    """比较 last_fired_at（UTC 存储）与当前时间是否同一分钟（按 UTC 比较，避免时区错位）。

    Compare the stored last_fired_at (UTC) with now in UTC to avoid a timezone mismatch.
    """
    if not iso_ts:
        return False
    try:
        dt = datetime.fromisoformat(iso_ts)
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    n = now_utc.astimezone(timezone.utc)
    return (dt.year, dt.month, dt.day, dt.hour, dt.minute) == (n.year, n.month, n.day, n.hour, n.minute)


def _fixed(expr: Any, lo: int, hi: int) -> int | None:
    try:
        v = int(str(expr).strip())
    except (TypeError, ValueError):
        return None
    return v if lo <= v <= hi else None


def describe(schedule: dict[str, Any]) -> str:
    """Human-readable frequency for a schedule. 频率人话化。"""
    mn = str(schedule.get("cron_min") or "*").strip()
    hr = str(schedule.get("cron_hour") or "*").strip()
    dw = str(schedule.get("cron_dow") or "*").strip()
    if hr == "*" and dw == "*":
        if mn == "*":
            return i18n.t("schedule.desc_every_minute")
        m = re.fullmatch(r"\*/(\d+)", mn)
        if m:
            return i18n.t("schedule.desc_every_n_minutes", n=m.group(1))
        mi = _fixed(mn, 0, 59)
        if mi is not None:
            return i18n.t("schedule.desc_hourly_at", min=f"{mi:02d}")
        return i18n.t("schedule.desc_custom", expr=f"{mn} {hr} {dw}")
    hi = _fixed(hr, 0, 23)
    mi = _fixed(mn, 0, 59)
    di = _fixed(dw, 0, 6)
    if dw == "*" and hi is not None and mi is not None:
        return i18n.t("schedule.desc_daily_at", time=f"{hi:02d}:{mi:02d}")
    if di is not None and hi is not None and mi is not None:
        return i18n.t("schedule.desc_weekly_at", dow=i18n.t(_WEEKDAY_KEYS[di]), time=f"{hi:02d}:{mi:02d}")
    return i18n.t("schedule.desc_custom", expr=f"{mn} {hr} {dw}")


def classify(schedule: dict[str, Any]) -> dict[str, str]:
    """Reverse-map a stored cron to a form preset (for editing). 编辑时反推频率预设。"""
    mn = str(schedule.get("cron_min") or "*").strip()
    hr = str(schedule.get("cron_hour") or "*").strip()
    dw = str(schedule.get("cron_dow") or "*").strip()
    out = {"preset": "custom", "minute": "", "hour": "", "dow": ""}
    if hr == "*" and dw == "*":
        m = re.fullmatch(r"\*/(5|10|15|30)", mn)
        if m:
            out["preset"] = "every" + m.group(1)
            return out
        mi = _fixed(mn, 0, 59)
        if mi is not None:
            out["preset"] = "hourly"
            out["minute"] = f"{mi:02d}"
            return out
        return out
    hi = _fixed(hr, 0, 23)
    mi = _fixed(mn, 0, 59)
    di = _fixed(dw, 0, 6)
    if dw == "*" and hi is not None and mi is not None:
        out.update(preset="daily", hour=f"{hi:02d}", minute=f"{mi:02d}")
        return out
    if di is not None and hi is not None and mi is not None:
        out.update(preset="weekly", dow=str(di), hour=f"{hi:02d}", minute=f"{mi:02d}")
        return out
    return out


def cron_error(schedule: dict[str, Any]) -> bool:
    """Validate cron fields (min/hour/dow); True when invalid. 校验 cron 字段合法性。"""
    for key, hi in (("cron_min", 59), ("cron_hour", 23), ("cron_dow", 6)):
        val = str(schedule.get(key) or "*").strip() or "*"
        for part in val.split(","):
            part = part.strip()
            if not part:
                return True
            if part == "*":
                continue
            if part.startswith("*/"):
                if not part[2:].isdigit() or int(part[2:]) <= 0:
                    return True
                continue
            if "-" in part:
                a, _, b = part.partition("-")
                if not (a.isdigit() and b.isdigit()):
                    return True
                if not (0 <= int(a) <= hi and 0 <= int(b) <= hi and int(a) <= int(b)):
                    return True
                continue
            if not part.isdigit() or not (0 <= int(part) <= hi):
                return True
    return False


def next_runs(schedule: dict[str, Any], count: int = 1, now: datetime | None = None) -> list[datetime]:
    """Compute the next `count` local fire times (minute granularity). 计算下次触发（本地时区）。"""
    base = (now or datetime.now()).replace(second=0, microsecond=0)
    out: list[datetime] = []
    cur = base
    for _ in range(366 * 24 * 60):
        cur = cur + timedelta(minutes=1)
        if _matches(schedule, cur):
            out.append(cur)
            if len(out) >= count:
                break
    return out


class Scheduler:
    def __init__(self, poll_interval: int = 15):
        self.poll_interval = max(5, int(poll_interval))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_cleanup_day = None
        self._inflight: set[int] = set()  # 防同任务在触发间隙重复 spawn

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="pypimeops-scheduler", daemon=True)
        self._thread.start()
        log.info("调度线程已启动，轮询间隔 %ss", self.poll_interval)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # noqa: BLE001
                log.exception("调度扫描异常")
            self._stop.wait(self.poll_interval)

    def _tick(self) -> None:
        now = datetime.now()                 # 本地时间：用于 cron 字段匹配（Local time for cron matching）
        now_utc = datetime.now(timezone.utc)  # UTC：用于与 last_fired_at 比较（UTC for last_fired_at comparison）
        if self._last_cleanup_day != now.date():
            self._last_cleanup_day = now.date()
            try:
                result = engine.cleanup_retention()
                log.info("每日保留清理完成：%s", result)
            except Exception:  # noqa: BLE001
                log.exception("保留清理失败")

        for schedule in models.fetch_all("run_schedule", "enabled=1"):
            if not _matches(schedule, now):
                continue
            if _same_minute(schedule.get("last_fired_at"), now_utc):
                continue
            # 同任务防重入：该 schedule 是否有进行中的 run
            running = models.query(
                "SELECT id FROM run_history WHERE schedule_id=? AND status='running' LIMIT 1",
                (schedule["id"],),
            )
            if running:
                continue
            if engine.is_running():
                continue
            self._fire(schedule)

    def _fire(self, schedule: dict[str, Any]) -> None:
        sid = int(schedule["id"])
        if sid in self._inflight:
            return
        # 抢到全局 run 锁才登记 last_fired_at；失败不消耗本轮触发（同分钟由后续 tick 补跑）。
        if not engine.begin_scheduled(sid):
            log.warning("定时任务 #%s 抢锁失败（busy），本轮跳过，等待同分钟补跑", sid)
            try:
                with models.db() as conn:
                    models.write_audit(
                        conn, "scheduler", "schedule_skip", "schedule", sid,
                        schedule.get("name") or "", {"reason": "busy"},
                    )
            except Exception:  # noqa: BLE001
                log.exception("写 schedule_skip 审计失败")
            return
        self._inflight.add(sid)

        targets = schedule.get("targets_json")
        scripts = schedule.get("scripts_json")
        try:
            targets = json.loads(targets) if isinstance(targets, str) else (targets or {})
        except (ValueError, TypeError):
            targets = {}
        try:
            scripts = json.loads(scripts) if isinstance(scripts, str) else (scripts or [])
        except (ValueError, TypeError):
            scripts = []
        log.info("定时触发：%s (#%s)", schedule.get("name"), sid)
        mode = schedule.get("mode") or "model"

        def _worker() -> None:
            try:
                engine.run(targets, scripts, trigger="schedule", schedule_id=sid, operator_ip="scheduler",
                           mode=mode, lock_held=True)
            except Exception:  # noqa: BLE001
                log.exception("定时任务 #%s 执行失败", sid)
            finally:
                self._inflight.discard(sid)

        threading.Thread(target=_worker, name=f"pypimeops-run-{sid}", daemon=True).start()
