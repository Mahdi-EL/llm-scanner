"""Starts scheduled scans when they're due. A background thread checks every minute.

Each schedule points at a saved target. When it's due, a normal scan is
queued (same quotas as a manual scan). When the scan ends, notifications
compares it with the previous one and sends a regression alert if the
score dropped by at least the schedule's alert_drop points, or a new
critical finding appeared.
"""
import logging
import threading

import services
import store
from auth_db import get_user_by_id

log = logging.getLogger("llmscanner.scheduler")

_stop = threading.Event()
_thread = None


def run_due() -> int:
    """Queues every schedule that's due. Returns how many scans were started."""
    started = 0
    for sched in store.due_schedules():
        user = get_user_by_id(sched["user_id"])
        target = store.get_target(sched["user_id"], sched["target_id"], with_key=True) if user else None
        if not user or not target:
            store.update_schedule(sched["user_id"], sched["id"], enabled=False)
            continue
        if user.get("plan", "free") == "free":     # subscription ended: keep the schedule, skip this run
            log.info("Scheduled scan %s skipped: account is on the free plan", sched["id"])
            store.mark_schedule_ran(sched["id"], sched["frequency"], None)
            continue
        cfg = dict(target["config"])
        if sched["categories"]:
            cfg["categories"] = sched["categories"]
        scan_id = None
        try:
            scan_id = services.queue_scan(user, cfg, target.get("api_key"), target_name=target["name"],
                                          target_id=target["id"], schedule_id=sched["id"])
            started += 1
        except services.ScanRejected as e:
            log.warning("Scheduled scan %s skipped: %s", sched["id"], e.message)
        except Exception:
            log.exception("Scheduled scan %s failed to start", sched["id"])
        store.mark_schedule_ran(sched["id"], sched["frequency"], scan_id)
    return started


def _loop(interval: float):
    while not _stop.wait(interval):
        try:
            run_due()
        except Exception:
            log.exception("Scheduler tick failed")


def start(interval: float = 60.0):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(interval,), name="scheduler", daemon=True)
    _thread.start()


def stop():
    _stop.set()
