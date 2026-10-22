"""Starts scheduled scans when they're due. A background thread checks every minute.

Each schedule points at a saved target. When it's due, a normal scan is
queued (same quotas as a manual scan). When the scan ends, notifications
compares it with the previous one and sends a regression alert if the
score dropped by at least the schedule's alert_drop points, or a new
critical finding appeared.
"""
import logging
import threading

import email_service
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
        if not store.claim_schedule(sched):          # another process took this run
            continue
        user = get_user_by_id(sched["user_id"])
        target = store.get_target(sched["user_id"], sched["target_id"], with_key=True) if user else None
        if not user or not target:
            store.update_schedule(sched["user_id"], sched["id"], enabled=False)
            continue
        if user.get("plan", "free") == "free":     # subscription ended: keep the schedule, skip this run
            log.info("Scheduled scan %s skipped: account is on the free plan", sched["id"])
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
            if e.status == 429:          # the scanner or this account is busy: try again shortly
                store.retry_schedule_soon(sched["id"])
                log.info("Scheduled scan %s postponed: %s", sched["id"], e.message)
            else:                        # e.g. the month's scans are used up: tell the owner it didn't run
                log.warning("Scheduled scan %s skipped: %s", sched["id"], e.message)
                if user.get("email") and user.get("email_verified"):
                    email_service.send_schedule_skipped(user["email"], target["name"], sched["frequency"],
                                                        e.message)
        except Exception:
            log.exception("Scheduled scan %s failed to start", sched["id"])
        if scan_id:
            store.record_schedule_scan(sched["id"], scan_id)
    return started


PRUNE_EVERY = 3600.0     # seconds between housekeeping runs


def _loop(interval: float):
    import time

    import database
    import runner
    last_prune = 0.0
    while not _stop.wait(interval):
        try:
            run_due()
        except Exception:
            log.exception("Scheduler tick failed")
        try:
            resumed = runner.resume_stale()       # scans a stopped or crashed process left behind
            if resumed:
                log.info("Resumed %d scan(s) no process was running", resumed)
        except Exception:
            log.exception("Resuming stale scans failed")
        if time.monotonic() - last_prune >= PRUNE_EVERY:
            last_prune = time.monotonic()
            try:
                removed = {k: v for k, v in database.prune().items() if v}
                if removed:
                    log.info("Housekeeping removed %s", removed)
            except Exception:
                log.exception("Housekeeping failed")


def start(interval: float = 60.0):
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(interval,), name="scheduler", daemon=True)
    _thread.start()


def stop():
    _stop.set()
