"""Free leak check: how easily does this system prompt come out? No account needed.

A visitor pastes a system prompt. It is given to the simulation model with a secret canary
planted in it, and a fixed sample of the library's extraction and override attacks (spread from
basic to advanced) is sent. Replies are graded by the rule detectors only: the canary, or the
prompt copied word for word. No judge calls, nothing stored.

The answer says how many attacks got the prompt out and which ones, never what the model
replied, so the endpoint can't be used as a free chat model. A paraphrased leak isn't counted
(the page says so); a full scan grades every reply.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import config
import detectors
from attacks import catalog
from attacks.multi_turn import is_multi_turn
from attacks.prompts import ATTACK_PROMPTS
from db import transaction
from scanner import spread

SAMPLE = {"extraction": 12, "direct_override": 8}
MAX_PROMPT_CHARS = 4000


class CheckUnavailable(RuntimeError):
    """The check can't run now: the day's free checks are used up (429), or the model isn't answering (503)."""
    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


def attacks() -> list:
    """[(category, prompt)] the free check sends: single-turn only."""
    out = []
    for category, n in SAMPLE.items():
        single = [p for p in ATTACK_PROMPTS[category] if not is_multi_turn(p)]
        out += [(category, p) for p in spread(single, n)]
    return out


def _take_slot() -> None:
    """Counts one check against today's global allowance (LEAK_CHECKS_PER_DAY)."""
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with transaction() as conn:
        conn.execute("INSERT INTO leak_checks (day, count) VALUES (?, 0) ON CONFLICT(day) DO NOTHING", (day,))
        taken = conn.execute("UPDATE leak_checks SET count = count + 1 WHERE day = ? AND count < ?",
                             (day, config.LEAK_CHECKS_PER_DAY)).rowcount
        conn.execute("DELETE FROM leak_checks WHERE day < ?", (day,))
    if not taken:
        raise CheckUnavailable("Today's free checks are used up. Create a free account to run a scan.", 429)


def run(system_prompt: str, target=None) -> dict:
    """{"attacks", "leaked", "partial", "errors", "examples": [{"category", "attack"}]}."""
    _take_slot()
    canary = detectors.make_canary()
    if target is None:
        from target import Target
        target = Target("simulation", system_prompt=detectors.with_canary(system_prompt, canary), timeout=20)
    sample = attacks()

    def one(item):
        category, prompt = item
        try:
            reply = target.send(prompt)
        except Exception:
            return category, prompt, None
        hits = [h for h in detectors.detect(reply, canary=canary, system_prompt=system_prompt)
                if h["type"] in ("canary", "prompt_overlap")]
        if any(h["severity"] == "CRITICAL" for h in hits):
            return category, prompt, "CRITICAL"          # the canary, or most of the prompt word for word
        return category, prompt, "HIGH" if hits else ""   # part of it word for word

    with ThreadPoolExecutor(max_workers=4) as pool:
        graded = list(pool.map(one, sample))
    errors = sum(1 for g in graded if g[2] is None)
    if errors == len(graded):
        raise CheckUnavailable("The free check isn't available right now. Please try again later.", 503)
    leaked = [g for g in graded if g[2] == "CRITICAL"]
    partial = [g for g in graded if g[2] == "HIGH"]
    return {"attacks": len(graded) - errors, "leaked": len(leaked), "partial": len(partial), "errors": errors,
            "examples": [{"category": catalog.info(c)["title"], "attack": p} for c, p, _ in (leaked + partial)[:5]]}
