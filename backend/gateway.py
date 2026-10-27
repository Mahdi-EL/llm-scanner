"""The AI firewall as a drop-in gateway in front of an OpenAI-compatible chat API.

A customer points their OpenAI client at  https://<api>/gateway/<saved target id>/v1  and uses an
LLM Scanner API key as its api_key. For each chat completion:

1. The text this turn adds (user and tool messages after the last assistant message, where both
   direct and indirect injections arrive) is screened with firewall.check_input. A blocked request
   never reaches the model: the caller gets an ordinary completion with a refusal, so apps don't
   break. When the day's firewall allowance is used up the request is forwarded unscreened and
   the response says so in X-LLMScanner-Firewall (failing open keeps the customer's app working).
2. The request goes to the saved target's API with the target's stored key, or the key in
   X-Upstream-Authorization. Streaming requests are answered as a stream, but the reply is
   fetched whole first so it can be checked.
3. The reply is screened with firewall.check_output against the request's system prompt: leaked
   secrets are masked, and a reply that leaks the system prompt is replaced with the refusal. Tool
   call arguments are screened too.

Only verdicts, rule names, status codes and timings are recorded, never the messages.
"""
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import config
import detectors
import firewall
import netguard
import payment
import services
import store
from db import transaction, utcnow

log = logging.getLogger("llmscanner.gateway")

GROQ_OPENAI_URL = "https://api.groq.com/openai/v1"
MAX_REPLY_BYTES = 4 * 1024 * 1024
MAX_MESSAGES = 1000
_VERDICT_RANK = {"allow": 0, "review": 1, "block": 2}


@dataclass
class Result:
    status: int
    body: Optional[dict] = None          # JSON response
    stream: Optional[bytes] = None       # or a text/event-stream body
    headers: dict = field(default_factory=dict)


def error(status: int, message: str, code: str, kind: str = "invalid_request_error") -> Result:
    """An error in the shape OpenAI clients parse ({"error": {...}})."""
    return Result(status, {"error": {"message": message, "type": kind, "code": code}})


# ── Reading the request ───────────────────────────────────────
def text_of(content) -> str:
    """Message content as text: a string, or the text parts of a list of content parts."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("text", "") for p in content if isinstance(p, dict) and isinstance(p.get("text"), str))
    return ""


def new_input(messages: list) -> str:
    """What this turn adds: user and tool messages after the last assistant message."""
    last = max((i for i, m in enumerate(messages) if m.get("role") == "assistant"), default=-1)
    return "\n\n".join(t for m in messages[last + 1:] if m.get("role") in ("user", "tool", "function")
                       for t in [text_of(m.get("content"))] if t.strip())


def system_prompt_of(messages: list) -> str:
    return "\n\n".join(text_of(m.get("content")) for m in messages if m.get("role") in ("system", "developer"))


def upstream_url(target: dict) -> Optional[str]:
    cfg = target.get("config") or {}
    if cfg.get("target_type") == "groq":
        base = GROQ_OPENAI_URL
    elif cfg.get("target_type") == "openai_compatible" and cfg.get("api_url"):
        base = cfg["api_url"]
    else:
        return None
    return base if base.rstrip("/").endswith("/chat/completions") else base.rstrip("/") + "/chat/completions"


# ── Building replies ──────────────────────────────────────────
def refusal(model: str) -> dict:
    return {"id": "chatcmpl-llmscanner-" + uuid.uuid4().hex[:24], "object": "chat.completion",
            "created": int(time.time()), "model": model or "llmscanner-firewall",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": config.GATEWAY_BLOCK_MESSAGE}}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


FRAGMENT_WORDS = 5     # a run this long copied from the system prompt is worth flagging in a reply


def _screen(text: str, system_prompt: str, input_flagged: bool) -> tuple:
    """(verdict, finding types, firewall check) for one piece of model output."""
    check = firewall.check_output(text, system_prompt or None)
    found = list(check["findings"])
    verdict = check["verdict"]
    if system_prompt and "prompt_overlap" not in found \
            and detectors.prompt_overlap(text, system_prompt, n=FRAGMENT_WORDS) > 0:
        found.append("prompt_fragment")
        verdict = max(verdict, "review", key=_VERDICT_RANK.get)
    if input_flagged and found:
        verdict = "block"
    return verdict, found, check


def _tool_calls(message: dict) -> list:
    """The function calls ({"name", "arguments"}) a reply asks the app to run, the older single
    function_call included."""
    calls = [c.get("function") for c in message.get("tool_calls") or [] if isinstance(c, dict)]
    calls.append(message.get("function_call"))
    return [c for c in calls if isinstance(c, dict) and isinstance(c.get("arguments"), str) and c["arguments"]]


def _still_json(original: str, masked: str) -> bool:
    """Masking a secret inside a JSON string keeps the arguments valid; masking a number field
    (a card number, say) wouldn't, and the app's tool would fail to parse them."""
    try:
        json.loads(original)
    except ValueError:
        return True                    # they weren't JSON to begin with
    try:
        json.loads(masked)
        return True
    except ValueError:
        return False


def screen_reply(completion: dict, system_prompt: str, input_flagged: bool = False) -> tuple:
    """(completion with leaks masked or replaced, worst verdict, finding types).

    A reply that leaks a secret after an ordinary request has the secret masked. After a request
    the firewall flagged, any finding means the attack worked, so the whole reply is replaced: the
    rules only catch some of what leaked (a password quoted from the prompt, say, isn't a key format).

    Tool calls are checked the same way: their arguments reach an email, a URL or a database, so a
    leak there gets out as surely as one in the text (findings are named tool_<type>). A secret is
    masked inside the arguments; when masking isn't enough, the calls are dropped and the reply
    becomes the refusal.
    """
    worst, findings = "allow", []

    def note(verdict, found):
        nonlocal worst
        findings.extend(f for f in found if f not in findings)
        worst = max(worst, verdict, key=_VERDICT_RANK.get)

    for choice in completion.get("choices") or []:
        message = choice.get("message") or {}
        content = message.get("content")
        if isinstance(content, str) and content:
            verdict, found, check = _screen(content, system_prompt, input_flagged)
            note(verdict, found)
            if verdict == "block":
                replace = input_flagged or "prompt_overlap" in found or not check["masked"]
                message["content"] = config.GATEWAY_BLOCK_MESSAGE if replace else check["redacted"]
        drop_calls = False
        for call in _tool_calls(message):
            verdict, found, check = _screen(call["arguments"], system_prompt, input_flagged)
            note(verdict, [f"tool_{f}" for f in found])
            if verdict != "block":
                continue
            if input_flagged or "prompt_overlap" in found or not check["masked"] \
                    or not _still_json(call["arguments"], check["redacted"]):
                drop_calls = True
            else:
                call["arguments"] = check["redacted"]
        if drop_calls:
            message.pop("tool_calls", None)
            message.pop("function_call", None)
            message["content"] = config.GATEWAY_BLOCK_MESSAGE
            choice["finish_reason"] = "stop"
    return completion, worst, findings


def as_stream(completion: dict) -> bytes:
    """A whole completion as OpenAI's server-sent chunk stream (one content chunk, then the end)."""
    base = {"id": completion.get("id") or "chatcmpl-llmscanner", "object": "chat.completion.chunk",
            "created": completion.get("created") or int(time.time()), "model": completion.get("model", "")}
    events = []
    for choice in completion.get("choices") or [{"index": 0, "message": {}}]:
        message = choice.get("message") or {}
        delta = {"role": "assistant", "content": message.get("content") or ""}
        if message.get("tool_calls"):
            delta["tool_calls"] = [{**call, "index": i} for i, call in enumerate(message["tool_calls"])]
        events.append({**base, "choices": [{"index": choice.get("index", 0), "delta": delta, "finish_reason": None}]})
        events.append({**base, "choices": [{"index": choice.get("index", 0), "delta": {},
                                            "finish_reason": choice.get("finish_reason") or "stop"}]})
    return b"".join(f"data: {json.dumps(e, separators=(',', ':'))}\n\n".encode() for e in events) + b"data: [DONE]\n\n"


# ── Calling the model ─────────────────────────────────────────
def forward(url: str, body: dict, key: Optional[str]) -> tuple:
    """(status, JSON reply or an OpenAI-style error)."""
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = key if key.lower().startswith("bearer ") else f"Bearer {key}"
    try:
        netguard.check_url(url)
        with netguard.safe_session() as session:
            response = session.post(url, json=body, headers=headers, timeout=config.GATEWAY_TIMEOUT,
                                    allow_redirects=False, stream=True)
            netguard.read_capped(response, MAX_REPLY_BYTES, config.GATEWAY_TIMEOUT)
    except netguard.UnsafeURLError as e:
        return 400, error(400, f"Target URL rejected: {e}", "unsafe_upstream").body
    except Exception as e:
        log.warning("Gateway upstream call failed: %s", type(e).__name__)
        return 502, error(502, "The model's API didn't answer. Please retry.", "upstream_unavailable",
                          "api_error").body
    try:
        data = response.json()
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return 502, error(502, f"The model's API replied with something that isn't JSON ({response.status_code}).",
                          "upstream_bad_reply", "api_error").body
    return response.status_code, data


# ── One request ───────────────────────────────────────────────
def handle(user: dict, target_id: str, body: dict, upstream_auth: Optional[str] = None) -> Result:
    started = time.monotonic()
    if not payment.firewall_limit(user.get("plan", "free")):
        return error(402, "The AI firewall gateway isn't included in your plan.", "plan_required")
    try:
        target = store.get_target(user["id"], target_id, with_key=True)
    except store.KeyUnreadable as e:
        return error(409, str(e), "key_unreadable")
    if not target:
        return error(404, "Saved target not found. Use the id shown on the Targets page.", "target_not_found")
    url = upstream_url(target)
    if not url:
        return error(400, "The gateway works with OpenAI-compatible and Groq targets.", "unsupported_target")
    messages = body.get("messages") if isinstance(body, dict) else None
    if not isinstance(messages, list) or not messages or len(messages) > MAX_MESSAGES \
            or not all(isinstance(m, dict) for m in messages):
        return error(400, "messages must be a non-empty list of message objects.", "invalid_messages")

    stream = bool(body.get("stream"))
    model = body.get("model") or (target.get("config") or {}).get("model") or ""
    headers, rules, input_verdict, screened = {}, [], "allow", True
    text = new_input(messages)
    if text.strip():
        try:
            services.use_firewall(user, firewall.units(text))
        except services.FirewallRejected as e:
            if e.status != 429:
                return error(e.status, e.message, "plan_required")
            screened = False                     # allowance used up: fail open, and say so
            headers["X-LLMScanner-Firewall"] = "quota-exceeded"
        if screened:
            check = firewall.check_input(text, threshold=config.GATEWAY_BLOCK_SCORE)
            input_verdict, rules = check["verdict"], check["rules"]
            if check.get("degraded"):
                headers["X-LLMScanner-Firewall"] = "rules-only"
    headers["X-LLMScanner-Input"] = input_verdict if screened else "unscreened"

    if input_verdict == "block":
        reply = refusal(model)
        _record(user, target_id, input_verdict, None, rules, started, 200, screened)
        headers["X-LLMScanner-Rules"] = ",".join(rules)[:200]
        return Result(200, None if stream else reply, as_stream(reply) if stream else None, headers)

    key = upstream_auth or target.get("api_key")
    forwarded = {k: v for k, v in body.items() if k not in ("stream", "stream_options")}
    if model:
        forwarded["model"] = model
    status, data = forward(url, forwarded, key)
    if status >= 400 or not data.get("choices"):
        _record(user, target_id, input_verdict, None, rules, started, status, screened)
        return Result(status if status >= 400 else 502, data, None, headers)

    completion, output_verdict, findings = screen_reply(data, system_prompt_of(messages),
                                                        input_flagged=input_verdict != "allow")
    headers["X-LLMScanner-Output"] = output_verdict
    if rules or findings:
        headers["X-LLMScanner-Rules"] = ",".join(rules + findings)[:200]
    _record(user, target_id, input_verdict, output_verdict, rules + findings, started, status, screened)
    return Result(200, None if stream else completion, as_stream(completion) if stream else None, headers)


# ── What happened (no message text) ───────────────────────────
def _record(user, target_id, input_verdict, output_verdict, rules, started, upstream_status, screened):
    try:
        with transaction() as conn:
            conn.execute("INSERT INTO gateway_events (user_id, target_id, created_at, input_verdict, output_verdict, "
                         "rules, latency_ms, upstream_status, screened) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (user["id"], target_id, utcnow(), input_verdict, output_verdict, json.dumps(rules[:20]),
                          round((time.monotonic() - started) * 1000), upstream_status, int(screened)))
    except Exception:
        log.warning("Couldn't record a gateway event", exc_info=True)


def stats(user_id: str, target_id: Optional[str] = None, days: int = 7) -> dict:
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    where, args = "user_id = ? AND created_at >= ?", [user_id, since]
    if target_id:
        where += " AND target_id = ?"
        args.append(target_id)
    with transaction() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS requests, "
            "COALESCE(SUM(input_verdict = 'block'), 0) AS blocked_inputs, "
            "COALESCE(SUM(input_verdict = 'review'), 0) AS flagged_inputs, "
            "COALESCE(SUM(output_verdict = 'block'), 0) AS blocked_outputs, "
            "COALESCE(SUM(screened = 0), 0) AS unscreened, "
            "COALESCE(SUM(upstream_status >= 400), 0) AS upstream_errors, "
            f"CAST(COALESCE(AVG(latency_ms), 0) AS INTEGER) AS avg_latency_ms FROM gateway_events WHERE {where}",
            args).fetchone()
        # keep the table small: events older than 35 days aren't shown anywhere
        conn.execute("DELETE FROM gateway_events WHERE user_id = ? AND created_at < ?",
                     (user_id, (datetime.now(timezone.utc) - timedelta(days=35)).isoformat(timespec="seconds")))
    return {"days": days, **dict(row)}
