"""Runtime AI firewall: screen messages before they reach your model, and replies before they reach users.

check_input() combines fast rules (chat-template tokens, "ignore your
instructions", requests for the system prompt, hidden characters) with
Meta's Prompt Guard 2 classifier on Groq, which rates how likely a text is a
prompt injection or jailbreak, from 0 to 1. Prompt Guard reads at most 512
tokens, so longer texts are split into overlapping chunks and the highest
score wins. Instructions hidden in base64 or in invisible Unicode tag
characters are decoded and checked too. The rules only know English;
Prompt Guard is multilingual.

check_output() needs no LLM: it flags replies that leak secrets, the canary
or long verbatim runs of the system prompt (see detectors.py), and returns a
copy with the secrets masked.
"""
import base64
import binascii
import logging
import math
import re
import threading
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Optional

import config
import detectors
import retry

log = logging.getLogger("llmscanner.firewall")

GUARD_MODELS = ["meta-llama/llama-prompt-guard-2-86m", "meta-llama/llama-prompt-guard-2-22m"]
TOKEN_BUDGET = 400      # estimated tokens per chunk; Prompt Guard's window is 512
MAX_CALLS    = 48       # Prompt Guard requests per check, at most
UNIT_CHARS   = 2000     # every started 2,000 characters count as one check
REVIEW_SCORE = 0.5      # under the block threshold, but still worth a look

VERDICT_RANK = {"allow": 0, "review": 1, "block": 2}

# Invisible characters that can hide or split instructions.
_HIDDEN = re.compile("[\N{ZERO WIDTH SPACE}\N{WORD JOINER}-\N{INVISIBLE PLUS}\N{ZERO WIDTH NO-BREAK SPACE}"
                     "\N{LEFT-TO-RIGHT EMBEDDING}-\N{RIGHT-TO-LEFT OVERRIDE}"
                     "\N{LEFT-TO-RIGHT ISOLATE}-\N{POP DIRECTIONAL ISOLATE}]")
# Invisible too, but normal in emoji and in Arabic, Persian and Indic text: removed, never reported.
_SOFT = re.compile("[\N{SOFT HYPHEN}\N{ZERO WIDTH NON-JOINER}-\N{RIGHT-TO-LEFT MARK}]")
# Tag characters mirror ASCII invisibly ("ASCII smuggling"). Short runs are flag emoji.
_TAGS = re.compile("[\N{LANGUAGE TAG}-\N{CANCEL TAG}]")
_TAG_RUN = re.compile("[\N{TAG SPACE}-\N{TAG TILDE}]{8,}")
_SPACED = re.compile(r"\b(?:\w ){3,}\w\b")
_BASE64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")

RULES = [
    ("chat_template_tokens", "block",
     re.compile(r"<\|(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|eot_id)\|>"
                r"|<<\s*/?SYS\s*>>|\[/?INST\]|<(?:start|end)_of_turn>", re.I),
     "Text contains chat-template control tokens, used to fake a system or assistant turn."),
    ("fake_role_marker", "review",
     re.compile(r"\[\s*(?:system|developer)(?:\s+(?:message|prompt|override|instructions?|note))?\s*\]"
                r"|\[\s*admin\s+(?:message|override|instructions?)\s*\]"
                r"|^[ \t]*#{1,6}[ \t]*(?:system|developer)(?:[ \t]+(?:message|prompt|instructions?))?[ \t]*:?[ \t]*$",
                re.I | re.M),
     "Text imitates a system or developer message."),
    ("override_phrase", "review",
     re.compile(r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,40}?"
                r"\b(?:previous|prior|above|earlier|preceding|all|your|system)\b.{0,30}?"
                r"\b(?:instructions?|rules|prompts?|guidelines|directions|directives|guardrails)\b", re.I | re.S),
     "Text asks the model to ignore its instructions."),
    ("prompt_extraction", "review",
     re.compile(r"\b(?:reveal|print|show|repeat|output|display|dump|leak|give me|tell me|what (?:is|are|was|were))\b"
                r".{0,40}?(?:\bsystem prompt\b|\b(?:initial|original|hidden|secret|full|exact) (?:prompt|instructions|rules)\b"
                r"|\b(?:text|words|everything|instructions) above\b)", re.I | re.S),
     "Text asks for the system prompt or hidden instructions."),
    ("jailbreak_persona", "review",
     re.compile(r"(?-i:\bDAN\b)|\bdo anything now\b|\bjailbroken\b"
                r"|\b(?:developer|god|jailbreak|DAN) mode (?:is )?(?:enabled|activated)\b"
                r"|\byou(?: are|'re) (?:now )?(?:an? )?(?:unfiltered|unrestricted|uncensored)\b", re.I),
     "Text uses a known jailbreak persona or phrase."),
]


def units(text: str) -> int:
    """How many checks a text counts for: one per started 2,000 characters."""
    return max(1, math.ceil(len(text) / UNIT_CHARS))


def _untag(match) -> str:
    code = ord(match.group(0)) - 0xE0000
    return chr(code) if 0x20 <= code <= 0x7E else ""


def normalize(text: str) -> str:
    """The text as a model reads it: NFKC, tag characters turned back into the ASCII they hide,
    invisible characters removed and spaced-out letters ("i g n o r e") joined."""
    text = unicodedata.normalize("NFKC", text)
    text = _TAGS.sub(_untag, text)
    text = _SOFT.sub("", _HIDDEN.sub("", text))
    return _SPACED.sub(lambda m: m.group(0).replace(" ", ""), text)


def _decoded_payloads(text: str, limit: int = 5) -> list:
    """Readable text hidden in base64, which attackers use to slip instructions past filters."""
    found = []
    for match in _BASE64.finditer(text):
        blob = match.group(0)
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        readable = sum(ch.isprintable() or ch.isspace() for ch in decoded)
        if " " in decoded and readable >= 0.9 * len(decoded):
            found.append(decoded[:2000])
            if len(found) >= limit:
                break
    return found


def _rule_hits(raw: str, scanned: str) -> list:
    hits = [{"rule": name, "action": action, "reason": reason}
            for name, action, pattern, reason in RULES if pattern.search(scanned)]
    if _HIDDEN.search(raw.lstrip("\N{ZERO WIDTH NO-BREAK SPACE}")) or _TAG_RUN.search(raw):
        hits.append({"rule": "hidden_characters", "action": "review",
                     "reason": "Text contains invisible characters that can hide instructions."})
    return hits


# ── Prompt Guard ──────────────────────────────────────────────
def _cost(ch: str) -> float:
    """Prompt Guard tokens per character, on the safe side. Measured: English prose about 0.2,
    Arabic, Hindi and Cyrillic 0.3 to 0.4, Chinese 0.7, emoji 0.85."""
    code = ord(ch)
    if code < 128:
        return 0.25 if ch.isalnum() else 0.5
    return 0.45 if code < 0x2E80 else 0.9


def _chunks(text: str) -> list:
    """Overlapping pieces that should each fit Prompt Guard's window, cut at a space when possible."""
    chunks, start, n = [], 0, len(text)
    while start < n:
        end, cost = start, 0.0
        while end < n:
            cost += _cost(text[end])
            if cost > TOKEN_BUDGET:
                break
            end += 1
        if end < n:
            space = text.rfind(" ", start + (end - start) // 2, end)
            if space > start:
                end = space
        chunks.append(text[start:end])
        if end >= n:
            break
        start = max(end - (end - start) // 8, start + 1)      # ~12% overlap
    return chunks


class _Budget:
    """Caps the Prompt Guard requests one check may make (chunks plus re-splits)."""

    def __init__(self, calls: int):
        self.left, self.exhausted = calls, False
        self._lock = threading.Lock()

    def take(self) -> bool:
        with self._lock:
            if self.left <= 0:
                self.exhausted = True
                return False
            self.left -= 1
            return True


def _too_long(error: Exception) -> bool:
    return getattr(error, "status_code", None) == 400 and "length" in str(error).lower()


def _score(client, model: str, chunk: str, budget: _Budget, depth: int = 0) -> list:
    """Scores for one chunk; when Groq says it's too long, scores both halves instead."""
    if not budget.take():
        return []
    try:
        reply = client.chat.completions.create(model=model, messages=[{"role": "user", "content": chunk}])
    except Exception as e:
        if _too_long(e) and depth < 4 and len(chunk) > 40:
            mid = len(chunk) // 2
            pad = min(100, mid // 4)
            return (_score(client, model, chunk[:mid + pad], budget, depth + 1)
                    + _score(client, model, chunk[mid - pad:], budget, depth + 1))
        raise
    return [float((reply.choices[0].message.content or "").strip())]


_client = None
_client_lock = threading.Lock()


def _groq():
    global _client
    with _client_lock:
        if _client is None:
            if not config.GROQ_API_KEY:
                raise RuntimeError("no Groq API key is configured on the server")
            from groq import Groq
            _client = Groq(api_key=config.GROQ_API_KEY, max_retries=1, timeout=20)
        return _client


def guard_score(text: str, client=None) -> dict:
    """{"score", "model", "truncated"}: the highest Prompt Guard score over the chunks.
    Raises RuntimeError when no guard model answers."""
    client = client or _groq()
    chunks = _chunks(text) or [""]
    last_error = None
    for model in GUARD_MODELS:
        budget = _Budget(MAX_CALLS)
        try:
            if len(chunks) == 1:
                results = [_score(client, model, chunks[0], budget)]
            else:
                with ThreadPoolExecutor(max_workers=4) as pool:
                    results = list(pool.map(partial(_score, client, model, budget=budget), chunks))
        except Exception as e:       # retired model, rate limit or an unexpected answer: try the next one
            last_error = e
            log.warning("Prompt Guard model %s failed: %s", model, e)
            continue
        scores = [s for chunk_scores in results for s in chunk_scores]
        if scores:
            return {"score": max(scores), "model": model, "truncated": budget.exhausted}
    if last_error is None:
        raise RuntimeError("the text couldn't be scored")
    raise RuntimeError("rate limit reached" if retry.is_rate_limit(last_error) else type(last_error).__name__)


# ── Public checks ─────────────────────────────────────────────
def check_input(text: str, threshold: float = 0.8, client=None) -> dict:
    """Screens a message before it reaches the model.

    Returns {"verdict": "allow" | "review" | "block", "score", "reasons", "rules", "model",
    "decoded", "truncated", "degraded"}. "degraded" means Prompt Guard didn't answer and only
    the rules were applied; "truncated" means the text was too long to score all of it.
    """
    normalized = normalize(text)
    payloads = _decoded_payloads(normalized)
    scanned = "\n\n".join([normalized, *payloads])
    hits = _rule_hits(text, scanned)
    verdict = max((h["action"] for h in hits), key=VERDICT_RANK.get, default="allow")
    reasons = [h["reason"] for h in hits]

    guard = {"score": None, "model": None, "truncated": False}
    degraded = False
    try:
        guard = guard_score(scanned, client)
    except RuntimeError as e:
        degraded = True
        log.warning("Prompt Guard unavailable: %s", e)
        why = "hit its rate limit" if "rate limit" in str(e) else "wasn't available"
        reasons.append(f"The Prompt Guard model {why}, so only the rules were applied.")
    score = guard["score"]
    if score is not None and score >= min(threshold, REVIEW_SCORE):
        verdict = max(verdict, "block" if score >= threshold else "review", key=VERDICT_RANK.get)
        reasons.insert(0, f"Prompt Guard rates this {min(score, 0.99):.0%} likely to be a prompt injection "
                          "or jailbreak.")
    if payloads and verdict != "allow":
        reasons.append("Part of the text was hidden in base64; it was decoded and checked.")
    return {"verdict": verdict, "score": None if score is None else round(score, 4), "reasons": reasons,
            "rules": [h["rule"] for h in hits], "model": guard["model"], "decoded": len(payloads),
            "truncated": guard["truncated"], "degraded": degraded}


def check_output(text: str, system_prompt: Optional[str] = None, canary: Optional[str] = None) -> dict:
    """Screens a reply before it reaches the user.

    Returns {"verdict", "reasons", "findings", "redacted", "masked"}: block when the reply leaks
    a secret, the canary or most of the system prompt, review for a partial overlap with the
    system prompt. "redacted" is the reply with secrets and the canary masked.
    """
    hits = detectors.detect(text, canary=canary, system_prompt=system_prompt)
    blocking = any(h["type"] in ("canary", "secret") or h["severity"] == "CRITICAL" for h in hits)
    redacted, masked = detectors.redact(text, canary)
    return {"verdict": "block" if blocking else "review" if hits else "allow",
            "reasons": [h["evidence"] for h in hits], "findings": [h["type"] for h in hits],
            "redacted": redacted, "masked": masked}
