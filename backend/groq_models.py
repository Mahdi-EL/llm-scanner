"""Picks Groq models that actually exist, so a model retirement can't break every scan.

Groq retires models regularly (llama-3.3-70b-versatile disappeared in 2026 and
every scan failed at its first call). resolve() checks Groq's live model list
(cached for an hour) and falls back along a preference list when the
configured model is gone.
"""
import logging
import re
import threading
import time
from typing import Optional

log = logging.getLogger("llmscanner.models")

# Different model families for the simulated target and the judge, so the
# judge doesn't grade its own family's answers.
TARGET_PREFERENCES = ["qwen/qwen3.8-27b", "openai/gpt-oss-20b", "openai/gpt-oss-120b"]
JUDGE_PREFERENCES  = ["openai/gpt-oss-120b", "qwen/qwen3.8-27b", "openai/gpt-oss-20b"]

_NOT_CHAT = ("whisper", "orpheus", "prompt-guard", "tts", "guard", "allam")
_CACHE_SECONDS = 3600
_FAILURE_CACHE_SECONDS = 300      # don't make every scan wait on a listing that just failed
_cache = {}
_lock = threading.Lock()


def available(api_key: Optional[str], client=None) -> Optional[set]:
    """Chat model IDs this key can use, or None when the list can't be fetched."""
    if not api_key and client is None:
        return None
    cache_key = api_key or id(client)
    with _lock:
        hit = _cache.get(cache_key)
        if hit and time.time() - hit[0] < (_CACHE_SECONDS if hit[1] is not None else _FAILURE_CACHE_SECONDS):
            return hit[1]
    try:
        if client is None:
            from groq import Groq
            client = Groq(api_key=api_key, max_retries=1, timeout=15)
        models = {m.id for m in client.models.list().data
                  if getattr(m, "active", True) and not any(tag in m.id for tag in _NOT_CHAT)}
    except Exception:
        log.warning("Couldn't list Groq models; using the configured ones as-is", exc_info=True)
        with _lock:
            _cache[cache_key] = (time.time(), None)
        return None
    with _lock:
        _cache[cache_key] = (time.time(), models)
    return models


def resolve(configured: Optional[str], preferences: list, api_key: Optional[str], client=None) -> str:
    """The configured model if Groq still serves it, else the first available preference."""
    models = available(api_key, client)
    if models is None:
        return configured or preferences[0]
    if configured and configured in models:
        return configured
    for candidate in preferences:
        if candidate in models:
            if configured:
                log.warning("Model %s is not available on Groq; using %s instead", configured, candidate)
            return candidate
    if models:
        fallback = sorted(models)[0]
        log.warning("None of the preferred models is available; using %s", fallback)
        return fallback
    return configured or preferences[0]


def default_model(api_key: Optional[str] = None) -> str:
    """The model for simulated targets and the CLI tools."""
    import config
    return resolve(config.DEFAULT_MODEL, TARGET_PREFERENCES, api_key or config.GROQ_API_KEY)


def judge_model(api_key: Optional[str] = None) -> str:
    import config
    if config.JUDGE_BASE_URL:            # another provider: Groq's model list says nothing about it
        return config.JUDGE_MODEL
    return resolve(config.JUDGE_MODEL, JUDGE_PREFERENCES, api_key or config.JUDGE_API_KEY)


def generation_params(model: str) -> dict:
    """Extra parameters some model families need. Reasoning models spend tokens
    thinking before they answer, so they get a larger budget."""
    if model.startswith("openai/gpt-oss") or "qwen3" in model:
        return {"max_tokens": 1500}
    return {"max_tokens": 400}


_THINKING = re.compile(r"<think>.*?(?:</think>|$)", re.DOTALL | re.IGNORECASE)


def strip_reasoning(text: Optional[str]) -> str:
    """The answer without the <think>...</think> reasoning some models write before it
    (cut off mid-thought by max_tokens, there is no answer)."""
    return _THINKING.sub("", text or "").strip()


_tool_client = None


def complete(prompt: str, max_tokens: int = 800) -> str:
    """The default model's answer to one message, on this server's key, retrying transient errors.
    For the command-line tools (prompt generation, hardening, auto-discovery)."""
    global _tool_client
    import config
    from retry import call_with_retry
    if _tool_client is None:
        from groq import Groq
        if not config.GROQ_API_KEY:
            raise RuntimeError("No Groq API key: set GROQ_API_KEY")
        _tool_client = Groq(api_key=config.GROQ_API_KEY, max_retries=0, timeout=90)
    model = default_model()
    params = generation_params(model)
    params["max_tokens"] = max(params["max_tokens"], max_tokens)
    response = call_with_retry(_tool_client.chat.completions.create, model=model,
                               messages=[{"role": "user", "content": prompt}], **params)
    return strip_reasoning(response.choices[0].message.content)


def clear_cache():
    with _lock:
        _cache.clear()
