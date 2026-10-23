"""Connectors for the AI applications we scan.

Supported targets: simulation (a Groq model with your system prompt),
groq (a Groq model with your own key), any OpenAI-compatible API, a custom
REST endpoint, GraphQL, and WebSocket. HTTP targets go through netguard's
SSRF-safe session, so a target URL can never reach internal addresses.
"""
import json
import threading
import time

import config
import netguard

MAX_REPLY_BYTES = 2 * 1024 * 1024    # a chat reply is a few KB; more means a wrong URL or a hostile target

# Default model per target type, used when the caller doesn't pick one.
# Groq targets resolve theirs at first use (groq_models), since Groq retires models.
DEFAULT_MODELS = {
    "simulation"       : config.DEFAULT_MODEL,
    "groq"             : config.DEFAULT_MODEL,
    "openai_compatible": "gpt-4o-mini",
}

TARGET_TYPES = ("simulation", "groq", "openai_compatible", "custom_rest", "graphql", "websocket")
# Target types that keep chat history, so multi-turn attacks can be played.
HISTORY_TYPES = ("simulation", "groq", "openai_compatible")

DEFAULT_BASELINE_QUESTION = "Hi! What can you help me with?"


class Target:
    """One AI application under test. Thread-safe: a scan sends attacks in parallel."""

    def __init__(self, target_type, **kwargs):
        if target_type not in TARGET_TYPES:
            raise ValueError(f"Unknown target type: {target_type}")
        self.target_type = target_type
        self.kwargs      = kwargs
        self.timeout     = kwargs.get("timeout") or config.TARGET_TIMEOUT
        self.logs        = []
        self.calls       = 0
        self.prompt_tokens = self.completion_tokens = 0
        self._lock       = threading.Lock()
        self._local      = threading.local()
        self._client     = None
        self._setup()

    def _setup(self):
        kw = self.kwargs
        if self.target_type in ("simulation", "groq"):
            self.model         = kw.get("model")          # None: resolved on first use
            self.system_prompt = kw.get("system_prompt") or "You are a helpful assistant."
            # "groq" scans the user's own Groq model with their key; "simulation"
            # uses the server's key.
            self.api_key = kw.get("api_key") if self.target_type == "groq" else None

        elif self.target_type == "openai_compatible":
            self.api_url       = (kw.get("api_url") or "").rstrip("/")
            self.api_key       = kw.get("api_key")
            self.model         = kw.get("model") or DEFAULT_MODELS["openai_compatible"]
            self.system_prompt = kw.get("system_prompt")   # optional, prepended if given

        elif self.target_type == "custom_rest":
            self.api_url      = kw.get("api_url")
            self.api_key      = kw.get("api_key")
            self.input_field  = kw.get("input_field") or "message"
            self.output_field = kw.get("output_field") or "response"

        elif self.target_type == "graphql":
            self.api_url = kw.get("api_url")
            self.api_key = kw.get("api_key")
            self.query   = kw.get("query") or (
                "mutation SendMessage($message: String!) {"
                " sendMessage(input: { message: $message }) { response } }"
            )

        elif self.target_type == "websocket":
            self.ws_url       = kw.get("ws_url")
            self.api_key      = kw.get("api_key")
            self.input_field  = kw.get("input_field") or "message"
            self.output_field = kw.get("output_field") or "response"

    # ── Auto detection ───────────────────────────────────────
    @classmethod
    def auto_detect(cls, url, api_key=None, **kwargs):
        """Guesses the target type from the URL."""
        if url.startswith(("ws://", "wss://")):
            return cls(target_type="websocket", ws_url=url, api_key=api_key, **kwargs)
        if "graphql" in url.lower():
            return cls(target_type="graphql", api_url=url, api_key=api_key, **kwargs)
        if "openai.com" in url or "api.groq.com" in url or url.rstrip("/").endswith("/v1"):
            return cls(target_type="openai_compatible", api_url=url, api_key=api_key, **kwargs)
        return cls(target_type="custom_rest", api_url=url, api_key=api_key, **kwargs)

    # ── Send ─────────────────────────────────────────────────
    def send(self, message):
        """Sends one message to the target and returns its reply as text."""
        start = time.time()
        try:
            if self.target_type in ("simulation", "groq"):
                reply = self._send_groq(message)
            elif self.target_type == "openai_compatible":
                reply = self._send_openai(message)
            elif self.target_type == "custom_rest":
                reply = self._send_rest(message)
            elif self.target_type == "graphql":
                reply = self._send_graphql(message)
            else:
                reply = self._send_websocket(message)
            reply = reply if isinstance(reply, str) else json.dumps(reply, ensure_ascii=False)
            self._log(message, reply, time.time() - start, "SUCCESS")
            return reply
        except Exception as e:
            self._log(message, f"ERROR: {e}", time.time() - start, "ERROR")
            raise

    @property
    def supports_history(self):
        return self.target_type in HISTORY_TYPES

    def converse(self, turns):
        """Plays user turns in order, keeping the chat history. Returns the assistant replies."""
        if not self.supports_history:
            raise RuntimeError(f"{self.target_type} targets don't keep chat history")
        history, replies = [], []
        for turn in turns:
            history.append({"role": "user", "content": turn})
            start = time.time()
            from retry import call_with_retry
            reply = call_with_retry(self._chat, history) or ""
            self._log(turn, reply, time.time() - start, "SUCCESS")
            history.append({"role": "assistant", "content": reply})
            replies.append(reply)
        return replies

    def _chat(self, history):
        if self.target_type in ("simulation", "groq"):
            response = self._groq.chat.completions.create(
                model=self._groq_model(),
                messages=[{"role": "system", "content": self.system_prompt}, *history],
                timeout=self.timeout,
            )
            self._count(response.usage)
            return response.choices[0].message.content or ""
        url = self.api_url if self.api_url.endswith("/chat/completions") else f"{self.api_url}/chat/completions"
        messages = ([{"role": "system", "content": self.system_prompt}] if self.system_prompt else []) + history
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = self._post(url, headers=headers, json={"model": self.model, "messages": messages}).json()
        self._count(data.get("usage") if isinstance(data, dict) else None)
        return data["choices"][0]["message"].get("content") or ""

    def get_baseline(self, question=None):
        """A normal, harmless reply used to spot behavior changes under attack."""
        return self.send(question or self.kwargs.get("baseline_question") or DEFAULT_BASELINE_QUESTION)

    # ── Transports ───────────────────────────────────────────
    @property
    def _groq_key(self):
        """A Groq target runs on the user's own key, never on this server's (that's what a simulation is for)."""
        return self.api_key if self.target_type == "groq" else config.GROQ_API_KEY

    @property
    def _groq(self):
        if self._client is None:
            from groq import Groq
            if not self._groq_key:
                raise RuntimeError("No Groq API key: enter your Groq API key for this target"
                                   if self.target_type == "groq" else "No Groq API key: set GROQ_API_KEY on the server")
            self._client = Groq(api_key=self._groq_key, max_retries=0)
        return self._client

    def _session(self):
        session = getattr(self._local, "session", None)
        if session is None:
            session = self._local.session = netguard.safe_session()
        return session

    def _post(self, url, **kwargs):
        """POSTs and reads the reply, at most MAX_REPLY_BYTES and self.timeout seconds in all
        (requests' timeout is per read, so a reply that trickles in would never time out)."""
        netguard.check_url(url)
        response = self._session().post(url, timeout=self.timeout, allow_redirects=False, stream=True, **kwargs)
        if 300 <= response.status_code < 400:
            response.close()
            raise RuntimeError(f"Target answered with a redirect ({response.status_code}); "
                               "use the final URL instead")
        netguard.read_capped(response, MAX_REPLY_BYTES, self.timeout)
        response.raise_for_status()
        return response

    def _groq_model(self):
        if not self.model:
            import groq_models
            self.model = groq_models.resolve(config.DEFAULT_MODEL, groq_models.TARGET_PREFERENCES, self._groq_key)
        return self.model

    def _send_groq(self, message):
        response = self._groq.chat.completions.create(
            model=self._groq_model(),
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user",   "content": message},
            ],
            timeout=self.timeout,
        )
        self._count(response.usage)
        return response.choices[0].message.content or ""

    def _send_openai(self, message):
        url = self.api_url if self.api_url.endswith("/chat/completions") \
            else f"{self.api_url}/chat/completions"
        messages = [{"role": "user", "content": message}]
        if self.system_prompt:
            messages.insert(0, {"role": "system", "content": self.system_prompt})
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = self._post(url, headers=headers, json={"model": self.model, "messages": messages}).json()
        self._count(data.get("usage") if isinstance(data, dict) else None)
        return data["choices"][0]["message"].get("content") or ""

    def _send_rest(self, message):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = self._post(self.api_url, headers=headers, json={self.input_field: message}).json()
        self._count()
        if isinstance(data, dict):
            return data.get(self.output_field, json.dumps(data, ensure_ascii=False))
        return json.dumps(data, ensure_ascii=False)

    def _send_graphql(self, message):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        data = self._post(self.api_url, headers=headers,
                          json={"query": self.query, "variables": {"message": message}}).json()
        self._count()
        # Return the first string we find under "data".
        node = data.get("data") if isinstance(data, dict) else None
        while isinstance(node, dict) and node:
            node = next(iter(node.values()))
        return node if isinstance(node, str) else json.dumps(data, ensure_ascii=False)

    def _send_websocket(self, message):
        import websocket  # websocket-client; imported lazily, only WS targets need it

        headers = [f"Authorization: Bearer {self.api_key}"] if self.api_key else []
        conn = websocket.create_connection(self.ws_url, header=headers, timeout=self.timeout)
        try:
            conn.send(json.dumps({self.input_field: message}))
            raw = conn.recv()
        finally:
            conn.close()
        self._count()
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            return str(raw)
        return data.get(self.output_field, str(data)) if isinstance(data, dict) else str(data)

    # ── Bookkeeping ──────────────────────────────────────────
    def _count(self, usage=None):
        from judge import usage_tokens
        tokens_in, tokens_out = usage_tokens(usage)
        with self._lock:
            self.calls += 1
            self.prompt_tokens += tokens_in
            self.completion_tokens += tokens_out

    def _log(self, message, response, elapsed, status):
        with self._lock:
            if len(self.logs) < 2000:
                self.logs.append({
                    "message" : message[:50] + "...",
                    "response": str(response)[:50] + "...",
                    "elapsed" : round(elapsed, 2),
                    "status"  : status,
                })

    def get_logs(self):
        return self.logs

    def print_logs(self):
        print(f"\nConnection logs ({len(self.logs)} requests):")
        for i, entry in enumerate(self.logs):
            print(f"[{i + 1}] {entry['status']} - {entry['elapsed']}s")
            print(f"     Message  : {entry['message']}")
            print(f"     Response : {entry['response']}")


def create_target_from_config(config_path):
    """Creates a Target from a JSON config file."""
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    target_type = cfg.pop("target_type")
    return Target(target_type=target_type, **cfg)
