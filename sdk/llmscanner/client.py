"""LLM Scanner SDK: HTTP client for the LLM Scanner API.

    from llmscanner import Client
    client = Client(api_key="llmsk_...")            # or set LLMSCANNER_API_KEY
    scan = client.scan("Support bot", target_type="openai_compatible",
                       api_url="https://api.openai.com/v1", api_key="sk-...", model="gpt-4o-mini")
    report = client.wait(scan.scan_id)
    print(report.security_score, report.grade)
"""
import os
import time
from typing import Callable, List, Optional

import requests

from .exceptions import (APIKeyError, LLMScannerError, QuotaError, RateLimitError,
                         ReportError, ScanError, TargetError)
from .models import Scan, ScanReport

DEFAULT_API_URL = "http://localhost:8000"
_FORMATS = {"pdf": "/download", "html": "/download/html", "md": "/download/md", "json": "/download/json"}


class Client:
    """A thin client for the LLM Scanner API. Authenticates with an API key (llmsk_...)."""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None,
                 timeout: float = 30.0, session: Optional[requests.Session] = None):
        self.api_key = api_key or os.getenv("LLMSCANNER_API_KEY")
        if not self.api_key:
            raise APIKeyError("An API key is required. Create one in Settings, then pass "
                              "Client(api_key='llmsk_...') or set LLMSCANNER_API_KEY.")
        self.base_url = (base_url or os.getenv("LLMSCANNER_API_URL") or DEFAULT_API_URL).rstrip("/")
        self.timeout = timeout
        self._http = session or requests.Session()
        self._http.headers.update({"X-API-Key": self.api_key, "User-Agent": "llmscanner-python/3.0"})

    # ── HTTP ─────────────────────────────────────────────────
    def _request(self, method: str, path: str, **kwargs):
        kwargs.setdefault("timeout", self.timeout)
        try:
            response = self._http.request(method, f"{self.base_url}{path}", **kwargs)
        except requests.RequestException as e:
            raise LLMScannerError(f"Can't reach {self.base_url}: {e}") from e
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail")
            except ValueError:
                detail = response.text[:300]
            if isinstance(detail, list):
                detail = "; ".join(str(d.get("msg", d)) for d in detail)
            message = detail or f"HTTP {response.status_code}"
            error = {401: APIKeyError, 402: QuotaError, 429: RateLimitError}.get(response.status_code)
            if error is None and response.status_code == 400 and "URL" in str(message):
                error = TargetError
            raise (error or LLMScannerError)(message, status=response.status_code)
        return response

    def _json(self, method: str, path: str, **kwargs):
        return self._request(method, path, **kwargs).json()

    # ── Scans ────────────────────────────────────────────────
    def scan(self, target_name: str, *, target_type: str = "simulation", api_url: Optional[str] = None,
             api_key: Optional[str] = None, model: Optional[str] = None, system_prompt: Optional[str] = None,
             categories: Optional[List[str]] = None, baseline_question: Optional[str] = None,
             input_field: Optional[str] = None, output_field: Optional[str] = None,
             target_id: Optional[str] = None, include_custom_prompts: bool = True,
             quick: bool = False) -> Scan:
        """Queues a scan and returns immediately. Use wait() to get the report.
        quick=True runs about 5 attacks per category (~110) instead of all ~1,090."""
        body = {"target_name": target_name, "target_type": target_type, "api_url": api_url,
                "api_key": api_key, "model": model, "system_prompt": system_prompt,
                "categories": categories, "baseline_question": baseline_question,
                "input_field": input_field, "output_field": output_field, "target_id": target_id,
                "include_custom_prompts": include_custom_prompts, "quick": quick}
        data = self._json("POST", "/scan", json={k: v for k, v in body.items() if v is not None})
        return Scan(scan_id=data["scan_id"], target_name=target_name, status=data.get("status", "pending"))

    def get(self, scan_id: str) -> dict:
        """The raw scan as the API returns it (status, progress, findings once complete)."""
        return self._json("GET", f"/scan/{scan_id}")

    def status(self, scan_id: str) -> Scan:
        return Scan.from_dict(self.get(scan_id))

    # Polls that may fail in a row (the API restarting during a deploy, a 502 from its proxy) before wait()
    # gives up: a scan resumes after a restart, so a long CI scan shouldn't fail on one blip.
    POLL_RETRIES = 6

    def wait(self, scan_id: str, poll_interval: float = 5.0, timeout: Optional[float] = None,
             on_progress: Optional[Callable[[Scan], None]] = None) -> ScanReport:
        """Polls until the scan finishes. Raises ScanError if it fails or is cancelled. Unreachable-API,
        5xx and 429 answers are retried up to POLL_RETRIES times in a row."""
        started, failures = time.monotonic(), 0
        while True:
            try:
                raw = self.get(scan_id)
            except LLMScannerError as e:
                passing = e.status is None or e.status >= 500 or e.status == 429
                failures += 1
                if not passing or failures > self.POLL_RETRIES or \
                        (timeout is not None and time.monotonic() - started > timeout):
                    raise
                time.sleep(min(poll_interval * failures, 30))
                continue
            failures = 0
            scan = Scan.from_dict(raw)
            if on_progress:
                on_progress(scan)
            if scan.status == "complete":
                return ScanReport.from_scan(raw)
            if scan.status in ("failed", "cancelled"):
                raise ScanError(f"Scan {scan.status}: {scan.error_message or 'no details'}")
            if timeout is not None and time.monotonic() - started > timeout:
                raise ScanError(f"Timed out after {timeout:.0f}s waiting for scan {scan_id}")
            time.sleep(poll_interval)

    def results(self, scan_id: str) -> ScanReport:
        """The report of a finished scan."""
        raw = self.get(scan_id)
        if raw.get("status") != "complete":
            raise ScanError(f"Scan is {raw.get('status')}, not complete")
        return ScanReport.from_scan(raw)

    def list(self, limit: int = 50, offset: int = 0, status: Optional[str] = None,
             target_name: Optional[str] = None) -> dict:
        params = {"limit": limit, "offset": offset, "status": status, "target_name": target_name}
        return self._json("GET", "/scans", params={k: v for k, v in params.items() if v is not None})

    def compare(self, base_scan_id: str, head_scan_id: str) -> dict:
        """Score change plus failures introduced and fixed between two finished scans."""
        return self._json("GET", f"/scan/compare/{base_scan_id}/{head_scan_id}")

    def triage(self, scan_id: str, key: str, status: str, note: Optional[str] = None) -> dict:
        """Marks a failed finding (Finding.key) as "false_positive" or "accepted_risk", or "open" to clear
        the mark. It applies to that attack in every scan of the target, and --fail-on stops counting it."""
        body = {"key": key, "status": status, **({"note": note} if note else {})}
        return self._json("PUT", f"/scan/{scan_id}/triage", json=body)

    def cancel(self, scan_id: str) -> dict:
        return self._json("POST", f"/scan/{scan_id}/cancel")

    def delete(self, scan_id: str) -> dict:
        return self._json("DELETE", f"/scan/{scan_id}")

    def download(self, scan_id: str, fmt: str = "pdf", path: Optional[str] = None) -> str:
        """Saves a report (pdf, html, md or json) and returns its path."""
        if fmt not in _FORMATS:
            raise ValueError(f"Format must be one of {sorted(_FORMATS)}")
        try:
            response = self._request("GET", f"{_FORMATS[fmt]}/{scan_id}", timeout=max(self.timeout, 120))
        except LLMScannerError as e:
            raise ReportError(str(e), status=e.status) from e
        path = path or f"llm-scanner-{scan_id}.{fmt}"
        with open(path, "wb") as f:
            f.write(response.content)
        return path

    def categories(self) -> list:
        """The built-in attack categories."""
        return self._json("GET", "/categories")["categories"]

    # ── Runtime AI firewall ──────────────────────────────────
    def check_input(self, text: str, threshold: float = 0.8) -> dict:
        """Screens a user message before it reaches your model.
        Returns {"verdict": "allow" | "review" | "block", "score", "reasons", "usage", ...}."""
        return self._json("POST", "/api/firewall/check", json={"text": text, "threshold": threshold})

    def check_output(self, text: str, system_prompt: Optional[str] = None, canary: Optional[str] = None) -> dict:
        """Screens a model reply before it reaches your user: leaked secrets, the canary, the system prompt.
        Returns {"verdict", "reasons", "findings", "redacted", "masked"}: "redacted" is the reply with
        secrets, card numbers and the canary replaced by [REDACTED]; "masked" is how many were replaced."""
        body = {"text": text}
        if system_prompt:
            body["system_prompt"] = system_prompt
        if canary:
            body["canary"] = canary
        return self._json("POST", "/api/firewall/check-output", json=body)

    def firewall_usage(self) -> dict:
        """{"used", "limit"}: firewall checks used today (UTC) and your plan's daily allowance."""
        return self._json("GET", "/api/firewall/usage")
