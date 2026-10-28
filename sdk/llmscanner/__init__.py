"""
LLM Scanner SDK
~~~~~~~~~~~~~~~

Python client for the LLM Scanner API: start scans of your AI applications,
wait for the result, download reports, and gate CI on the findings.

    from llmscanner import Client

    client = Client(api_key="llmsk_...", base_url="https://your-api")
    scan = client.scan("Support bot", target_type="openai_compatible",
                       api_url="https://api.openai.com/v1", api_key="sk-...", model="gpt-4o-mini")
    report = client.wait(scan.scan_id)
    print(report.security_score, report.grade)
    for finding in report.critical_findings:
        print(finding)
"""

from .client import Client
from .exceptions import (
    APIKeyError,
    LLMScannerError,
    QuotaError,
    RateLimitError,
    ReportError,
    ScanError,
    TargetError,
    WaitTimeout,
)
from .models import Finding, Scan, ScanReport, ScanSummary

__version__ = "3.1.0"
__all__ = [
    "Client",
    "Scan",
    "ScanReport",
    "ScanSummary",
    "Finding",
    "LLMScannerError",
    "APIKeyError",
    "QuotaError",
    "RateLimitError",
    "ScanError",
    "WaitTimeout",
    "TargetError",
    "ReportError",
]
