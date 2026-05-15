"""
LLM Scanner SDK
~~~~~~~~~~~~~~~

The official Python SDK for LLM Scanner.
Automatically find security vulnerabilities in AI applications.

Usage :
    from llmscanner import Scanner

    scanner = Scanner(groq_api_key="gsk_...")
    report  = scanner.scan(
        target_name   = "My Banking Bot",
        system_prompt = "You are a banking assistant..."
    )

    print(f"Security Score : {report.security_score}%")
    print(f"Critical       : {len(report.critical_findings)}")

    for finding in report.critical_findings :
        print(finding)
"""

from .scanner    import Scanner
from .models     import ScanReport, ScanSummary, Finding
from .exceptions import (
    LLMScannerError,
    APIKeyError,
    ScanError,
    RateLimitError,
    TargetError,
    ReportError
)

__version__ = "2.0.0"
__author__  = "Mahdi EL"
__all__     = [
    "Scanner",
    "ScanReport",
    "ScanSummary",
    "Finding",
    "LLMScannerError",
    "APIKeyError",
    "ScanError",
    "RateLimitError",
]
