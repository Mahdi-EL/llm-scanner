"""
LLM Scanner SDK — Data Models
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict


@dataclass
class Finding:
    """Represents a single vulnerability finding."""
    category        : str
    attack          : str
    response        : str
    score           : int
    severity        : str
    reason          : str
    behavior_changed: bool
    confidence      : str

    @property
    def is_critical(self):
        return self.severity == "CRITICAL"

    @property
    def is_high(self):
        return self.severity == "HIGH"

    @property
    def is_safe(self):
        return self.severity == "SAFE"

    def __str__(self):
        return (
            f"[{self.severity}] {self.category} — "
            f"Score: {self.score}/10 — {self.reason}"
        )


@dataclass
class ScanSummary:
    """Summary statistics of a scan."""
    total_attacks  : int
    critical       : int
    high           : int
    medium         : int
    low            : int
    safe           : int
    security_score : int

    @property
    def is_secure(self):
        return self.security_score >= 70

    @property
    def needs_attention(self):
        return self.critical > 0 or self.high > 5

    def __str__(self):
        return (
            f"Security Score: {self.security_score}% | "
            f"Critical: {self.critical} | "
            f"High: {self.high} | "
            f"Safe: {self.safe}"
        )


@dataclass
class ScanReport:
    """
    Complete scan report returned by the SDK.
    """
    scan_date   : str
    target_name : str
    summary     : ScanSummary
    findings    : List[Finding] = field(default_factory=list)
    pdf_path    : Optional[str] = None
    html_path   : Optional[str] = None
    json_path   : Optional[str] = None

    @property
    def security_score(self):
        return self.summary.security_score

    @property
    def critical_findings(self):
        return [f for f in self.findings if f.severity == "CRITICAL"]

    @property
    def high_findings(self):
        return [f for f in self.findings if f.severity == "HIGH"]

    @property
    def is_secure(self):
        return self.summary.is_secure

    def get_findings_by_category(self, category):
        return [f for f in self.findings if f.category == category]

    def get_findings_by_severity(self, severity):
        return [f for f in self.findings if f.severity == severity]

    def print_summary(self):
        print(f"\n{'='*50}")
        print(f"  LLM Scanner Report — {self.target_name}")
        print(f"{'='*50}")
        print(f"  Date           : {self.scan_date}")
        print(f"  Security Score : {self.summary.security_score}%")
        print(f"  Critical       : {self.summary.critical}")
        print(f"  High           : {self.summary.high}")
        print(f"  Medium         : {self.summary.medium}")
        print(f"  Safe           : {self.summary.safe}")
        if self.pdf_path:
            print(f"  PDF Report     : {self.pdf_path}")
        print(f"{'='*50}\n")

    def __str__(self):
        return f"ScanReport({self.target_name}, score={self.security_score}%)"
    