"""LLM Scanner SDK: data models returned by the client."""
from dataclasses import dataclass, field
from typing import List, Optional

SEVERITY_RANK = {"SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    """One attack and how the target handled it."""
    category        : str
    attack          : str
    response        : str
    score           : int
    severity        : str
    reason          : str
    behavior_changed: bool = False
    confidence      : str = "LOW"
    owasp           : List[str] = field(default_factory=list)

    @property
    def is_critical(self):
        return self.severity == "CRITICAL"

    @property
    def is_high(self):
        return self.severity == "HIGH"

    @property
    def is_safe(self):
        return self.severity == "SAFE"

    @property
    def is_error(self):
        return self.severity == "ERROR"

    @property
    def failed(self):
        """True when the attack succeeded (any severity above SAFE)."""
        return SEVERITY_RANK.get(self.severity, 0) > 0

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            category=d.get("category", ""), attack=d.get("attack", ""), response=d.get("response", ""),
            score=int(d.get("score") or 0), severity=d.get("severity", "SAFE"), reason=d.get("reason", ""),
            behavior_changed=bool(d.get("behavior_changed")), confidence=d.get("confidence", "LOW"),
            owasp=list(d.get("owasp") or []),
        )

    def __str__(self):
        return f"[{self.severity}] {self.category} - score {self.score}/10 - {self.reason}"


@dataclass
class ScanSummary:
    """Counts per severity, plus the score and grade."""
    total_attacks : int
    critical      : int
    high          : int
    medium        : int
    low           : int
    safe          : int
    security_score: int
    grade         : Optional[str] = None
    errors        : int = 0

    @property
    def is_secure(self):
        return self.critical == 0 and self.high == 0 and self.security_score >= 80

    @property
    def needs_attention(self):
        return self.critical > 0 or self.high > 5

    @classmethod
    def from_dict(cls, d: dict, total: int = 0) -> "ScanSummary":
        return cls(
            total_attacks=int(d.get("total") or total or 0), critical=int(d.get("critical") or 0),
            high=int(d.get("high") or 0), medium=int(d.get("medium") or 0), low=int(d.get("low") or 0),
            safe=int(d.get("safe") or 0), security_score=int(d.get("security_score") or 0),
            grade=d.get("grade"), errors=int(d.get("errors") or 0),
        )

    def __str__(self):
        return (f"Security score {self.security_score}/100 (grade {self.grade or '?'}) | "
                f"critical {self.critical} | high {self.high} | safe {self.safe}")


@dataclass
class Scan:
    """A scan as it runs: status and progress."""
    scan_id         : str
    target_name     : str
    status          : str
    progress        : int = 0
    completed_attacks: int = 0
    total_attacks   : int = 0
    error_message   : Optional[str] = None

    @property
    def done(self):
        return self.status in ("complete", "failed", "cancelled")

    @classmethod
    def from_dict(cls, d: dict) -> "Scan":
        return cls(scan_id=d["scan_id"], target_name=d.get("target_name", ""), status=d.get("status", "pending"),
                   progress=int(d.get("progress") or 0), completed_attacks=int(d.get("completed_attacks") or 0),
                   total_attacks=int(d.get("total_attacks") or 0), error_message=d.get("error_message"))


@dataclass
class ScanReport:
    """A finished scan: summary, findings and recommendations."""
    scan_id        : str
    scan_date      : str
    target_name    : str
    summary        : ScanSummary
    findings       : List[Finding] = field(default_factory=list)
    recommendations: List[dict] = field(default_factory=list)

    @property
    def security_score(self):
        return self.summary.security_score

    @property
    def grade(self):
        return self.summary.grade

    @property
    def critical_findings(self):
        return [f for f in self.findings if f.severity == "CRITICAL"]

    @property
    def high_findings(self):
        return [f for f in self.findings if f.severity == "HIGH"]

    @property
    def failed_findings(self):
        return [f for f in self.findings if f.failed]

    @property
    def is_secure(self):
        return self.summary.is_secure

    def worst_severity(self) -> str:
        failed = [f.severity for f in self.findings if f.failed]
        return max(failed, key=SEVERITY_RANK.get) if failed else "SAFE"

    def has_findings_at_or_above(self, severity: str) -> bool:
        floor = SEVERITY_RANK[severity.upper()]
        return any(SEVERITY_RANK.get(f.severity, 0) >= floor for f in self.findings if f.failed)

    def get_findings_by_category(self, category):
        return [f for f in self.findings if f.category == category]

    def get_findings_by_severity(self, severity):
        return [f for f in self.findings if f.severity == severity]

    @classmethod
    def from_scan(cls, scan: dict) -> "ScanReport":
        data = scan.get("results") or {}
        results = data.get("results") or []
        return cls(
            scan_id=scan.get("scan_id", ""), scan_date=data.get("scan_date") or scan.get("completed_at") or "",
            target_name=scan.get("target_name", ""),
            summary=ScanSummary.from_dict({**(scan.get("summary") or {}), **(data.get("summary") or {})},
                                          total=len(results)),
            findings=[Finding.from_dict(r) for r in results],
            recommendations=scan.get("recommendations") or [],
        )

    def print_summary(self):
        print(f"LLM Scanner report: {self.target_name}")
        print(f"  {self.summary}")
        for rec in self.recommendations[:5]:
            print(f"  {rec['priority']} {rec['title']} ({rec['failed']} failed)")

    def __str__(self):
        return f"ScanReport({self.target_name}, score={self.security_score}, grade={self.grade})"
