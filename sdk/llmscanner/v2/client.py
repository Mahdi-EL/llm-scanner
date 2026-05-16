# sdk/llmscanner/v2/client.py
import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
from datetime import datetime
from typing import Optional, List, Dict, Any


# ── SDK V2 Client ─────────────────────────────────────────────
class LLMScannerClient:
    """
    Official LLM Scanner SDK V2.
    Full enterprise features included.

    Usage:
        from llmscanner.v2 import LLMScannerClient

        client = LLMScannerClient(api_key="gsk_...")

        # Quick scan
        result = client.scan("My App", "Your system prompt...")

        # Full pipeline
        result = client.pipeline("My App", "Your system prompt...")

        # Predict risks
        risks = client.predict("Your system prompt...")
    """

    VERSION = "2.0.0"

    def __init__(
        self,
        api_key     =None,
        base_url    ="http://localhost:8000",
        verbose     =True,
        output_dir  ="results"
    ):
        self.api_key    = api_key or os.getenv("GROQ_API_KEY")
        self.base_url   = base_url
        self.verbose    = verbose
        self.output_dir = output_dir

        if not self.api_key:
            raise ValueError(
                "API key required. Get free key at console.groq.com"
            )

        os.environ["GROQ_API_KEY"] = self.api_key
        os.makedirs(output_dir, exist_ok=True)

    def scan(
        self,
        target_name  : str,
        system_prompt: str,
        profile      : str = "standard",
        categories   : Optional[List[str]] = None,
        output_name  : Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Runs a security scan.
        Returns dict with score, findings, and report paths.
        """
        import sys
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ))

        from target  import Target
        from scanner import run_full_scan

        if self.verbose:
            print(f"🔐 Scanning: {target_name}")

        target = Target(
            target_type  ="simulation",
            system_prompt=system_prompt
        )

        output = output_name or \
                 f"sdk_v2_{target_name.lower().replace(' ','_')}"

        report_data = run_full_scan(
            target     =target,
            target_name=target_name,
            output_name=output,
            categories =categories
        )

        return {
            "target_name"   : target_name,
            "security_score": report_data["summary"]["security_score"],
            "critical"      : report_data["summary"]["critical"],
            "high"          : report_data["summary"]["high"],
            "medium"        : report_data["summary"]["medium"],
            "safe"          : report_data["summary"]["safe"],
            "total_attacks" : report_data["total_attacks"],
            "pdf_path"      : f"{self.output_dir}/{output}.pdf",
            "html_path"     : f"{self.output_dir}/{output}.html",
            "json_path"     : f"{self.output_dir}/{output}.json",
            "findings"      : report_data.get("results", [])
        }

    def predict(
        self,
        system_prompt: str
    ) -> Dict[str, Any]:
        """Predicts vulnerabilities before scanning."""
        import sys
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ))

        from vulnerability_predictor import VulnerabilityPredictor

        predictor  = VulnerabilityPredictor()
        risk_score = predictor.calculate_overall_risk_score(system_prompt)
        risk_level = predictor.get_risk_level(risk_score)
        top_cats   = predictor.predict_vulnerable_categories(system_prompt)
        prediction = predictor.predict_scan_results(system_prompt)

        return {
            "risk_score"               : risk_score,
            "risk_level"               : risk_level,
            "top_vulnerable_categories": top_cats[:5],
            "predicted_score"          : prediction["estimated_score"],
            "predicted_findings"       : prediction["estimated_findings"]
        }

    def remediate(
        self,
        system_prompt    : str,
        scan_results_path: str
    ) -> Dict[str, Any]:
        """Auto-remediates vulnerabilities in system prompt."""
        import sys
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ))

        from auto_remediation import AIRemediator

        remediator = AIRemediator()
        hardened, report = remediator.auto_remediate(
            scan_results_path, system_prompt
        )

        return {
            "hardened_prompt": hardened,
            "fixes_applied"  : report["fixes_applied"],
            "improvement"    : report.get("improvement", 0)
        }

    def pipeline(
        self,
        target_name  : str,
        system_prompt: str,
        steps        : Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Runs full automation pipeline."""
        import sys
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ))

        from automation_pipeline import run_pipeline

        return run_pipeline(
            system_prompt=system_prompt,
            target_name  =target_name,
            steps        =steps or ["predict","scan","remediate","report"]
        )

    def scorecard(
        self,
        scan_results_path: str,
        target_name      : str = "AI Application"
    ) -> Dict[str, Any]:
        """Generates security scorecard."""
        import sys
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ))

        from scorecard import SecurityScorecard
        sc = SecurityScorecard(scan_results_path)
        return sc.calculate_scorecard()

    def compliance(
        self,
        scan_results_path: str,
        frameworks       : Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Checks compliance against frameworks."""
        import sys
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ))

        from compliance_engine import ComplianceChecker

        checker    = ComplianceChecker(scan_results_path)
        frameworks = frameworks or ["owasp_llm_top10"]
        results    = {}

        for fw in frameworks:
            result = checker.check_framework(fw)
            if result:
                results[fw] = {
                    "compliant"     : result["overall_compliant"],
                    "score"         : result["compliance_score"],
                    "failed_controls": result["required_failed"]
                }

        return results

    def copilot(
        self,
        question         : str,
        scan_results_path: Optional[str] = None
    ) -> str:
        """Asks the AI security copilot a question."""
        import sys
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ))

        from security_copilot import SecurityCopilot
        cop = SecurityCopilot(scan_results_path)
        return cop.ask(question)

    def issue_certificate(
        self,
        scan_results_path: str,
        target_name      : str
    ) -> Optional[str]:
        """Issues security certificate if eligible."""
        import sys
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ))

        from certificate_authority import AISecurityCertificateAuthority
        ca = AISecurityCertificateAuthority()
        return ca.issue_certificate(scan_results_path, target_name)

    def get_stats(self) -> Dict[str, Any]:
        """Gets global security statistics."""
        import sys
        sys.path.insert(0, os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ))

        from analytics import AnalyticsEngine
        engine = AnalyticsEngine()
        return engine.generate_analytics_report()

    def __repr__(self):
        return f"LLMScannerClient(v{self.VERSION})"