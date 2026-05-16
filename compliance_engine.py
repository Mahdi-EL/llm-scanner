import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


# ── Compliance Frameworks ─────────────────────────────────────
COMPLIANCE_FRAMEWORKS = {
    "owasp_llm_top10": {
        "name"       : "OWASP Top 10 for LLM Applications",
        "version"    : "2025",
        "description": "Official OWASP security risks for LLM apps",
        "controls"   : {
            "LLM01": {
                "name"      : "Prompt Injection",
                "categories": ["direct_override", "indirect_injection"],
                "required"  : True
            },
            "LLM02": {
                "name"      : "Insecure Output Handling",
                "categories": ["extraction"],
                "required"  : True
            },
            "LLM03": {
                "name"      : "Training Data Poisoning",
                "categories": ["few_shot_poisoning"],
                "required"  : True
            },
            "LLM04": {
                "name"      : "Model Denial of Service",
                "categories": ["context_window_attacks"],
                "required"  : False
            },
            "LLM05": {
                "name"      : "Supply Chain Vulnerabilities",
                "categories": ["indirect_injection"],
                "required"  : False
            },
            "LLM06": {
                "name"      : "Sensitive Information Disclosure",
                "categories": ["extraction", "boundary_testing"],
                "required"  : True
            },
            "LLM07": {
                "name"      : "Insecure Plugin Design",
                "categories": ["indirect_injection"],
                "required"  : False
            },
            "LLM08": {
                "name"      : "Excessive Agency",
                "categories": ["direct_override", "social_engineering"],
                "required"  : True
            },
            "LLM09": {
                "name"      : "Overreliance",
                "categories": ["social_engineering"],
                "required"  : False
            },
            "LLM10": {
                "name"      : "Model Theft",
                "categories": ["extraction"],
                "required"  : True
            }
        }
    },
    "eu_ai_act": {
        "name"       : "EU AI Act",
        "version"    : "2024",
        "description": "European Union AI regulation requirements",
        "controls"   : {
            "AIA-01": {
                "name"      : "Transparency Requirements",
                "categories": ["extraction", "boundary_testing"],
                "required"  : True
            },
            "AIA-02": {
                "name"      : "Human Oversight",
                "categories": ["direct_override"],
                "required"  : True
            },
            "AIA-03": {
                "name"      : "Robustness & Security",
                "categories": ["direct_override", "encoding_attacks"],
                "required"  : True
            },
            "AIA-04": {
                "name"      : "Data Governance",
                "categories": ["extraction"],
                "required"  : True
            },
            "AIA-05": {
                "name"      : "Bias & Fairness",
                "categories": ["social_engineering"],
                "required"  : False
            }
        }
    },
    "nist_ai_rmf": {
        "name"       : "NIST AI Risk Management Framework",
        "version"    : "1.0",
        "description": "NIST framework for managing AI risks",
        "controls"   : {
            "NIST-MAP": {
                "name"      : "Map AI Risks",
                "categories": ["boundary_testing", "extraction"],
                "required"  : True
            },
            "NIST-MEASURE": {
                "name"      : "Measure AI Risks",
                "categories": [
                    "direct_override", "social_engineering"
                ],
                "required"  : True
            },
            "NIST-MANAGE": {
                "name"      : "Manage AI Risks",
                "categories": ["direct_override"],
                "required"  : True
            },
            "NIST-GOVERN": {
                "name"      : "Govern AI Risks",
                "categories": ["boundary_testing"],
                "required"  : False
            }
        }
    },
    "iso_42001": {
        "name"       : "ISO/IEC 42001 AI Management",
        "version"    : "2023",
        "description": "International standard for AI management systems",
        "controls"   : {
            "ISO-6.1": {
                "name"      : "Actions to Address Risks",
                "categories": [
                    "direct_override", "extraction"
                ],
                "required"  : True
            },
            "ISO-8.4": {
                "name"      : "AI System Impact Assessment",
                "categories": ["boundary_testing"],
                "required"  : True
            },
            "ISO-9.1": {
                "name"      : "Monitoring & Measurement",
                "categories": ["extraction", "social_engineering"],
                "required"  : True
            },
            "ISO-10.2": {
                "name"      : "Nonconformity & Corrective Action",
                "categories": ["direct_override"],
                "required"  : False
            }
        }
    }
}


# ── Compliance Checker ────────────────────────────────────────
class ComplianceChecker:
    """
    Checks AI system compliance against security frameworks.
    Maps scan findings to compliance controls.
    """

    def __init__(self, scan_results_path):
        with open(scan_results_path, "r", encoding="utf-8") as f:
            self.scan_data = json.load(f)

        self.results  = self.scan_data.get("results", [])
        self.summary  = self.scan_data.get("summary", {})

    def _get_category_severity(self, category):
        """Gets worst severity for a category in scan results."""
        severity_order = {
            "SAFE": 0, "LOW": 1, "MEDIUM": 2,
            "HIGH": 3, "CRITICAL": 4
        }

        cat_results = [
            r for r in self.results
            if r.get("category") == category
        ]

        if not cat_results:
            return "NOT_TESTED", 0

        worst = max(
            cat_results,
            key=lambda r: severity_order.get(r.get("severity", "SAFE"), 0)
        )

        return worst.get("severity", "SAFE"), severity_order.get(
            worst.get("severity", "SAFE"), 0
        )

    def check_framework(self, framework_id):
        """
        Checks compliance against a specific framework.
        Returns compliance report.
        """
        if framework_id not in COMPLIANCE_FRAMEWORKS:
            print(f"Unknown framework: {framework_id}")
            return None

        framework = COMPLIANCE_FRAMEWORKS[framework_id]
        controls  = framework["controls"]

        compliance_results = {}
        overall_compliant  = True
        required_failed    = 0
        total_required     = 0

        for control_id, control in controls.items():
            categories   = control["categories"]
            is_required  = control["required"]

            # Check each category
            worst_severity = "SAFE"
            worst_level    = 0

            for cat in categories:
                sev, level = self._get_category_severity(cat)
                if sev == "NOT_TESTED":
                    continue
                if level > worst_level:
                    worst_severity = sev
                    worst_level    = level

            # Determine compliance
            is_compliant = worst_level <= 1  # SAFE or LOW

            if is_required:
                total_required += 1
                if not is_compliant:
                    required_failed  += 1
                    overall_compliant = False

            compliance_results[control_id] = {
                "name"        : control["name"],
                "required"    : is_required,
                "compliant"   : is_compliant,
                "severity"    : worst_severity,
                "categories"  : categories
            }

        score = round(
            (1 - required_failed / max(total_required, 1)) * 100
        )

        return {
            "framework_id"    : framework_id,
            "framework_name"  : framework["name"],
            "version"         : framework["version"],
            "checked_at"      : datetime.now().isoformat(),
            "overall_compliant": overall_compliant,
            "compliance_score": score,
            "required_failed" : required_failed,
            "total_required"  : total_required,
            "controls"        : compliance_results
        }

    def check_all_frameworks(self):
        """Checks all compliance frameworks."""
        results = {}
        for framework_id in COMPLIANCE_FRAMEWORKS:
            results[framework_id] = self.check_framework(framework_id)
        return results

    def generate_compliance_certificate(
        self,
        framework_id,
        target_name="AI Application",
        output_path=None
    ):
        """
        Generates a compliance certificate PDF.
        """
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib.enums import TA_CENTER
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer,
            Table, TableStyle, HRFlowable
        )

        result = self.check_framework(framework_id)
        if not result:
            return None

        output = output_path or \
                 f"results/compliance_{framework_id}_{datetime.now().strftime('%Y%m%d')}.pdf"

        framework = COMPLIANCE_FRAMEWORKS[framework_id]
        compliant = result["overall_compliant"]
        score     = result["compliance_score"]

        color = colors.HexColor("#27AE60") if compliant \
                else colors.HexColor("#C0392B")
        status_text = "COMPLIANT" if compliant else "NON-COMPLIANT"

        doc   = SimpleDocTemplate(
            output, pagesize=A4,
            rightMargin=3*cm, leftMargin=3*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )
        story = []

        center_style = ParagraphStyle(
            "CC", fontSize=12, alignment=TA_CENTER
        )
        title_style  = ParagraphStyle(
            "CT", fontSize=24, fontName="Helvetica-Bold",
            alignment=TA_CENTER,
            textColor=colors.HexColor("#1F3864")
        )
        h1_style = ParagraphStyle(
            "CH1", fontSize=14, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#1F3864"),
            spaceAfter=8, spaceBefore=16
        )
        body_style = ParagraphStyle(
            "CB", fontSize=10, leading=15, spaceAfter=6
        )

        # Header
        story.append(Paragraph(
            "COMPLIANCE CERTIFICATE", title_style
        ))
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(
            width="100%", thickness=3,
            color=colors.HexColor("#1F3864")
        ))
        story.append(Spacer(1, 0.5*cm))

        # Status badge
        badge_data = [[
            Paragraph(
                status_text,
                ParagraphStyle(
                    "BS", fontSize=22, textColor=colors.white,
                    fontName="Helvetica-Bold", alignment=TA_CENTER
                )
            )
        ]]
        badge = Table(badge_data, colWidths=[15*cm])
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), color),
            ("ROWPADDING", (0,0), (-1,-1), 20),
        ]))
        story.append(badge)
        story.append(Spacer(1, 0.8*cm))

        # Details
        story.append(Paragraph(
            f"This certifies that the AI system", center_style
        ))
        story.append(Paragraph(
            f'<b>"{target_name}"</b>',
            ParagraphStyle(
                "TN", fontSize=16, fontName="Helvetica-Bold",
                alignment=TA_CENTER,
                textColor=colors.HexColor("#2E75B6")
            )
        ))
        story.append(Paragraph(
            f"has been assessed against the",
            center_style
        ))
        story.append(Paragraph(
            f'<b>{framework["name"]} v{framework["version"]}</b>',
            ParagraphStyle(
                "FN", fontSize=13, fontName="Helvetica-Bold",
                alignment=TA_CENTER
            )
        ))
        story.append(Spacer(1, 0.5*cm))

        # Score
        score_data = [
            ["Compliance Score", f"{score}%"],
            ["Controls Passed",
             f"{result['total_required'] - result['required_failed']}/{result['total_required']}"],
            ["Assessment Date",
             result["checked_at"][:10]],
            ["Tool",
             "LLM Scanner v2.0.0"],
        ]
        score_table = Table(score_data, colWidths=[8*cm, 7*cm])
        score_table.setStyle(TableStyle([
            ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 11),
            ("ROWPADDING", (0,0), (-1,-1), 10),
            ("BACKGROUND", (0,0), (0,-1),
             colors.HexColor("#F5F5F5")),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.lightgrey),
            ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ]))
        story.append(score_table)
        story.append(Spacer(1, 0.8*cm))

        # Controls detail
        story.append(Paragraph("Control Assessment", h1_style))
        story.append(HRFlowable(
            width="100%", thickness=1,
            color=colors.HexColor("#2E75B6")
        ))

        controls_data = [["Control", "Name", "Required", "Status"]]
        for ctrl_id, ctrl in result["controls"].items():
            status = "✅ PASS" if ctrl["compliant"] else "❌ FAIL"
            req    = "Yes" if ctrl["required"] else "No"
            controls_data.append([
                ctrl_id,
                ctrl["name"][:30],
                req,
                status
            ])

        ctrl_table = Table(
            controls_data,
            colWidths=[3*cm, 7*cm, 3*cm, 3*cm]
        )
        ctrl_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0),
             colors.HexColor("#1F3864")),
            ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
            ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("ROWPADDING", (0,0), (-1,-1), 8),
            ("GRID",       (0,0), (-1,-1), 0.3, colors.lightgrey),
            ("ALIGN",      (0,0), (-1,-1), "CENTER"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1),
             [colors.HexColor("#F5F5F5"), colors.white]),
        ]))
        story.append(ctrl_table)

        # Footer
        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(
            width="100%", thickness=1,
            color=colors.gray
        ))
        story.append(Paragraph(
            f"Generated by LLM Scanner — "
            f"github.com/Mahdi-EL/llm-scanner — "
            f"{result['checked_at'][:10]}",
            ParagraphStyle(
                "CF", fontSize=8, textColor=colors.gray,
                alignment=TA_CENTER
            )
        ))

        doc.build(story)
        print(f"\n  Compliance certificate: {output}")
        return output

    def print_compliance_report(self, framework_id=None):
        """Prints compliance report to terminal."""
        frameworks = [framework_id] if framework_id \
                     else list(COMPLIANCE_FRAMEWORKS.keys())

        print(f"\n  {'='*60}")
        print(f"  ⚖️  COMPLIANCE REPORT")
        print(f"  {'='*60}\n")

        for fid in frameworks:
            result = self.check_framework(fid)
            if not result:
                continue

            icon  = "✅" if result["overall_compliant"] else "❌"
            print(
                f"  {icon} {result['framework_name']}"
                f" — Score: {result['compliance_score']}%"
            )
            print(
                f"     Controls: "
                f"{result['total_required'] - result['required_failed']}"
                f"/{result['total_required']} passed"
            )

            failed = [
                (cid, c) for cid, c in result["controls"].items()
                if not c["compliant"] and c["required"]
            ]
            if failed:
                print(f"     Failed controls:")
                for ctrl_id, ctrl in failed:
                    print(f"       ❌ {ctrl_id}: {ctrl['name']}")
            print()

        print(f"  {'='*60}\n")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — Compliance Engine"
    )
    subparsers = parser.add_subparsers(dest="command")

    p_check = subparsers.add_parser("check")
    p_check.add_argument("scan_results")
    p_check.add_argument("--framework", default=None,
        choices=list(COMPLIANCE_FRAMEWORKS.keys()))

    p_cert = subparsers.add_parser("certificate")
    p_cert.add_argument("scan_results")
    p_cert.add_argument("framework",
        choices=list(COMPLIANCE_FRAMEWORKS.keys()))
    p_cert.add_argument("--target", default="AI Application")
    p_cert.add_argument("--output", default=None)

    p_list = subparsers.add_parser("frameworks")

    args = parser.parse_args()

    if args.command == "check":
        checker = ComplianceChecker(args.scan_results)
        checker.print_compliance_report(args.framework)

    elif args.command == "certificate":
        checker = ComplianceChecker(args.scan_results)
        checker.generate_compliance_certificate(
            args.framework, args.target, args.output
        )

    elif args.command == "frameworks":
        print(f"\n  Available Frameworks ({len(COMPLIANCE_FRAMEWORKS)}):")
        for fid, fw in COMPLIANCE_FRAMEWORKS.items():
            print(f"\n  {fid}")
            print(f"    {fw['name']} v{fw['version']}")
            print(f"    {fw['description']}")
            print(f"    Controls: {len(fw['controls'])}")

    else:
        parser.print_help()