import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
from dotenv import load_dotenv

load_dotenv()


# ── Narrative Generator ───────────────────────────────────────
class NarrativeGenerator:
    """
    Generates human-readable narrative reports from scan results.
    Uses AI to write professional security assessment text.
    """

    def __init__(self):
        from groq import Groq
        self.client = Groq(api_key=os.getenv("GROQ_API_KEY"))

    def generate_executive_summary(self, scan_data, target_name):
        """
        Generates a 3-paragraph executive summary
        suitable for a C-level audience.
        """
        summary  = scan_data["summary"]
        results  = scan_data.get("results", [])
        score    = summary["security_score"]
        critical = summary["critical"]
        high     = summary["high"]
        total    = scan_data["total_attacks"]

        # Get most vulnerable category
        cat_scores = {}
        for r in results:
            cat = r["category"]
            if cat not in cat_scores:
                cat_scores[cat] = []
            cat_scores[cat].append(r["score"])

        most_vuln_cat = max(
            cat_scores,
            key=lambda c: sum(cat_scores[c]) / len(cat_scores[c])
        ) if cat_scores else "direct_override"

        prompt = f"""You are a senior cybersecurity consultant
writing an executive summary for an AI security audit report.

TARGET : {target_name}
SECURITY SCORE : {score}%
TOTAL ATTACKS FIRED : {total}
CRITICAL FINDINGS : {critical}
HIGH FINDINGS : {high}
MOST VULNERABLE CATEGORY : {most_vuln_cat.replace('_', ' ').title()}

Write a professional 3-paragraph executive summary that :
Paragraph 1 : Overview of the assessment and overall security posture
Paragraph 2 : Key findings and most critical vulnerabilities discovered
Paragraph 3 : Recommended immediate actions and business impact

Use professional language suitable for a C-level audience.
Be specific about the risks.
Do not use bullet points — write in flowing prose.
Maximum 200 words total."""

        response = self.client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=300
        )

        return response.choices[0].message.content.strip()

    def generate_finding_narrative(self, finding):
        """
        Generates a detailed narrative for a single finding.
        Explains what happened, why it matters, and how to fix it.
        """
        prompt = f"""You are a cybersecurity expert writing
a finding narrative for a security report.

FINDING :
Category : {finding['category'].replace('_', ' ').title()}
Severity : {finding['severity']}
Score    : {finding['score']}/10
Attack   : {finding['attack'][:200]}
Response : {finding['response'][:200]}
Reason   : {finding.get('reason', 'N/A')}

Write a 3-sentence finding narrative that :
1. Describes what the attacker did
2. Explains what the AI revealed or did wrong
3. States the business risk of this vulnerability

Use professional security language.
Be specific and technical but understandable.
Do NOT use bullet points."""

        response = self.client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150
        )

        return response.choices[0].message.content.strip()

    def generate_attack_story(self, scan_data, target_name):
        """
        Generates a narrative story of the full attack session.
        Written like a penetration test report.
        """
        results  = scan_data.get("results", [])
        critical = [r for r in results if r["severity"] == "CRITICAL"]
        high     = [r for r in results if r["severity"] == "HIGH"]
        safe     = [r for r in results if r["severity"] == "SAFE"]
        score    = scan_data["summary"]["security_score"]
        total    = scan_data["total_attacks"]

        # Build context
        worst_finding = critical[0] if critical else \
                        (high[0] if high else None)

        worst_text = ""
        if worst_finding:
            worst_text = f"""
Most Critical Finding :
Attack   : {worst_finding['attack'][:150]}
Response : {worst_finding['response'][:150]}
Category : {worst_finding['category']}"""

        prompt = f"""You are a red team security researcher
writing the attack narrative section of a penetration test report.

TARGET    : {target_name}
SCORE     : {score}%
ATTACKS   : {total} adversarial prompts fired
CRITICAL  : {len(critical)} attacks fully succeeded
HIGH      : {len(high)} attacks caused significant leakage
SAFE      : {len(safe)} attacks were blocked
{worst_text}

Write a 4-sentence attack narrative that :
1. Sets the scene — how the assessment began
2. Describes the attack progression and what was discovered
3. Highlights the most significant finding
4. Concludes with the overall security assessment

Write in past tense like a real pentest report.
Professional, technical, specific language.
No bullet points."""

        response = self.client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200
        )

        return response.choices[0].message.content.strip()

    def generate_remediation_plan(self, scan_data, target_name):
        """
        Generates a prioritized remediation plan.
        """
        summary  = scan_data["summary"]
        results  = scan_data.get("results", [])
        critical = [r for r in results if r["severity"] == "CRITICAL"]
        high     = [r for r in results if r["severity"] == "HIGH"]

        # Get unique vulnerable categories
        vuln_categories = list(set(
            r["category"] for r in results
            if r["severity"] in ("CRITICAL", "HIGH")
        ))[:5]

        prompt = f"""You are a cybersecurity consultant
writing a remediation plan for an AI security assessment.

TARGET             : {target_name}
CRITICAL FINDINGS  : {len(critical)}
HIGH FINDINGS      : {len(high)}
VULNERABLE CATEGORIES : {', '.join(vuln_categories)}

Write a prioritized remediation plan with exactly 3 priorities :

IMMEDIATE (0-7 days) : What to fix right now
SHORT TERM (1-4 weeks) : What to fix soon
LONG TERM (1-3 months) : What to implement strategically

For each priority, give 1-2 specific actionable recommendations.
Be concrete and technical.
No generic advice."""

        response = self.client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=250
        )

        return response.choices[0].message.content.strip()

    def generate_full_narrative(self, scan_data, target_name):
        """
        Generates all narrative sections for the report.
        Returns a dict with all sections.
        """
        print("  Generating AI narrative report...")

        narrative = {}

        print("  → Executive summary...")
        narrative["executive_summary"] = self.generate_executive_summary(
            scan_data, target_name
        )

        print("  → Attack story...")
        narrative["attack_story"] = self.generate_attack_story(
            scan_data, target_name
        )

        print("  → Remediation plan...")
        narrative["remediation_plan"] = self.generate_remediation_plan(
            scan_data, target_name
        )

        # Generate narratives for top 3 critical/high findings
        results  = scan_data.get("results", [])
        top_findings = [
            r for r in results
            if r["severity"] in ("CRITICAL", "HIGH")
        ][:3]

        narrative["finding_narratives"] = []
        for i, finding in enumerate(top_findings):
            print(f"  → Finding narrative {i+1}/3...")
            text = self.generate_finding_narrative(finding)
            narrative["finding_narratives"].append({
                "category": finding["category"],
                "severity": finding["severity"],
                "narrative": text
            })

        print("  Narrative generation complete !")
        return narrative


# ── Narrative PDF Section ─────────────────────────────────────
def add_narrative_to_report(story, narrative, styles):
    """
    Returns ReportLab flowables for the narrative section.
    To be called from report.py
    """
    from reportlab.platypus import Paragraph, Spacer, HRFlowable
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    DARK_BLUE   = colors.HexColor("#1F3864")
    MEDIUM_BLUE = colors.HexColor("#2E75B6")

    h1 = ParagraphStyle(
        "H1N", fontSize=16, textColor=DARK_BLUE,
        fontName="Helvetica-Bold", spaceAfter=10, spaceBefore=20
    )
    h2 = ParagraphStyle(
        "H2N", fontSize=13, textColor=MEDIUM_BLUE,
        fontName="Helvetica-Bold", spaceAfter=8, spaceBefore=14
    )
    body = ParagraphStyle(
        "BodyN", fontSize=10, spaceAfter=8, leading=16
    )

    elements = []

    elements.append(Paragraph("AI Narrative Report", h1))
    elements.append(HRFlowable(
        width="100%", thickness=2,
        color=DARK_BLUE, spaceAfter=10
    ))

    # Executive Summary
    if narrative.get("executive_summary"):
        elements.append(Paragraph("Executive Summary", h2))
        elements.append(Paragraph(
            narrative["executive_summary"], body
        ))
        elements.append(Spacer(1, 0.5*cm))

    # Attack Story
    if narrative.get("attack_story"):
        elements.append(Paragraph("Attack Narrative", h2))
        elements.append(Paragraph(
            narrative["attack_story"], body
        ))
        elements.append(Spacer(1, 0.5*cm))

    # Finding Narratives
    if narrative.get("finding_narratives"):
        elements.append(Paragraph("Key Findings", h2))
        for fn in narrative["finding_narratives"]:
            sev_colors = {
                "CRITICAL": "#C0392B",
                "HIGH"    : "#E67E22"
            }
            color = sev_colors.get(fn["severity"], "#888888")

            elements.append(Paragraph(
                f'<font color="{color}"><b>[{fn["severity"]}]</b></font> '
                f'{fn["category"].replace("_"," ").title()}',
                ParagraphStyle(
                    "FN", fontSize=11,
                    fontName="Helvetica-Bold",
                    spaceAfter=4, spaceBefore=8
                )
            ))
            elements.append(Paragraph(fn["narrative"], body))

    # Remediation Plan
    if narrative.get("remediation_plan"):
        elements.append(Spacer(1, 0.5*cm))
        elements.append(Paragraph("Remediation Plan", h2))
        elements.append(Paragraph(
            narrative["remediation_plan"], body
        ))

    return elements


# ── Generate Narrative Report ─────────────────────────────────
def generate_narrative_report(
    json_path,
    output_path,
    target_name="AI Application"
):
    """
    Generates a standalone narrative PDF report.
    """
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate
    from reportlab.lib.units import cm

    with open(json_path, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    generator = NarrativeGenerator()
    narrative = generator.generate_full_narrative(scan_data, target_name)

    # Save narrative JSON
    narrative_json = json_path.replace(".json", "_narrative.json")
    with open(narrative_json, "w", encoding="utf-8") as f:
        json.dump(narrative, f, indent=2, ensure_ascii=False)

    # Build PDF
    doc    = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )
    styles   = getSampleStyleSheet()
    elements = add_narrative_to_report([], narrative, styles)

    doc.build(elements)
    print(f"\nNarrative report : {output_path}")
    return narrative


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — AI Narrative Report Generator"
    )
    parser.add_argument(
        "--input",  required=True,
        help="Path to scan results JSON"
    )
    parser.add_argument(
        "--output", default=None,
        help="Output PDF path"
    )
    parser.add_argument(
        "--target", default="AI Application",
        help="Target name"
    )

    args   = parser.parse_args()
    output = args.output or args.input.replace(".json", "_narrative.pdf")

    generate_narrative_report(
        json_path  =args.input,
        output_path=output,
        target_name=args.target
    )
    