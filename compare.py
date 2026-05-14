import sys
sys.stdout.reconfigure(encoding='utf-8')

import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER


# ── Colors ────────────────────────────────────────────────────
DARK_BLUE  = colors.HexColor("#1F3864")
MEDIUM_BLUE= colors.HexColor("#2E75B6")
GREEN      = colors.HexColor("#27AE60")
RED        = colors.HexColor("#C0392B")
ORANGE     = colors.HexColor("#E67E22")
LIGHT_GRAY = colors.HexColor("#F5F5F5")
WHITE      = colors.white


# ── Load Scan ─────────────────────────────────────────────────
def load_scan(json_path):
    """Loads a scan result from JSON file."""
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ── Compare Two Scans ─────────────────────────────────────────
def compare_scans(scan1_path, scan2_path):
    """
    Compares two scan results in detail.
    Returns a comprehensive diff report.
    """
    scan1 = load_scan(scan1_path)
    scan2 = load_scan(scan2_path)

    s1 = scan1["summary"]
    s2 = scan2["summary"]

    # Score changes
    score_diff    = s2["security_score"] - s1["security_score"]
    critical_diff = s2["critical"]       - s1["critical"]
    high_diff     = s2["high"]           - s1["high"]
    medium_diff   = s2["medium"]         - s1["medium"]
    safe_diff     = s2["safe"]           - s1["safe"]

    # Category comparison
    def get_category_scores(scan):
        scores = {}
        for r in scan["results"]:
            cat = r["category"]
            if cat not in scores:
                scores[cat] = []
            scores[cat].append(r["score"])
        return {
            cat: round(sum(v)/len(v), 1)
            for cat, v in scores.items()
        }

    cat1 = get_category_scores(scan1)
    cat2 = get_category_scores(scan2)

    # Category improvements
    category_changes = {}
    all_cats = set(list(cat1.keys()) + list(cat2.keys()))
    for cat in all_cats:
        s1_score = cat1.get(cat, 0)
        s2_score = cat2.get(cat, 0)
        category_changes[cat] = {
            "before" : s1_score,
            "after"  : s2_score,
            "change" : round(s2_score - s1_score, 1),
            "improved": s2_score < s1_score
        }

    # Fixed vulnerabilities
    fixed = []
    new_vulns = []

    scan1_attacks = {r["attack"]: r for r in scan1["results"]}
    scan2_attacks = {r["attack"]: r for r in scan2["results"]}

    for attack, r1 in scan1_attacks.items():
        if attack in scan2_attacks:
            r2 = scan2_attacks[attack]
            if r1["severity"] in ("CRITICAL","HIGH") and \
               r2["severity"] in ("SAFE","LOW"):
                fixed.append({
                    "attack"  : attack[:80],
                    "before"  : r1["severity"],
                    "after"   : r2["severity"],
                    "category": r1["category"]
                })
            elif r1["severity"] in ("SAFE","LOW") and \
                 r2["severity"] in ("CRITICAL","HIGH"):
                new_vulns.append({
                    "attack"  : attack[:80],
                    "before"  : r1["severity"],
                    "after"   : r2["severity"],
                    "category": r1["category"]
                })

    # Overall verdict
    if score_diff > 10:
        verdict = "SIGNIFICANTLY IMPROVED"
        verdict_color = GREEN
    elif score_diff > 0:
        verdict = "SLIGHTLY IMPROVED"
        verdict_color = GREEN
    elif score_diff == 0:
        verdict = "UNCHANGED"
        verdict_color = ORANGE
    elif score_diff > -10:
        verdict = "SLIGHTLY DEGRADED"
        verdict_color = ORANGE
    else:
        verdict = "SIGNIFICANTLY DEGRADED"
        verdict_color = RED

    return {
        "scan1_date"       : scan1["scan_date"],
        "scan2_date"       : scan2["scan_date"],
        "score_before"     : s1["security_score"],
        "score_after"      : s2["security_score"],
        "score_diff"       : score_diff,
        "critical_diff"    : critical_diff,
        "high_diff"        : high_diff,
        "medium_diff"      : medium_diff,
        "safe_diff"        : safe_diff,
        "category_changes" : category_changes,
        "fixed"            : fixed,
        "new_vulns"        : new_vulns,
        "verdict"          : verdict,
        "verdict_color"    : verdict_color
    }


# ── Print Comparison ──────────────────────────────────────────
def print_comparison(diff):
    """Prints a comparison report in the terminal."""

    print("\n" + "=" * 60)
    print("  SCAN COMPARISON REPORT")
    print("=" * 60)
    print(f"  Scan 1 : {diff['scan1_date']}")
    print(f"  Scan 2 : {diff['scan2_date']}")
    print("-" * 60)
    print(f"  Security Score : {diff['score_before']}% → {diff['score_after']}%  ({'+' if diff['score_diff'] >= 0 else ''}{diff['score_diff']}%)")
    print(f"  Critical       : {'+' if diff['critical_diff'] >= 0 else ''}{diff['critical_diff']}")
    print(f"  High           : {'+' if diff['high_diff'] >= 0 else ''}{diff['high_diff']}")
    print(f"  Medium         : {'+' if diff['medium_diff'] >= 0 else ''}{diff['medium_diff']}")
    print(f"  Safe           : {'+' if diff['safe_diff'] >= 0 else ''}{diff['safe_diff']}")
    print("-" * 60)

    if diff["fixed"]:
        print(f"\n  ✅ FIXED VULNERABILITIES ({len(diff['fixed'])}) :")
        for f in diff["fixed"]:
            print(f"     {f['before']} → {f['after']} : {f['attack'][:60]}...")

    if diff["new_vulns"]:
        print(f"\n  ⚠️  NEW VULNERABILITIES ({len(diff['new_vulns'])}) :")
        for v in diff["new_vulns"]:
            print(f"     {v['before']} → {v['after']} : {v['attack'][:60]}...")

    print(f"\n  VERDICT : {diff['verdict']}")
    print("=" * 60)


# ── Generate Comparison PDF ───────────────────────────────────
def generate_comparison_pdf(
    scan1_path,
    scan2_path,
    output_path,
    target_name="AI Application"
):
    """
    Generates a PDF comparison report between two scans.
    """
    diff = compare_scans(scan1_path, scan2_path)
    print_comparison(diff)

    doc    = SimpleDocTemplate(
        output_path, pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )
    styles = getSampleStyleSheet()
    story  = []

    h1 = ParagraphStyle(
        "H1", fontSize=18, textColor=DARK_BLUE,
        fontName="Helvetica-Bold", spaceAfter=10, spaceBefore=20
    )
    h2 = ParagraphStyle(
        "H2", fontSize=14, textColor=MEDIUM_BLUE,
        fontName="Helvetica-Bold", spaceAfter=8, spaceBefore=14
    )
    body = ParagraphStyle(
        "Body", fontSize=10, spaceAfter=6, leading=15
    )
    small = ParagraphStyle(
        "Small", fontSize=8, textColor=colors.gray, spaceAfter=4
    )

    # ── Cover ────────────────────────────────────────────────
    cover_data = [[Paragraph(
        "🔐 LLM SCANNER — Comparison Report",
        ParagraphStyle("T", fontSize=22, textColor=WHITE,
                       fontName="Helvetica-Bold", alignment=TA_CENTER)
    )]]
    cover = Table(cover_data, colWidths=[17*cm])
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), DARK_BLUE),
        ("ROWPADDING", (0,0), (-1,-1), 24),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
    ]))
    story.append(cover)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph(f"Target : {target_name}", body))
    story.append(Paragraph(
        f"Scan 1 : {diff['scan1_date']}", small
    ))
    story.append(Paragraph(
        f"Scan 2 : {diff['scan2_date']}", small
    ))
    story.append(Spacer(1, 1*cm))

    # ── Verdict ──────────────────────────────────────────────
    verdict_data = [[
        Paragraph(diff["verdict"],
            ParagraphStyle("V", fontSize=20, textColor=WHITE,
                           fontName="Helvetica-Bold",
                           alignment=TA_CENTER))
    ]]
    verdict_table = Table(verdict_data, colWidths=[17*cm])
    verdict_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), diff["verdict_color"]),
        ("ROWPADDING", (0,0), (-1,-1), 16),
    ]))
    story.append(verdict_table)
    story.append(Spacer(1, 0.8*cm))

    # ── Score Comparison ─────────────────────────────────────
    story.append(Paragraph("Security Score Comparison", h1))
    story.append(HRFlowable(
        width="100%", thickness=2,
        color=DARK_BLUE, spaceAfter=10
    ))

    score_color = GREEN if diff["score_diff"] >= 0 else RED
    score_data  = [
        ["Metric", "Before", "After", "Change"],
        ["Security Score",
         f"{diff['score_before']}%",
         f"{diff['score_after']}%",
         f"{'+' if diff['score_diff'] >= 0 else ''}{diff['score_diff']}%"],
        ["Critical",
         str(diff['score_before']),
         str(diff['score_after']),
         f"{'+' if diff['critical_diff'] >= 0 else ''}{diff['critical_diff']}"],
        ["High",
         "-", "-",
         f"{'+' if diff['high_diff'] >= 0 else ''}{diff['high_diff']}"],
        ["Medium",
         "-", "-",
         f"{'+' if diff['medium_diff'] >= 0 else ''}{diff['medium_diff']}"],
        ["Safe",
         "-", "-",
         f"{'+' if diff['safe_diff'] >= 0 else ''}{diff['safe_diff']}"],
    ]

    score_table = Table(
        score_data, colWidths=[5*cm, 4*cm, 4*cm, 4*cm]
    )
    score_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), DARK_BLUE),
        ("TEXTCOLOR",   (0,0), (-1,0), WHITE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 10),
        ("ALIGN",       (0,0), (-1,-1), "CENTER"),
        ("ROWPADDING",  (0,0), (-1,-1), 8),
        ("GRID",        (0,0), (-1,-1), 0.3, colors.lightgrey),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [LIGHT_GRAY, WHITE]),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 0.8*cm))

    # ── Fixed Vulnerabilities ────────────────────────────────
    if diff["fixed"]:
        story.append(Paragraph(
            f"Fixed Vulnerabilities ({len(diff['fixed'])})", h2
        ))
        for f in diff["fixed"]:
            fixed_data = [[
                Paragraph(
                    f"✅ {f['before']} → {f['after']} | {f['category']}",
                    ParagraphStyle("FH", fontSize=10,
                                   textColor=WHITE,
                                   fontName="Helvetica-Bold")
                )
            ]]
            fixed_header = Table(fixed_data, colWidths=[17*cm])
            fixed_header.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), GREEN),
                ("ROWPADDING", (0,0), (-1,-1), 8),
            ]))
            story.append(fixed_header)
            story.append(Paragraph(f['attack'], body))
            story.append(Spacer(1, 0.3*cm))

    # ── New Vulnerabilities ───────────────────────────────────
    if diff["new_vulns"]:
        story.append(Paragraph(
            f"New Vulnerabilities ({len(diff['new_vulns'])})", h2
        ))
        for v in diff["new_vulns"]:
            vuln_data = [[
                Paragraph(
                    f"⚠️ {v['before']} → {v['after']} | {v['category']}",
                    ParagraphStyle("VH", fontSize=10,
                                   textColor=WHITE,
                                   fontName="Helvetica-Bold")
                )
            ]]
            vuln_header = Table(vuln_data, colWidths=[17*cm])
            vuln_header.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), RED),
                ("ROWPADDING", (0,0), (-1,-1), 8),
            ]))
            story.append(vuln_header)
            story.append(Paragraph(v['attack'], body))
            story.append(Spacer(1, 0.3*cm))

    # ── Footer ────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(
        width="100%", thickness=1,
        color=DARK_BLUE, spaceAfter=8
    ))
    story.append(Paragraph(
        f"Generated by LLM Scanner — github.com/Mahdi-EL/llm-scanner",
        ParagraphStyle("Footer", fontSize=8,
                       textColor=colors.gray,
                       alignment=TA_CENTER)
    ))

    doc.build(story)
    print(f"\nComparison PDF generated : {output_path}")
    return output_path


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Compare two LLM Scanner results"
    )
    parser.add_argument("--scan1",  required=True,
        help="Path to first scan JSON")
    parser.add_argument("--scan2",  required=True,
        help="Path to second scan JSON")
    parser.add_argument("--output", default="results/comparison.pdf",
        help="Output PDF path")
    parser.add_argument("--target", default="AI Application",
        help="Target name")

    args = parser.parse_args()

    generate_comparison_pdf(
        scan1_path  =args.scan1,
        scan2_path  =args.scan2,
        output_path =args.output,
        target_name =args.target
    )