"""Compares two scan result files (the JSON reports) and writes a comparison PDF.

Used by `python backend/cli.py compare before.json after.json`. Fixed, new and
still-failing findings come from analysis.diff_findings, like the web app's
comparison; the score change only counts when both scans ran the same attacks.
"""
import json

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

import scoring
from analysis import diff_findings
from attacks import catalog
from report import _HTML_SEV, C_BORDER, STYLES, _clip, _p

COUNTS = ("critical", "high", "medium", "low", "safe", "errors")


def load_scan(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def compare_scans(scan1_path, scan2_path):
    """What changed between two scans: summaries, fixed / new / still failing findings, a verdict."""
    scan1, scan2 = load_scan(scan1_path), load_scan(scan2_path)
    s1, s2 = scoring.ensure_summary(scan1), scoring.ensure_summary(scan2)
    diff = diff_findings(scan1.get("results", []), scan2.get("results", []))
    score_diff = s2["security_score"] - s1["security_score"]

    if not diff["same_attacks"]:
        verdict = "Different attacks: scores not compared"
    elif diff["introduced"]:
        verdict = "Regressed"
    elif score_diff > 0 or diff["resolved"]:
        verdict = "Improved"
    elif score_diff < 0:
        verdict = "Regressed"
    else:
        verdict = "Unchanged"

    return {
        "scan1_date"   : scan1.get("scan_date", ""),
        "scan2_date"   : scan2.get("scan_date", ""),
        "before"       : s1,
        "after"        : s2,
        "score_diff"   : score_diff,
        "same_attacks" : diff["same_attacks"],
        "fixed"        : diff["resolved"],
        "new_vulns"    : diff["introduced"],
        "still_failing": diff["still_failing"],
        "verdict"      : verdict,
    }


def _signed(n):
    return f"+{n}" if n > 0 else str(n)


def print_comparison(diff):
    b, a = diff["before"], diff["after"]
    print("\n" + "=" * 60)
    print("  SCAN COMPARISON")
    print(f"  Before : {diff['scan1_date']}")
    print(f"  After  : {diff['scan2_date']}")
    print("-" * 60)
    score = f"{b['security_score']} -> {a['security_score']}"
    print(f"  Score  : {score}" + (f" ({_signed(diff['score_diff'])})" if diff["same_attacks"] else
                                   " (different attacks, not comparable)"))
    for key in COUNTS[:-1]:
        print(f"  {key.title():<7}: {b[key]} -> {a[key]}")
    print(f"  Fixed {len(diff['fixed'])}, new {len(diff['new_vulns'])}, still failing {diff['still_failing']}")
    print(f"  Verdict: {diff['verdict']}")
    print("=" * 60)


def _finding_rows(findings, limit=25):
    S = STYLES
    out = []
    for f in findings[:limit]:
        sev = f.get("severity", "")
        label = f"<font color='{_HTML_SEV.get(sev, '#555555')}'><b>{_p(sev)}</b></font>"
        out.append(Paragraph(f"{label}  {_p(catalog.info(f.get('category', ''))['title'])}: "
                             f"{_p(_clip(f.get('attack'), 200))}", S["small"]))
    if len(findings) > limit:
        out.append(Paragraph(f"{len(findings) - limit} more.", S["small"]))
    return out


def generate_comparison_pdf(scan1_path, scan2_path, output_path, target_name="AI Application"):
    diff = compare_scans(scan1_path, scan2_path)
    print_comparison(diff)
    S = STYLES
    b, a = diff["before"], diff["after"]
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=1.8 * cm, leftMargin=1.8 * cm,
                            topMargin=1.8 * cm, bottomMargin=2 * cm)
    story = [
        Paragraph("LLM SCANNER · COMPARISON", S["kicker"]),
        Paragraph(_p(target_name), S["title"]),
        Paragraph(_p(f"Before: {diff['scan1_date']}   ·   After: {diff['scan2_date']}"), S["sub"]),
        Paragraph(_p(diff["verdict"]), S["h2"]),
    ]
    if not diff["same_attacks"]:
        story.append(Paragraph("The two scans ran different attacks, so their scores aren't comparable. "
                               "Fixed and new findings below only count attacks both scans ran.", S["body"]))

    rows = [["", "Before", "After", "Change"],
            ["Security score", str(b["security_score"]), str(a["security_score"]),
             _signed(diff["score_diff"]) if diff["same_attacks"] else "—"],
            ["Grade", str(b["grade"]), str(a["grade"]), ""]]
    rows += [[k.title(), str(b[k]), str(a[k]), _signed(a[k] - b[k])] for k in COUNTS]
    table = Table([[Paragraph(_p(c), S["cellb" if i == 0 or j == 0 else "cell"]) for j, c in enumerate(r)]
                   for i, r in enumerate(rows)], colWidths=[5 * cm, 3.5 * cm, 3.5 * cm, 3.5 * cm])
    table.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER)]))
    story += [Spacer(1, 0.2 * cm), table]

    for title, findings in ((f"Fixed ({len(diff['fixed'])})", diff["fixed"]),
                            (f"New failures ({len(diff['new_vulns'])})", diff["new_vulns"])):
        story.append(Paragraph(_p(title), S["h2"]))
        story += _finding_rows(findings) or [Paragraph("None.", S["small"])]
    story.append(Paragraph(f"Still failing: {diff['still_failing']}", S["body"]))
    story += [Spacer(1, 0.6 * cm), Paragraph("Generated by LLM Scanner · github.com/Mahdi-EL/llm-scanner", S["footer"])]
    doc.build(story)
    print(f"\nComparison PDF written to {output_path}")
    return output_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Compare two LLM Scanner results")
    parser.add_argument("--scan1", required=True, help="first (older) scan JSON")
    parser.add_argument("--scan2", required=True, help="second (newer) scan JSON")
    parser.add_argument("--output", default="results/comparison.pdf")
    parser.add_argument("--target", default="AI Application")
    args = parser.parse_args()
    generate_comparison_pdf(args.scan1, args.scan2, args.output, args.target)
