"""Compliance evidence report: a PDF for auditors and customers' security reviews.

It records what was tested and how (scope and method), coverage against each risk of the OWASP
Top 10 for LLM Applications (2025), including the ones a prompt-based scan can't test, the results,
every triage decision with its note, re-test evidence, and a sign-off block. It is testing evidence,
not a certificate, and says so.
"""
import io
import json
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

import scoring
from analysis import diff_findings
from attacks import catalog
from report import _HTML_SEV, C_BORDER, STYLES, _clip, _p, _serious_spread, brand_of

# Risks a black-box prompt scan can't exercise, and what to do about them instead.
NOT_TESTABLE = {
    "LLM03": "Review where your models, datasets and plugins come from (supply chain); prompts can't test it.",
    "LLM04": "Review how training and fine-tuning data is collected and checked; prompts can't test it.",
    "LLM05": "Check that your application escapes or validates model output before rendering or executing it.",
}

DISCLAIMER = ("This report records the results of automated adversarial testing on the date shown. It is "
              "evidence for risk assessment and testing activities, for example under the NIST AI Risk "
              "Management Framework, ISO/IEC 42001 or the EU AI Act. It is not a certification of compliance.")


def owasp_coverage(results: list, triaged: list) -> list:
    """One row per OWASP risk: categories that test it, attacks graded, failures before and after triage."""
    by_category = {}
    for raw, after in zip(results, triaged, strict=False):
        if raw.get("severity") == scoring.ERROR:
            continue
        row = by_category.setdefault(raw.get("category", ""), {"attacks": 0, "failed": 0, "failed_after": 0})
        row["attacks"] += 1
        row["failed"] += raw.get("severity") not in ("SAFE", None)
        row["failed_after"] += after.get("severity") not in ("SAFE", None)
    rows = []
    for code, name in catalog.OWASP_LLM_2025.items():
        cats = [c for c in by_category if code in catalog.info(c)["owasp"]]
        rows.append({
            "code": code, "name": name,
            "categories": [catalog.info(c)["title"] for c in cats],
            "attacks": sum(by_category[c]["attacks"] for c in cats),
            "failed": sum(by_category[c]["failed"] for c in cats),
            "failed_after_triage": sum(by_category[c]["failed_after"] for c in cats),
            "note": None if cats else NOT_TESTABLE.get(code, "Not covered by the attacks this scan ran."),
        })
    return rows


def retest_evidence(base_results: list, retests: list) -> Optional[dict]:
    """The latest re-test of this scan's failures: how many were re-run, how many now pass."""
    if not retests:
        return None
    latest = retests[-1]
    diff = diff_findings(base_results, latest["results"])
    rerun = len(latest["results"])
    return {"scan_id": latest["scan_id"], "date": latest["created_at"], "rerun": rerun,
            "now_pass": len(diff["resolved"]), "still_failing": diff["still_failing"]}


def _table(rows, widths, header=True):
    S = STYLES
    cells = [[Paragraph(_p("" if c is None else str(c)), S["cellb" if header and i == 0 else "cell"]) for c in row]
             for i, row in enumerate(rows)]
    t = Table(cells, colWidths=widths, repeatRows=1 if header else 0)
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return t


def build(scan: dict, data: dict, *, triaged_results: list, retests: list,
          prepared_by: str) -> bytes:
    """The evidence report as PDF bytes."""
    S = STYLES
    results = data.get("results") or []
    summary = scoring.ensure_summary(data)
    after = scoring.summarize(triaged_results)
    try:
        cfg = json.loads(scan.get("config_json") or "{}") or {}
    except (TypeError, ValueError):
        cfg = {}
    usage = data.get("usage") or {}
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=1.8 * cm, leftMargin=1.8 * cm, topMargin=1.8 * cm,
                            bottomMargin=2 * cm, title=f"Security testing evidence: {scan['target_name']}")
    W = doc.width - 12
    depth = "Quick (about 5 attacks per category)" if data.get("scan_depth") == "quick" else "Full"
    story = [
        Paragraph(_p(f"{brand_of(data)[0].upper()} · SECURITY TESTING EVIDENCE"), S["kicker"]),
        Paragraph(_p(scan["target_name"]), S["title"]),
        Paragraph(_p(f"Adversarial testing on {data.get('scan_date', '')} · scan {scan['scan_id']}"), S["sub"]),
        Paragraph(_p(DISCLAIMER), S["small"]),
        Paragraph("Scope", S["h2"]),
        _table([["Item", "Value"],
                ["Target", scan["target_name"]],
                ["Target type", cfg.get("target_type") or scan.get("target_type") or ""],
                ["Model", cfg.get("model") or scan.get("model") or "not recorded"],
                ["Date (UTC)", data.get("scan_date", "")],
                ["Duration", f"{int(scan.get('duration_seconds') or data.get('duration_seconds') or 0)} s"],
                ["Depth", depth],
                ["Attacks graded", f"{summary['tested']} (plus {summary['errors']} that couldn't be completed)"],
                ["Attack categories", str(len({r.get('category') for r in results}))],
                ["Grading model", usage.get("judge_model") or data.get("judge_model") or "not recorded"]],
               [5 * cm, W - 5 * cm]),
        Paragraph("Method", S["h2"]),
        Paragraph(_p("Each attack prompt was sent to the target and its reply graded twice: by an LLM judge in JSON "
                     "mode at temperature 0, which receives the attack and the reply as untrusted data, and by "
                     "rule-based detectors that don't depend on the judge (a secret canary planted in the system "
                     "prompt, verbatim copies of the system prompt, API keys, tokens and card numbers). Plain "
                     "refusals the detectors cleared are graded by rules. Attacks that couldn't be completed are "
                     "left out of the score. The score weights failures by severity and is capped by the worst "
                     "finding: any critical caps it at 49, any high at 69, any medium at 89."), S["body"]),
        Paragraph("Results", S["h2"]),
        _table([["", "Score", "Grade", "Critical", "High", "Medium", "Low", "Safe"],
                ["As graded", summary["security_score"], summary["grade"], summary["critical"], summary["high"],
                 summary["medium"], summary["low"], summary["safe"]],
                ["After triage", after["security_score"], after["grade"], after["critical"], after["high"],
                 after["medium"], after["low"], after["safe"]]],
               [3 * cm] + [(W - 3 * cm) / 7] * 7),
    ]

    story.append(Paragraph("Coverage: OWASP Top 10 for LLM Applications (2025)", S["h2"]))
    rows = [["Risk", "Tested by", "Attacks", "Failed", "After triage"]]
    for r in owasp_coverage(results, triaged_results):
        tested_by = ", ".join(r["categories"]) if r["categories"] else r["note"]
        rows.append([f"{r['code']} {r['name']}", tested_by, r["attacks"] or "—", r["failed"] if r["attacks"] else "—",
                     r["failed_after_triage"] if r["attacks"] else "—"])
    story.append(_table(rows, [4.2 * cm, W - 4.2 * cm - 5.4 * cm, 1.8 * cm, 1.6 * cm, 2.0 * cm]))

    story.append(Paragraph("Triage decisions", S["h2"]))
    triaged = [r for r in triaged_results if r.get("triage")]
    if not triaged:
        story.append(Paragraph("No finding was marked as a false positive or an accepted risk.", S["body"]))
    else:
        rows = [["Finding", "Graded", "Decision", "Note", "Date"]]
        for r in triaged:
            t = r["triage"]
            rows.append([f"{catalog.info(r.get('category', ''))['title']}: {_clip(r.get('attack'), 120)}",
                         t.get("severity", ""), t["status"].replace("_", " "), t.get("note") or "—",
                         (t.get("created_at") or "")[:10]])
        story.append(_table(rows, [W * 0.38, W * 0.12, W * 0.15, W * 0.23, W * 0.12]))

    story.append(Paragraph("Remediation evidence", S["h2"]))
    evidence = retest_evidence(triaged_results, retests)
    if not evidence:
        story.append(Paragraph("No re-test of this scan's failures has been run yet.", S["body"]))
    else:
        story.append(Paragraph(_p(
            f"Re-test {evidence['scan_id']} on {evidence['date'][:16].replace('T', ' ')} UTC re-ran "
            f"{evidence['rerun']} previously failing attacks: {evidence['now_pass']} now pass, "
            f"{evidence['still_failing']} still fail."), S["body"]))

    open_failures = _serious_spread(triaged_results)
    story.append(Paragraph("Open critical and high findings", S["h2"]))
    if not open_failures:
        story.append(Paragraph("None after triage.", S["body"]))
    for r in open_failures[:15]:
        story.append(Paragraph(f"<font color='{_HTML_SEV.get(r['severity'], '#555555')}'><b>{r['severity']}</b></font> "
                               f"{_p(catalog.info(r.get('category', ''))['title'])}: {_p(_clip(r.get('attack'), 200))}",
                               S["small"]))
    if len(open_failures) > 15:
        story.append(Paragraph(f"{len(open_failures) - 15} more are in the scan's full report.", S["small"]))

    story += [Spacer(1, 0.4 * cm), KeepTogether([
        Paragraph("Sign-off", S["h2"]),
        _table([["Prepared by", prepared_by], ["Reviewed by", ""], ["Role", ""], ["Date", ""], ["Signature", ""]],
               [4 * cm, W - 4 * cm], header=False),
    ]), Spacer(1, 0.4 * cm),
        Paragraph(_p(f"{'Prepared by ' + brand_of(data)[0] if brand_of(data)[1] else 'Generated by LLM Scanner'}"
                     f" from scan {scan['scan_id']}"), S["footer"])]
    doc.build(story)
    return buf.getvalue()


def retests_of(conn, user_id: str, scan: dict) -> list:
    """Finished re-tests of this target's failures run after this scan, oldest first."""
    rows = conn.execute(
        "SELECT scan_id, created_at, config_json, results_json FROM scans WHERE user_id = ? AND target_name = ? "
        "AND status = 'complete' AND id > (SELECT id FROM scans WHERE scan_id = ?) ORDER BY id",
        (user_id, scan["target_name"], scan["scan_id"])).fetchall()
    out = []
    for r in rows:
        try:
            cfg = json.loads(r["config_json"] or "{}")
            if cfg.get("attacks"):
                out.append({"scan_id": r["scan_id"], "created_at": r["created_at"],
                            "results": (json.loads(r["results_json"] or "{}") or {}).get("results", [])})
        except (TypeError, ValueError):
            continue
    return out
