"""Scan reports: PDF, HTML and Markdown, built from a scan's JSON data.

Every value that comes from a user or a model (target name, attack text,
replies, judge reasons) is escaped for its format. The HTML report also
carries a nonce-based Content-Security-Policy, so even text that slipped
through escaping couldn't run a script. Recommendations come from
attacks/catalog.py and only cover the categories that actually failed.
"""
import html
import json
import os
import re
import secrets
from collections import OrderedDict, defaultdict
from datetime import datetime
from xml.sax.saxutils import escape as _xml_escape

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

import scoring
from attacks import catalog

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "ERROR"]


# ─── Shared helpers ──────────────────────────────────────────

def load(json_path):
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _summary(data):
    return scoring.ensure_summary(data)


def _clip(text, limit):
    text = str(text or "")
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def recommendations(results):
    """One recommendation per failing category, most urgent first."""
    failing = defaultdict(list)
    for r in results:
        if r.get("severity") not in ("SAFE", scoring.ERROR, None):
            failing[r.get("category", "other")].append(r)
    recs = []
    for category, items in failing.items():
        worst = scoring.worst(*(i["severity"] for i in items))
        meta  = catalog.info(category)
        recs.append({
            "priority": "P1" if worst in ("CRITICAL", "HIGH") else "P2" if worst == "MEDIUM" else "P3",
            "category": category,
            "title"   : meta["title"],
            "owasp"   : catalog.owasp_labels(category),
            "failed"  : len(items),
            "worst"   : worst,
            "fix"     : meta["fix"],
        })
    recs.sort(key=lambda r: (r["priority"], -scoring.RANK[r["worst"]], -r["failed"]))
    return recs


def category_rows(results):
    """Per-category totals in the order categories were scanned."""
    rows = OrderedDict()
    for r in results:
        cat = r.get("category", "other")
        row = rows.setdefault(cat, {"category": cat, "title": catalog.info(cat)["title"],
                                    "owasp": catalog.info(cat)["owasp"], "attacks": 0,
                                    "failed": 0, "errors": 0, "worst": "SAFE"})
        row["attacks"] += 1
        sev = r.get("severity")
        if sev == scoring.ERROR:
            row["errors"] += 1
        elif sev != "SAFE":
            row["failed"] += 1
            row["worst"] = scoring.worst(row["worst"], sev)
    return list(rows.values())


def _sorted_findings(results):
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(results, key=lambda r: (rank.get(r.get("severity"), 99), -int(r.get("score") or 0)))


def _serious_spread(results):
    """Critical and high findings, worst first, alternating categories within a severity, so a
    report that shows only the first N still has an example of every failing category."""
    seen = {}
    spread = []
    for r in _sorted_findings(results):
        if r.get("severity") not in ("CRITICAL", "HIGH"):
            continue
        key = (r["severity"], r.get("category", ""))
        spread.append((r["severity"] != "CRITICAL", seen.get(key, 0), len(spread), r))
        seen[key] = seen.get(key, 0) + 1
    return [item[-1] for item in sorted(spread, key=lambda item: item[:3])]


# ─── HTML ────────────────────────────────────────────────────

_HTML_SEV = {
    "CRITICAL": "#b42318", "HIGH": "#c4320a", "MEDIUM": "#a15c07",
    "LOW": "#4b6b2f", "SAFE": "#3d6b4f", "ERROR": "#6b6b6b",
}


def render_html(data, target_name="AI Application"):
    e       = html.escape
    summary = _summary(data)
    results = data.get("results") or []
    score   = summary["security_score"]
    nonce   = secrets.token_urlsafe(16)

    counts = "".join(
        f'<div class="count"><span class="n" style="color:{_HTML_SEV[s]}">{summary.get(s.lower(), 0)}</span>'
        f'<span class="l">{s.title()}</span></div>'
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]
    )

    recs = recommendations(results)
    if recs:
        recs_html = "".join(
            f'<article class="rec"><div class="rec-head"><span class="pri pri-{e(r["priority"])}">{e(r["priority"])}</span>'
            f'<h3>{e(r["title"])}</h3><span class="muted">{r["failed"]} failed · worst {e(r["worst"].lower())}</span></div>'
            f'<p class="owasp">{e(" · ".join(r["owasp"]))}</p>'
            f'<ul>{"".join(f"<li>{e(tip)}</li>" for tip in r["fix"])}</ul></article>'
            for r in recs
        )
    else:
        recs_html = '<p>No attack succeeded. Re-scan after every change to the system prompt or model.</p>'

    cat_rows = "".join(
        f'<tr><td>{e(c["title"])}</td><td class="muted">{e(", ".join(c["owasp"]))}</td>'
        f'<td class="num">{c["attacks"]}</td><td class="num">{c["failed"]}</td>'
        f'<td><span class="sev" style="color:{_HTML_SEV.get(c["worst"], "#555")}">'
        f'{e(c["worst"] if c["failed"] else "none")}</span></td></tr>'
        for c in category_rows(results)
    )

    findings = []
    for r in _sorted_findings(results):
        sev = r.get("severity", "SAFE")
        det = "".join(f"<li>{e(d.get('evidence', ''))}</li>" for d in r.get("detectors") or [])
        findings.append(
            f'<details class="finding" data-sev="{e(sev)}">'
            f'<summary><span class="sev" style="color:{_HTML_SEV.get(sev, "#555")}">{e(sev)}</span>'
            f'<span class="cat">{e(catalog.info(r.get("category", "")).get("title", ""))}</span>'
            f'<span class="score">{int(r.get("score") or 0)}/10</span></summary>'
            f'<div class="body"><h4>Attack</h4><pre>{e(_clip(r.get("attack"), 2000))}</pre>'
            f'<h4>Reply</h4><pre>{e(_clip(r.get("response"), 4000))}</pre>'
            f'<h4>Why</h4><p>{e(r.get("reason") or "")}</p>'
            + (f'<h4>Rule-based detection</h4><ul>{det}</ul>' if det else "")
            + '</div></details>'
        )

    coverage = ""
    if summary.get("errors"):
        coverage = (f'<p class="warn">{summary["errors"]} of {summary["total"]} attacks could not be '
                    f'completed (target or grading errors) and are not counted in the score.</p>')

    filters = "".join(
        f'<button type="button" data-filter="{s}">{s.title()}</button>' for s in SEVERITY_ORDER
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; img-src data:">
<title>LLM Scanner report: {e(target_name)}</title>
<style nonce="{nonce}">
:root{{--paper:#faf8f4;--ink:#1d1b18;--muted:#6b665e;--rule:#e3ded5;--card:#ffffff}}
@media (prefers-color-scheme:dark){{:root{{--paper:#161513;--ink:#ece8e1;--muted:#a39d93;--rule:#34312c;--card:#1f1d1a}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 -apple-system,"Segoe UI",Helvetica,Arial,sans-serif}}
main{{max-width:880px;margin:0 auto;padding:48px 20px 64px}}
h1,h2,h3{{font-family:Georgia,"Times New Roman",serif;font-weight:600;line-height:1.2}}
h1{{font-size:34px;margin:4px 0 6px}} h2{{font-size:22px;margin:40px 0 12px;padding-top:16px;border-top:1px solid var(--rule)}}
h3{{font-size:17px;margin:0}} h4{{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:14px 0 4px}}
.kicker{{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}}
.muted{{color:var(--muted);font-size:13px}}
.hero{{display:flex;gap:32px;align-items:flex-end;flex-wrap:wrap;margin-top:24px}}
.big{{font-family:Georgia,serif;font-size:72px;line-height:1}} .grade{{font-family:Georgia,serif;font-size:40px}}
.counts{{display:flex;gap:24px;flex-wrap:wrap;margin:28px 0 8px}}
.count .n{{display:block;font-family:Georgia,serif;font-size:30px;line-height:1}} .count .l{{font-size:12px;color:var(--muted)}}
.warn{{border-left:3px solid #a15c07;padding:8px 12px;background:var(--card)}}
.rec{{background:var(--card);border:1px solid var(--rule);border-radius:6px;padding:16px 18px;margin:10px 0}}
.rec-head{{display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}}
.pri{{font-size:11px;font-weight:700;padding:2px 7px;border-radius:3px;border:1px solid currentColor}}
.pri-P1{{color:#b42318}} .pri-P2{{color:#a15c07}} .pri-P3{{color:var(--muted)}}
.owasp{{margin:6px 0 4px;color:var(--muted);font-size:13px}} .rec ul{{margin:6px 0 0;padding-left:20px}}
table{{width:100%;border-collapse:collapse;font-size:14px}} th,td{{text-align:left;padding:8px 6px;border-bottom:1px solid var(--rule);vertical-align:top}}
th{{font-size:12px;color:var(--muted);font-weight:600}} .num{{text-align:right;font-variant-numeric:tabular-nums}}
.sev{{font-size:12px;font-weight:700;letter-spacing:.04em}}
.filters{{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0 14px}}
.filters button{{font:inherit;font-size:13px;background:transparent;color:var(--ink);border:1px solid var(--rule);border-radius:4px;padding:4px 10px;cursor:pointer}}
.filters button.on{{background:var(--ink);color:var(--paper)}}
.finding{{border-bottom:1px solid var(--rule)}} .finding summary{{display:flex;gap:14px;align-items:baseline;padding:10px 2px;cursor:pointer;list-style:none}}
.finding summary::-webkit-details-marker{{display:none}} .finding .cat{{flex:1}} .finding .score{{font-variant-numeric:tabular-nums;color:var(--muted)}}
.finding .body{{padding:0 2px 14px}}
pre{{white-space:pre-wrap;word-break:break-word;background:var(--card);border:1px solid var(--rule);border-radius:4px;padding:10px;margin:0;font:13px/1.5 ui-monospace,Menlo,Consolas,monospace}}
footer{{margin-top:48px;color:var(--muted);font-size:12px}}
</style>
</head>
<body>
<main>
  <div class="kicker">LLM Scanner · Security report</div>
  <h1>{e(target_name)}</h1>
  <div class="muted">Scanned {e(str(data.get("scan_date", "")))} · {summary["tested"]} attacks graded</div>
  <div class="hero">
    <div><div class="big">{score}</div><div class="muted">Security Score / 100</div></div>
    <div><div class="grade">Grade {e(summary["grade"])}</div><div class="muted">{e(scoring.risk_label(score))}</div></div>
  </div>
  <div class="counts">{counts}</div>
  {coverage}
  <p class="muted">The score weights failures by severity. Any critical finding caps it at 49, any high at 69, any medium at 89.</p>

  <h2>What to fix first</h2>
  {recs_html}

  <h2>Results by category</h2>
  <table><thead><tr><th>Category</th><th>OWASP LLM Top 10</th><th class="num">Attacks</th><th class="num">Failed</th><th>Worst</th></tr></thead>
  <tbody>{cat_rows}</tbody></table>

  <h2>All findings</h2>
  <div class="filters"><button type="button" data-filter="ALL" class="on">All</button>{filters}</div>
  <div id="findings">{"".join(findings)}</div>

  <footer>Generated by LLM Scanner · github.com/Mahdi-EL/llm-scanner · {datetime.now().strftime("%Y-%m-%d")}</footer>
</main>
<script nonce="{nonce}">
document.querySelectorAll('.filters button').forEach(function (btn) {{
  btn.addEventListener('click', function () {{
    var sev = btn.getAttribute('data-filter');
    document.querySelectorAll('.filters button').forEach(function (b) {{ b.classList.toggle('on', b === btn); }});
    document.querySelectorAll('.finding').forEach(function (f) {{
      f.style.display = (sev === 'ALL' || f.getAttribute('data-sev') === sev) ? '' : 'none';
    }});
  }});
}});
</script>
</body>
</html>"""


def generate_html_report(json_path, output_path, target_name="AI Application"):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(render_html(load(json_path), target_name))
    return output_path


# ─── Markdown ────────────────────────────────────────────────

def _md(text, limit=None):
    """Escapes text for a Markdown table cell or line: no raw HTML, pipes or newlines."""
    text = _clip(text, limit) if limit else str(text or "")
    text = html.escape(text, quote=False).replace("|", "\\|")
    return " ".join(text.split())


def render_markdown(data, target_name="AI Application"):
    summary = _summary(data)
    results = data.get("results") or []
    lines = [
        "# LLM Scanner Security Report",
        "",
        f"**Target:** {_md(target_name)}  ",
        f"**Date:** {_md(data.get('scan_date', ''))}  ",
        f"**Security Score:** {summary['security_score']}/100 (grade {summary['grade']}, "
        f"{scoring.risk_label(summary['security_score']).lower()})",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]:
        lines.append(f"| {sev.title()} | {summary.get(sev.lower(), 0)} |")
    if summary.get("errors"):
        lines.append(f"| Errors (not scored) | {summary['errors']} |")
    lines += ["", "## What to fix first", ""]
    recs = recommendations(results)
    if not recs:
        lines.append("No attack succeeded. Re-scan after every change to the system prompt or model.")
    for r in recs:
        lines.append(f"### {r['priority']} · {_md(r['title'])} ({r['failed']} failed, worst {r['worst'].lower()})")
        lines.append("")
        lines.append(f"*{_md(' · '.join(r['owasp']))}*")
        lines.append("")
        lines += [f"- {_md(tip)}" for tip in r["fix"]]
        lines.append("")
    lines += ["## Critical and high findings", ""]
    serious = _serious_spread(results)
    if not serious:
        lines.append("None.")
    for i, r in enumerate(serious[:25], 1):
        lines += [
            f"### {i}. {r['severity']} · {_md(catalog.info(r.get('category', ''))['title'])}",
            "",
            f"- **Score:** {int(r.get('score') or 0)}/10",
            f"- **Attack:** {_md(r.get('attack'), 300)}",
            f"- **Reply:** {_md(r.get('response'), 300)}",
            f"- **Why:** {_md(r.get('reason'), 400)}",
            "",
        ]
    if len(serious) > 25:
        lines += [f"{len(serious) - 25} more are listed in the HTML and JSON reports.", ""]
    lines += ["---", "", "*Generated by [LLM Scanner](https://github.com/Mahdi-EL/llm-scanner)*", ""]
    return "\n".join(lines)


def generate_markdown_report(json_path, output_path, target_name="AI Application"):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(render_markdown(load(json_path), target_name))
    return output_path


# ─── PDF ─────────────────────────────────────────────────────

C_NAVY   = colors.HexColor("#1d1b18")
C_TEXT   = colors.HexColor("#1d1b18")
C_TEXT2  = colors.HexColor("#4a463f")
C_TEXT3  = colors.HexColor("#8a847a")
C_BORDER = colors.HexColor("#e3ded5")
C_PAPER  = colors.HexColor("#faf8f4")
C_WHITE  = colors.white
SEV_COLORS = {s: colors.HexColor(c) for s, c in _HTML_SEV.items()}


def _p(text):
    """Escapes text for a reportlab Paragraph (which parses a small XML subset)."""
    return _xml_escape(str(text or "")).replace("\n", "<br/>")


def _s(name, **kw):
    kw.setdefault("fontName", "Helvetica")
    kw.setdefault("textColor", C_TEXT)
    return ParagraphStyle(name, **kw)


STYLES = {
    "kicker" : _s("kicker", fontSize=8, textColor=C_TEXT3, spaceAfter=2),
    "title"  : _s("title", fontName="Times-Bold", fontSize=26, leading=30, spaceAfter=4),
    "sub"    : _s("sub", fontSize=10, textColor=C_TEXT2, spaceAfter=10),
    "big"    : _s("big", fontName="Times-Bold", fontSize=54, leading=58),
    "h2"     : _s("h2", fontName="Times-Bold", fontSize=16, leading=20, spaceBefore=14, spaceAfter=4),
    "h3"     : _s("h3", fontName="Helvetica-Bold", fontSize=10, spaceAfter=2),
    "body"   : _s("body", fontSize=9.5, leading=13.5, spaceAfter=4),
    "small"  : _s("small", fontSize=8, leading=11, textColor=C_TEXT2),
    "footer" : _s("footer", fontSize=7.5, textColor=C_TEXT3, alignment=TA_CENTER),
    "cell"   : _s("cell", fontSize=8, leading=10.5),
    "cellb"  : _s("cellb", fontName="Helvetica-Bold", fontSize=8, leading=10.5),
    "count"  : _s("count", fontSize=16, leading=20),
}


def _category_bars(rows, width=480):
    height = max(24, 16 * len(rows))
    d = Drawing(width, height)
    label_w, bar_max = 170, width - 170 - 40
    for i, row in enumerate(rows):
        y = height - (i + 1) * 16 + 4
        share = row["failed"] / row["attacks"] if row["attacks"] else 0
        d.add(String(0, y + 2, _clip(row["title"], 32), fontName="Helvetica", fontSize=7, fillColor=C_TEXT2))
        d.add(Rect(label_w, y, bar_max, 9, fillColor=C_PAPER, strokeColor=None))
        color = SEV_COLORS.get(row["worst"], C_TEXT3) if row["failed"] else SEV_COLORS["SAFE"]
        d.add(Rect(label_w, y, max(bar_max * share, 1), 9, fillColor=color, strokeColor=None))
        d.add(String(label_w + bar_max + 6, y + 2, f"{row['failed']}/{row['attacks']}",
                     fontName="Helvetica", fontSize=7, fillColor=C_TEXT2))
    return d


def build_pdf(data, output_path, target_name="AI Application"):
    summary = _summary(data)
    results = data.get("results") or []
    score   = summary["security_score"]
    S = STYLES
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=1.8 * cm, leftMargin=1.8 * cm,
                            topMargin=1.8 * cm, bottomMargin=2 * cm,
                            title=f"LLM Scanner report: {target_name}")
    W = doc.width - 12          # the frame keeps 6pt of padding on each side
    story = [
        Paragraph("LLM SCANNER · SECURITY REPORT", S["kicker"]),
        Paragraph(_p(target_name), S["title"]),
        Paragraph(_p(f"Scanned {data.get('scan_date', '')} · {summary['tested']} attacks graded"), S["sub"]),
    ]

    score_table = Table([[
        Paragraph(f"{score}", S["big"]),
        Paragraph(f"<b>Grade {_p(summary['grade'])}</b><br/>{_p(scoring.risk_label(score))}<br/>"
                  f"<font color='#8a847a'>Security Score / 100</font>", S["body"]),
    ]], colWidths=[4 * cm, W - 4 * cm])
    score_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "BOTTOM"),
                                     ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story += [score_table, Spacer(1, 0.3 * cm)]

    cells = [[Paragraph(f"<font size='16' color='{_HTML_SEV[s]}'><b>{summary.get(s.lower(), 0)}</b></font>"
                        f"<br/><font size='8' color='#8a847a'>{s.title()}</font>", S["count"])
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"]]]
    counts = Table(cells, colWidths=[W / 5] * 5)
    counts.setStyle(TableStyle([("LINEABOVE", (0, 0), (-1, 0), 0.5, C_BORDER),
                                ("LINEBELOW", (0, 0), (-1, 0), 0.5, C_BORDER),
                                ("TOPPADDING", (0, 0), (-1, -1), 6),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                                ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story += [counts, Spacer(1, 0.25 * cm)]
    if summary.get("errors"):
        story.append(Paragraph(_p(f"{summary['errors']} of {summary['total']} attacks could not be completed "
                                  "(target or grading errors) and are not counted in the score."), S["small"]))
    story.append(Paragraph("The score weights failures by severity. Any critical finding caps it at 49, "
                           "any high at 69, any medium at 89.", S["small"]))

    # What to fix
    story += [Paragraph("What to fix first", S["h2"])]
    recs = recommendations(results)
    if not recs:
        story.append(Paragraph("No attack succeeded. Re-scan after every change to the system prompt or model.",
                               S["body"]))
    for r in recs:
        tips = "".join(f"• {_p(tip)}<br/>" for tip in r["fix"])
        block = [
            Paragraph(f"<b>{r['priority']} · {_p(r['title'])}</b>  "
                      f"<font color='#8a847a'>{r['failed']} failed · worst {r['worst'].lower()}</font>", S["body"]),
            Paragraph(_p(" · ".join(r["owasp"])), S["small"]),
            Paragraph(tips, S["body"]),
            HRFlowable(width="100%", thickness=0.3, color=C_BORDER, spaceAfter=6),
        ]
        story.append(KeepTogether(block))

    rows = category_rows(results)
    story += [Paragraph("Results by category", S["h2"]),
              Paragraph("Share of attacks that succeeded in each category.", S["small"]),
              Spacer(1, 0.15 * cm), _category_bars(rows, width=int(W / cm * 28.35))]

    table = [[Paragraph("<b>Category</b>", S["cell"]), Paragraph("<b>OWASP</b>", S["cell"]),
              Paragraph("<b>Attacks</b>", S["cell"]), Paragraph("<b>Failed</b>", S["cell"]),
              Paragraph("<b>Worst</b>", S["cell"])]]
    for row in rows:
        table.append([Paragraph(_p(row["title"]), S["cell"]), Paragraph(_p(", ".join(row["owasp"])), S["cell"]),
                      Paragraph(str(row["attacks"]), S["cell"]), Paragraph(str(row["failed"]), S["cell"]),
                      Paragraph(_p(row["worst"] if row["failed"] else "none"), S["cell"])])
    t = Table(table, colWidths=[W * f for f in (0.40, 0.20, 0.13, 0.13, 0.14)], repeatRows=1)
    t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story += [Spacer(1, 0.3 * cm), t]

    # Serious findings in detail
    serious = _serious_spread(results)
    story += [PageBreak(), Paragraph("Critical and high findings", S["h2"])]
    if not serious:
        story.append(Paragraph("None.", S["body"]))
    for i, r in enumerate(serious[:25], 1):
        color = _HTML_SEV.get(r["severity"], "#555555")
        block = [
            Paragraph(f"<font color='{color}'><b>{r['severity']}</b></font>  <b>{i}. "
                      f"{_p(catalog.info(r.get('category', ''))['title'])}</b>  "
                      f"<font color='#8a847a'>score {int(r.get('score') or 0)}/10</font>", S["body"]),
            Paragraph("<b>Attack:</b> " + _p(_clip(r.get("attack"), 400)), S["small"]),
            Paragraph("<b>Reply:</b> " + _p(_clip(r.get("response"), 600)), S["small"]),
            Paragraph("<b>Why:</b> " + _p(_clip(r.get("reason"), 400)), S["small"]),
            Spacer(1, 0.25 * cm),
        ]
        story.append(KeepTogether(block))
    if len(serious) > 25:
        story.append(Paragraph(f"{len(serious) - 25} more are listed in the HTML report.", S["small"]))

    # Other findings, one line each
    others = [r for r in _sorted_findings(results) if r.get("severity") in ("MEDIUM", "LOW")]
    if others:
        story += [Paragraph("Medium and low findings", S["h2"])]
        rows_ml = [[Paragraph("<b>Severity</b>", S["cell"]), Paragraph("<b>Category</b>", S["cell"]),
                    Paragraph("<b>Why</b>", S["cell"])]]
        for r in others[:200]:
            rows_ml.append([Paragraph(_p(r["severity"]), S["cellb"]),
                            Paragraph(_p(catalog.info(r.get("category", ""))["title"]), S["cell"]),
                            Paragraph(_p(_clip(r.get("reason"), 160)), S["cell"])])
        tml = Table(rows_ml, colWidths=[W * f for f in (0.13, 0.29, 0.58)], repeatRows=1)
        tml.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER),
                                 ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(tml)

    story += [Spacer(1, 0.8 * cm), HRFlowable(width="100%", thickness=0.4, color=C_BORDER, spaceAfter=6),
              Paragraph(f"Generated by LLM Scanner · github.com/Mahdi-EL/llm-scanner · "
                        f"{datetime.now().strftime('%Y-%m-%d')}", S["footer"])]
    doc.build(story)
    return output_path


def generate_report(json_path="results/scan_results.json",
                    output_path="results/LLM_Security_Report.pdf",
                    target_name="AI Application"):
    """Writes the PDF report, plus HTML and Markdown versions next to it."""
    data = load(json_path)
    build_pdf(data, output_path, target_name)
    base = output_path[:-4] if output_path.endswith(".pdf") else output_path
    with open(base + ".html", "w", encoding="utf-8") as f:
        f.write(render_html(data, target_name))
    with open(base + ".md", "w", encoding="utf-8") as f:
        f.write(render_markdown(data, target_name))
    return output_path


def write_reports(data, out_dir, base_name, target_name="AI Application"):
    """Writes JSON, PDF, HTML and Markdown for a scan. Returns the paths."""
    os.makedirs(out_dir, exist_ok=True)
    base  = os.path.join(out_dir, base_name)
    paths = {"json": base + ".json", "pdf": base + ".pdf", "html": base + ".html", "md": base + ".md"}
    with open(paths["json"], "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    build_pdf(data, paths["pdf"], target_name)
    with open(paths["html"], "w", encoding="utf-8") as f:
        f.write(render_html(data, target_name))
    with open(paths["md"], "w", encoding="utf-8") as f:
        f.write(render_markdown(data, target_name))
    return paths


def write_one(data, fmt, path, target_name="AI Application"):
    """Writes a single format (pdf, html or md); used to rebuild a missing report."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if fmt == "pdf":
        return build_pdf(data, path, target_name)
    text = render_html(data, target_name) if fmt == "html" else render_markdown(data, target_name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


# ─── Multilingual PDF ────────────────────────────────────────

PDF_LANGUAGES = ("en", "fr", "es", "de")   # Arabic needs a bundled Arabic font and right-to-left shaping
_PICTOGRAPHS = re.compile("[\u2600-\u27bf\ufe0f\U0001f000-\U0001faff]")


def generate_multilingual_report(json_path, output_path, target_name="AI Application", language="en"):
    """PDF with headings in another language (en, fr, es, de). Findings stay in English."""
    if language not in PDF_LANGUAGES:
        raise ValueError(f"PDF reports are available in {', '.join(PDF_LANGUAGES)}, not {language!r}")
    if language == "en":
        return build_pdf(load(json_path), output_path, target_name)
    try:
        from i18n import Translator
        t = Translator(language)
    except ImportError:
        return build_pdf(load(json_path), output_path, target_name)

    data    = load(json_path)
    summary = _summary(data)
    results = data.get("results") or []
    S = STYLES
    doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=1.8 * cm, leftMargin=1.8 * cm,
                            topMargin=1.8 * cm, bottomMargin=2 * cm)
    story = [
        Paragraph(_p(t.t("security_audit").upper()), S["kicker"]),
        Paragraph(_p(target_name), S["title"]),
        Paragraph(_p(str(data.get("scan_date", ""))), S["sub"]),
        Paragraph(f"{summary['security_score']}", S["big"]),
        Paragraph(_p(f"Grade {summary['grade']}"), S["body"]),
        Paragraph(_p(t.t("executive_summary")), S["h2"]),
    ]
    rows = [[_p(t.t("status")), "#"]]
    for key, label in [("critical", "critical_label"), ("high", "high_label"), ("medium", "medium_label"),
                       ("low", "low_label"), ("safe", "safe_label")]:
        rows.append([_p(_PICTOGRAPHS.sub("", t.t(label)).strip()), str(summary.get(key, 0))])   # no emoji glyphs in the PDF fonts
    table = Table([[Paragraph(a, S["cell"]), Paragraph(b, S["cell"])] for a, b in rows],
                  colWidths=[8 * cm, 3 * cm])
    table.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.3, C_BORDER)]))
    story += [table, Paragraph(_p(t.t("vulnerability_details")), S["h2"])]
    serious = _serious_spread(results)
    if not serious:
        story.append(Paragraph("—", S["small"]))
    for r in serious[:15]:
        story.append(Paragraph(f"<b>{r['severity']}</b> · {_p(catalog.info(r.get('category', ''))['title'])}: "
                               f"{_p(_clip(r.get('attack'), 200))}", S["small"]))
    story.append(Paragraph(_p(t.t("recommendations")), S["h2"]))
    if not recommendations(results):
        story.append(Paragraph("—", S["small"]))
    for r in recommendations(results):
        story.append(Paragraph(f"<b>{r['priority']} · {_p(r['title'])}</b><br/>" +
                               "".join(f"• {_p(tip)}<br/>" for tip in r["fix"]), S["body"]))
    doc.build(story)
    return output_path


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="LLM Scanner report generator")
    parser.add_argument("--lang", default="en", choices=PDF_LANGUAGES)
    parser.add_argument("--input", default="results/scan_results.json")
    parser.add_argument("--output", default=None)
    parser.add_argument("--target", default="AI Application")
    args = parser.parse_args()
    if args.lang == "en":
        generate_report(args.input, args.output or "results/LLM_Security_Report.pdf", args.target)
    else:
        generate_multilingual_report(args.input, args.output or f"results/LLM_Security_Report_{args.lang}.pdf",
                                     args.target, args.lang)
