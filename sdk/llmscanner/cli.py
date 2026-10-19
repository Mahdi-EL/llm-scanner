"""`llmscanner` command: run scans against the LLM Scanner API from a terminal or CI.

    export LLMSCANNER_API_KEY=llmsk_...  LLMSCANNER_API_URL=https://your-api
    llmscanner scan --name "Support bot" --type openai_compatible \
        --url https://api.openai.com/v1 --target-key "$OPENAI_API_KEY" --model gpt-4o-mini \
        --wait --fail-on high

Exit codes: 0 = passed, 1 = findings at or above --fail-on, 2 = error.
"""
import argparse
import json
import os
import sys

from .client import Client
from .exceptions import LLMScannerError
from .models import SEVERITY_RANK


def _client(args) -> Client:
    return Client(api_key=args.api_key, base_url=args.api_url)


def _progress(scan):
    if scan.status == "pending":
        print("  queued...", flush=True)
    elif scan.total_attacks:
        print(f"  {scan.completed_attacks}/{scan.total_attacks} attacks ({scan.progress}%)", flush=True)


def _github_outputs(report):
    """Exposes scan-id, score, grade and worst severity as GitHub Actions step outputs."""
    path = os.getenv("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"scan-id={report.scan_id}\nscore={report.security_score}\n"
                f"grade={report.grade}\nworst-severity={report.worst_severity()}\n")


def _step_summary(report, fail_on):
    _github_outputs(report)
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if not path:
        return
    s = report.summary
    lines = [
        f"## LLM Scanner: {report.target_name}",
        "",
        f"**Score {s.security_score}/100, grade {s.grade}**" + (f" · failing on {fail_on}" if fail_on else ""),
        "",
        "| Critical | High | Medium | Low | Safe | Errors |",
        "|---|---|---|---|---|---|",
        f"| {s.critical} | {s.high} | {s.medium} | {s.low} | {s.safe} | {s.errors} |",
        "",
    ]
    for rec in report.recommendations[:5]:
        lines.append(f"- **{rec['priority']} {rec['title']}**: {rec['failed']} failed")
    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def cmd_scan(args) -> int:
    client = _client(args)
    system_prompt = args.prompt
    if args.prompt_file:
        with open(args.prompt_file, encoding="utf-8") as f:
            system_prompt = f.read()
    scan = client.scan(args.name, target_type=args.type, api_url=args.url, api_key=args.target_key,
                       model=args.model, system_prompt=system_prompt, categories=args.categories,
                       baseline_question=args.baseline, target_id=args.target_id)
    print(f"Scan {scan.scan_id} queued for {args.name}")
    if not args.wait:
        return 0

    report = client.wait(scan.scan_id, poll_interval=args.poll, timeout=args.timeout, on_progress=_progress)
    print(str(report.summary))
    for rec in report.recommendations[:5]:
        print(f"  {rec['priority']} {rec['title']}: {rec['failed']} failed")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(client.get(scan.scan_id).get("results"), f, indent=2)
        print(f"Results written to {args.json}")
    if args.download:
        print(f"Report saved to {client.download(scan.scan_id, args.download, args.out)}")
    _step_summary(report, args.fail_on)

    if args.fail_on and report.has_findings_at_or_above(args.fail_on):
        print(f"FAILED: findings at or above {args.fail_on.upper()} (worst: {report.worst_severity()})")
        return 1
    if args.min_score is not None and report.security_score < args.min_score:
        print(f"FAILED: score {report.security_score} is below --min-score {args.min_score}")
        return 1
    print("PASSED")
    return 0


def cmd_status(args) -> int:
    scan = _client(args).status(args.scan_id)
    print(f"{scan.scan_id}: {scan.status} {scan.progress}% ({scan.completed_attacks}/{scan.total_attacks})")
    if scan.error_message:
        print(f"  {scan.error_message}")
    return 0


def cmd_report(args) -> int:
    print(_client(args).download(args.scan_id, args.format, args.out))
    return 0


def cmd_categories(args) -> int:
    for c in _client(args).categories():
        print(f"{c['id']:<28} {c['attacks']:>4}  {c['title']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="llmscanner", description="Scan AI apps with LLM Scanner")
    parser.add_argument("--api-key", default=None, help="LLM Scanner API key (default: $LLMSCANNER_API_KEY)")
    parser.add_argument("--api-url", default=None, help="API URL (default: $LLMSCANNER_API_URL)")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="start a scan")
    scan.add_argument("--name", required=True, help="target name shown in reports")
    scan.add_argument("--type", default="simulation",
                      choices=["simulation", "groq", "openai_compatible", "custom_rest"])
    scan.add_argument("--url", help="target API URL")
    scan.add_argument("--target-key", default=os.getenv("LLMSCANNER_TARGET_KEY"),
                      help="the target's own API key (default: $LLMSCANNER_TARGET_KEY)")
    scan.add_argument("--model")
    scan.add_argument("--prompt", help="system prompt (simulation/groq) or known prompt for leak detection")
    scan.add_argument("--prompt-file")
    scan.add_argument("--baseline", help="a harmless question for the baseline reply")
    scan.add_argument("--categories", nargs="+")
    scan.add_argument("--target-id", help="use a saved target instead of --type/--url/--target-key")
    scan.add_argument("--wait", action="store_true", help="wait for the result")
    scan.add_argument("--fail-on", type=str.lower, choices=[s.lower() for s in SEVERITY_RANK if s != "SAFE"],
                      help="exit 1 if any finding is at or above this severity")
    scan.add_argument("--min-score", type=int, help="exit 1 if the score is below this")
    scan.add_argument("--json", help="write the full results to this file")
    scan.add_argument("--download", choices=["pdf", "html", "md", "json"], help="download a report")
    scan.add_argument("--out", help="where to save the downloaded report")
    scan.add_argument("--poll", type=float, default=10.0, help="seconds between status checks")
    scan.add_argument("--timeout", type=float, default=None, help="give up after this many seconds")
    scan.set_defaults(func=cmd_scan)

    status = sub.add_parser("status", help="show a scan's status")
    status.add_argument("scan_id")
    status.set_defaults(func=cmd_status)

    rep = sub.add_parser("report", help="download a finished scan's report")
    rep.add_argument("scan_id")
    rep.add_argument("--format", default="pdf", choices=["pdf", "html", "md", "json"])
    rep.add_argument("--out")
    rep.set_defaults(func=cmd_report)

    cats = sub.add_parser("categories", help="list attack categories")
    cats.set_defaults(func=cmd_categories)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except LLMScannerError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
