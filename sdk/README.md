# llmscanner

Python client and command-line tool for the LLM Scanner API. Start security scans of your AI
applications, wait for the result, download reports, and fail CI when a scan finds problems.

```bash
pip install llmscanner
```

Create an API key in the web app (Settings → API keys).

## Python

```python
from llmscanner import Client

client = Client(api_key="llmsk_...", base_url="https://your-llm-scanner-api")
scan = client.scan(
    "Support bot",
    target_type="openai_compatible",
    api_url="https://api.openai.com/v1",
    api_key="sk-...",            # the target's key: encrypted while the scan runs, then deleted
    model="gpt-4o-mini",
    categories=["extraction", "direct_override"],   # omit for all 22 categories
)
report = client.wait(scan.scan_id, on_progress=lambda s: print(s.progress, "%"))
print(report.security_score, report.grade)
for finding in report.critical_findings:
    print(finding)
client.download(scan.scan_id, "pdf", "report.pdf")
client.download(scan.scan_id, "evidence", "evidence.pdf")   # testing evidence for audits (paid plans)
```

## Command line

```bash
export LLMSCANNER_API_KEY=llmsk_...
export LLMSCANNER_API_URL=https://your-llm-scanner-api

llmscanner scan --name "Support bot" --type openai_compatible \
  --url https://api.openai.com/v1 --target-key "$OPENAI_API_KEY" --model gpt-4o-mini \
  --wait --fail-on high --download pdf --out report.pdf
```

A custom REST endpoint takes a JSON message and returns a JSON reply; name the fields if they aren't
`message` / `response`:

```bash
llmscanner scan --name "Help desk" --type custom_rest --url https://api.example.com/chat \
  --input-field question --output-field answer --wait --fail-on high
```

`--quick` runs about 5 attacks per category (~110) instead of all ~1,090: a fast check for every pull
request, with a full scan before a release.

Exit codes: `0` passed, `1` a finding at or above `--fail-on` (or a score below `--min-score`), `2` error,
`130` interrupted. With `--wait`, the scan belongs to the command: when `--timeout` passes or the command is
interrupted (Ctrl+C, a cancelled CI job), the scan is cancelled rather than left holding one of your
account's scan slots. Leave out `--wait` to start a scan and check on it later with `llmscanner status`.
In GitHub Actions the result is also written to the job summary. A report that can't be downloaded is a
warning, not a failure, and waiting rides out a few failed status checks in a row (the API restarting
during a deploy): the scan itself resumes from where it was.

Findings your team marked as a false positive or an accepted risk (in the web app, or with
`client.triage(scan_id, finding.key, "accepted_risk", note=...)`) don't fail the build, and
`--min-score` compares the score after triage. In Python, `report.open_findings` lists what still needs
fixing, and `has_findings_at_or_above("high", include_triaged=True)` counts everything.
