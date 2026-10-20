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
llmscanner scan --name "Help desk" --type custom_rest --url https://api.example.com/chat   --input-field question --output-field answer --wait --fail-on high
```

Exit codes: `0` passed, `1` a finding at or above `--fail-on` (or a score below `--min-score`), `2` error.
In GitHub Actions the result is also written to the job summary.
