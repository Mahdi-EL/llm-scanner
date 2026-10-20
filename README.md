# LLM Scanner

Automated red-teaming for AI applications. LLM Scanner fires over 1,000 adversarial prompts at an
AI app (prompt injection, jailbreaks, system-prompt extraction, data exfiltration, multi-turn
conversations and 17 more categories), grades every reply, and produces a report with a 0–100 score, a letter grade, the
OWASP Top 10 for LLM Applications risk behind each finding, and what to fix first.

It comes as a web app, an HTTP API, a Python SDK and CLI, a GitHub Action and a VS Code extension.

## What a scan does

1. **Sends each attack** to the target: a simulated model with your system prompt, your own Groq
   model, any OpenAI-compatible API (OpenAI, Mistral, Together, OpenRouter, Groq…) or a custom REST endpoint.
2. **Grades each reply** with an LLM judge in JSON mode at temperature 0. The attack, a baseline
   reply and the reply under attack are passed as untrusted data, so the scanned model can't
   talk the judge into a good grade. Replies the judge can't grade are marked `ERROR`, never `SAFE`.
3. **Runs rule-based detectors** that don't depend on the judge: a secret canary planted in the
   system prompt, verbatim system-prompt overlap, and leaked API keys, tokens and card numbers.
4. **Scores the scan.** Failures are weighted by severity, then the score is capped by the worst
   finding: any CRITICAL caps it at 49 (grade F), any HIGH at 69 (D), any MEDIUM at 89 (B).
   One full system-prompt leak can't hide behind a thousand refusals. `ERROR` attacks are left out
   of the score, and a scan where more than half of its attacks errored fails instead of reporting one.

Scans run in a background worker with live progress, retries for rate limits and network errors,
and checkpoints, so a server restart resumes a scan instead of losing it.

## Features

- 1,090 attack prompts in 22 categories (including 15 multi-turn conversations), each mapped to the OWASP LLM Top 10 (2025)
- Quick scans: about 110 attacks spread across every category, for a check on each change
- A free, no-signup leak check at /check: 20 attacks on a pasted system prompt, rule-graded, nothing stored
- Your own custom attack prompts, run with every scan
- Reports in PDF, HTML, Markdown and JSON; read-only share links that expire
- Saved targets (keys stored encrypted), daily or weekly scheduled scans, regression alerts
- Scan comparison: score change, failures introduced and fixed
- API keys for CI, signed webhooks (`scan.completed`, `scan.failed`, `scan.regression`)
- Runtime AI firewall API: screen user messages before your model sees them and replies before your users do
- Firewall gateway: put the firewall in front of any OpenAI-compatible API by changing only the base URL
- Plans and billing with Stripe (Checkout, customer portal, webhooks)
- Triage (false positive / accepted risk, kept per target) and evidence reports for audits: scope, method,
  OWASP LLM Top 10 coverage, triage decisions, re-test proof and a sign-off block (paid plans)
- White-label reports: your organisation's name instead of LLM Scanner (paid plans)
- Teams: invite people by email as viewer, member or admin; switch workspaces in the sidebar
  (Pro: 5 people per workspace, `PRO_SEATS`; Enterprise: no limit)
- Account data export and deletion

## Quick start (local)

Requirements: Python 3.11+, Node 20+, a [Groq API key](https://console.groq.com).

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt
pip install -e sdk                                    # optional: SDK + `llmscanner` command
cp .env.example .env                                  # set GROQ_API_KEY

uvicorn api:app --app-dir backend --reload            # API on http://localhost:8000 (docs at /docs)

cd frontend && npm ci && npm run dev                  # web app on http://localhost:3000
```

Or with Docker: `docker compose up --build` (set `SECRET_KEY` and `GROQ_API_KEY` in `.env` first).

## Running scans

**Web app:** New scan → pick a target type → Test connection → Launch.

**Python SDK and CLI** (`pip install -e sdk`), with an API key from Settings:

```python
from llmscanner import Client
client = Client(api_key="llmsk_...", base_url="http://localhost:8000")
scan = client.scan("Support bot", target_type="openai_compatible",
                   api_url="https://api.openai.com/v1", api_key="sk-...", model="gpt-4o-mini")
report = client.wait(scan.scan_id)
print(report.security_score, report.grade)
```

```bash
llmscanner scan --name "Support bot" --type openai_compatible --url https://api.openai.com/v1 \
  --target-key "$OPENAI_API_KEY" --model gpt-4o-mini --wait --fail-on high
```

**GitHub Actions:** fail a pull request when the scan finds HIGH or worse.

```yaml
- uses: Mahdi-EL/llm-scanner/.github/actions/scan@main
  with:
    api-key: ${{ secrets.LLMSCANNER_API_KEY }}
    api-url: https://your-llm-scanner-api
    target-name: Support bot
    target-type: openai_compatible
    target-url: https://api.openai.com/v1
    target-key: ${{ secrets.OPENAI_API_KEY }}
    model: gpt-4o-mini
    fail-on: high
    quick: "true"        # ~110 attacks on every PR; drop it for a full scan
```

**Engine only, no server:** `python backend/scanner.py --target "Demo" --categories extraction`
writes reports to `results/`. `python backend/cli.py --help` has more local tools.

## Webhooks

Set a URL in Settings → Webhook. Each request carries `X-LLMScanner-Event` and
`X-LLMScanner-Signature: t=<unix time>,v1=<hex>`, where `v1` is HMAC-SHA256 of
`"<t>.<raw body>"` with your webhook secret. Answer with a 2xx within 5 seconds; timeouts,
connection errors, 429 and 5xx are retried twice (after 2 s and 10 s), other 4xx are not.
To verify a request:

```python
import hashlib, hmac, time

def verify(secret: str, body: bytes, header: str) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    if abs(time.time() - int(parts["t"])) > 300:
        return False
    expected = hmac.new(secret.encode(), f"{parts['t']}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts["v1"])
```

## Runtime AI firewall

Call it from your application with an API key (Settings → API keys). It is part of
every plan with a daily allowance (`GET /api/firewall/usage`); Targets & CI in the app
has a box to try messages.

- `POST /api/firewall/check` with `{"text": "<user message>"}` returns
  `{"verdict": "allow" | "review" | "block", "score", "reasons"}`. It combines rules
  (instruction overrides, fake system messages, hidden base64...) with Meta's Prompt
  Guard model. Every started 2,000 characters counts as one check.
- `POST /api/firewall/check-output` with `{"text": "<model reply>", "system_prompt", "canary"}`
  flags leaked secrets, the canary and copies of the system prompt. `redacted` is the reply
  with secrets, card numbers and the canary replaced by `[REDACTED]` (`masked` says how many).
  These checks don't count against the allowance.

```python
from llmscanner import Client

client = Client(api_key="llmsk_...", base_url="https://your-api")
if client.check_input(user_message)["verdict"] == "block":
    ...
checked = client.check_output(reply, system_prompt=SYSTEM_PROMPT)
safe_reply = checked["redacted"] if checked["verdict"] != "block" else "Sorry, I can't help with that."
```

### Gateway: no code changes

Save the app as an OpenAI-compatible (or Groq) target with its key, then point your OpenAI client
at the gateway and use an LLM Scanner key as the `api_key`. Targets & CI shows the URL per target.

```python
client = OpenAI(base_url="https://your-api/gateway/<target id>/v1", api_key="llmsk_...")
```

Each request's new user and tool messages are checked first; a blocked request never reaches the
model and gets an ordinary reply with a refusal (`GATEWAY_BLOCK_MESSAGE`). The rest go to your model
with the saved key (or the one in `X-Upstream-Authorization`), and the reply is checked: leaked
secrets are masked, and a reply that leaks the system prompt, or leaks anything after a flagged
request, is replaced by the refusal. Streaming works (the reply is checked whole, then streamed).
`X-LLMScanner-Input` / `X-LLMScanner-Output` headers give the verdicts. When the day's allowance is
used up, requests pass unscreened with `X-LLMScanner-Firewall: quota-exceeded`. Only verdicts and
timings are stored, never messages; `GET /api/gateway/stats` sums them up.

## Deploying

- **API on Railway:** the repo's `railway.json` runs `uvicorn api:app --app-dir backend`. Attach a
  volume at `/data` and set `DB_PATH=/data/llmscanner.db`, plus `SECRET_KEY`, `GROQ_API_KEY`,
  `ALLOWED_ORIGINS` and `APP_URL`. `/health` reports `"storage": "ephemeral"` when the database
  isn't on a volume.
- **Web app on Vercel:** `vercel.json` builds `frontend/`. Set `VITE_API_URL` (or the older
  `REACT_APP_API_URL`) to the API's URL; the build fails without it.
- **Docker:** see `Dockerfile` (API) and `frontend/Dockerfile` (nginx).

All settings are documented in [`.env.example`](.env.example).

## Security model

- Scans, reports, keys and webhooks belong to one user; other users get 404s.
- Target URLs and webhooks must resolve to public addresses. Every outgoing connection is checked
  at the socket level and redirects are never followed, which blocks DNS-rebinding and redirect
  tricks to internal hosts.
- Passwords use bcrypt. Refresh, reset and verification tokens are stored hashed. Changing your
  password signs out every other session.
- A target's API key is encrypted while its scan runs and deleted when the scan ends; saved
  targets keep it encrypted. Replies are stored with the scan until you delete it or your account.
- Reports escape all model output and set a Content-Security-Policy.

## Tests

```bash
pytest backend                          # API, engine and SDK end to end
ruff check backend sdk
cd frontend && npm test                 # Vitest
node vscode-llm-scanner/test/extract.test.js
```

CI (`.github/workflows/ci.yml`) runs all of these plus `pip-audit` and `npm audit` on every push.

## Project layout

```
backend/        FastAPI app (api.py), scan engine (scanner, judge, detectors, scoring), runner,
                scheduler, reports, auth and billing; tests in backend/tests
backend/attacks prompts.py (the attack library) and catalog.py (titles, OWASP mapping, fixes)
frontend/       React + Vite web app
sdk/            Python SDK and `llmscanner` CLI
vscode-llm-scanner/   VS Code extension
.github/        CI workflows and the reusable scan action
archive/        old modules that the product no longer uses
docs/           extra documentation
```

## License

MIT
