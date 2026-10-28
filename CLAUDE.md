# CLAUDE.md

Working rules for every session in this repo. LLM Scanner red-teams AI applications: it fires the attack
library at a target, grades every reply and reports a score.

## Layout

```
backend/              FastAPI app (api.py) with flat imports (`import config`); conftest.py puts backend/ on sys.path
  config.py           every setting, read once from the environment (plans and quotas: payment.py)
  scanner.py, judge.py, detectors.py, scoring.py   the scan engine
  runner.py           runs scans in background threads, checkpoints, resumes after restarts
  services.py         quotas and starting a scan (shared by the API and the scheduler)
  store.py            saved targets, schedules, custom prompts, share links; scheduler.py runs schedules
  firewall.py, gateway.py   runtime AI firewall and the OpenAI-compatible gateway in front of it
  vault.py, logsafe.py      encryption at rest, and secrets kept out of logs
  attacks/            prompts.py (the attack library), catalog.py (titles, OWASP mapping, fixes), multi_turn.py
  tests/              pytest
frontend/             React + Vite web app; Vitest tests sit next to the code (*.test.js)
sdk/                  Python SDK (llmscanner.Client) and the `llmscanner` CLI
.github/actions/scan/action.yml   the reusable GitHub Action; .github/workflows/ holds CI
vscode-llm-scanner/   VS Code extension
docs/                 api-reference.md, attack-categories.md, faq.md, maintenance.md
```

Every environment variable is documented in `.env.example`. `docs/LAUNCH_CONTENT.md` is marketing that gets
rewritten separately: leave it alone unless the task is about it.

## Run locally

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt && pip install -e sdk
cp .env.example .env                                  # set GROQ_API_KEY
uvicorn api:app --app-dir backend --reload            # API on http://localhost:8000, docs at /docs
cd frontend && npm ci && npm run dev                  # web app on http://localhost:3000
```

`python backend/scanner.py --help` runs the engine without a server; `python backend/cli.py --help` lists
the local tools.

## Checks: all must pass before a task is done

```bash
pytest backend
ruff check backend sdk
cd frontend && npm test
node vscode-llm-scanner/test/extract.test.js
```

CI (`.github/workflows/ci.yml`) runs the same on Python 3.11 and Node 20, plus `npm run build`, pip-audit
and npm audit.

## Rules

- **Docs mirror the code, and tests check them.** `docs/api-reference.md` lists every route
  (`test_api_reference_lists_every_route`); `docs/attack-categories.md` gives each category's exact prompt
  count and the total (`test_attack_categories_doc_matches_the_library`). Update them in the same change.
- **A new scan or target setting reaches every surface:** the request models in `api.py`, `runner.py`,
  saved targets (`store.py`), re-tests (`_RETEST_KEEP` in `api.py`), schedules (`scheduler.py`), the web
  app (`NewScan`, `Targets`), the SDK and CLI, `action.yml`, the VS Code extension, the README and the docs.
- **Secrets** (target API keys, webhook secrets, tokens) are stored encrypted (`vault.py`), never logged,
  and never returned by the API.
- **Never hardcode attack or category counts in copy.** The web app reads them from `GET /categories`;
  backend strings compute them from the library (`ATTACK_PROMPTS`); static docs avoid exact numbers, except
  `docs/attack-categories.md`, which its test keeps exact.
- **Small commits in the existing style:** `fix(scope): what changed, said plainly` (also `feat`, `perf`,
  `test`, `docs`, `chore`).
- **No features beyond the task given.**
