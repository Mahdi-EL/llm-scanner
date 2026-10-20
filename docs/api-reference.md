# API reference

Interactive docs with request and response schemas: `GET /docs` on your API.

Authenticate with `Authorization: Bearer <access token>` (from `/auth/login`) or with an API key in `X-API-Key: llmsk_...` (create one in Settings or with `POST /api/keys`). An API key can run and read scans, saved targets, schedules and the firewall, but not manage API keys, the webhook, billing, the password, the data export or account deletion (403): those need a signed-in session.

Errors are JSON with a readable `detail`: a string, or for invalid input (422) a list of `{loc, msg, type}` (the rejected value isn't echoed back). Request bodies are limited to 1 MB (413); 429 responses carry `Retry-After`.

_This page lists the FastAPI routes in `backend/api.py`; a test fails when a route is missing from it._

| Method | Path | Auth | What it does |
|---|---|---|---|
| GET | `/` |  | API name, version and a link to the interactive docs. |
| GET | `/analytics/categories` | yes | Failure rate per attack category across all your finished scans. |
| POST | `/api/billing/portal` | yes | A link to Stripe's portal to update cards, see invoices or cancel. |
| POST | `/api/checkout` | yes | Creates a Stripe Checkout session for the signed-in user. |
| POST | `/api/firewall/check` | yes | Screens a user message before it reaches your model: allow, review or block, with reasons. Every started 2,000 characters count as one check against your plan's daily allowance. |
| POST | `/api/firewall/check-output` | yes | Screens a model reply before it reaches the user: flags and masks leaked secrets, the canary and copies of the system prompt. Free of charge on plans that include the firewall. |
| GET | `/api/firewall/usage` | yes | Firewall checks used today (UTC) and your plan's daily allowance. |
| GET | `/api/gateway/stats` | yes | Gateway requests in the last `days` days: blocked and flagged inputs, masked or replaced replies. |
| GET | `/api/keys` | yes | Lists your API keys (prefix only, never the full secret). |
| POST | `/api/keys` | yes | Creates an API key. The full key is returned ONCE: store it now. |
| DELETE | `/api/keys/{key_id}` | yes | Revokes an API key immediately. |
| GET | `/api/plans` |  | Plans with prices, scan limits and features. |
| GET | `/api/prompts` | yes | Your custom attack prompts. |
| POST | `/api/prompts` | yes | Adds a custom attack prompt; it runs with your future scans. |
| DELETE | `/api/prompts/{prompt_id}` | yes | Deletes a custom attack prompt. |
| GET | `/api/schedules` | yes | Your scheduled scans. |
| POST | `/api/schedules` | yes | Schedules daily or weekly scans of a saved target (Pro and Enterprise). |
| DELETE | `/api/schedules/{schedule_id}` | yes | Deletes a schedule. |
| PUT | `/api/schedules/{schedule_id}` | yes | Changes, pauses or resumes a schedule. |
| POST | `/api/stripe-webhook` |  | Stripe events: checkout completed, subscription changed or cancelled, payment failed. |
| GET | `/api/targets` | yes | Your saved targets (their API keys are never returned). |
| POST | `/api/targets` | yes | Saves a target; its API key is stored encrypted. |
| DELETE | `/api/targets/{target_id}` | yes | Deletes a saved target and its schedule. |
| PUT | `/api/targets/{target_id}` | yes | Changes a saved target. Send clear_api_key=true to remove its key. |
| POST | `/api/waitlist` |  | Adds an email to the waitlist and sends one welcome email. |
| GET | `/api/waitlist/count` |  | How many people joined the waitlist. |
| GET | `/api/webhook` | yes | Your webhook URL and whether a signing secret exists. |
| PUT | `/api/webhook` | yes | Sets (or clears, with null) the URL we POST scan events to. Returns the signing secret the first time one is created. |
| POST | `/api/webhook/rotate` | yes | Creates a new webhook signing secret (the old one stops working). |
| POST | `/api/webhook/test` | yes | Sends a test `ping` event to your webhook. |
| POST | `/auth/forgot-password` |  | Emails a password reset link. Answers the same whether or not the account exists; 503 when email delivery isn't set up on the server. |
| POST | `/auth/login` |  | Log in with a username or email. Returns an access token and a refresh token. |
| POST | `/auth/logout` |  | Revokes a refresh token; with everywhere=true, ends every session of the caller. |
| DELETE | `/auth/me` | yes | Deletes the account, its scans and report files. Cancels any subscription. |
| GET | `/auth/me` | yes | The signed-in user's profile, plan and usage. |
| GET | `/auth/me/export` | yes | Everything we store about you, as JSON (GDPR data portability). |
| PUT | `/auth/password` | yes | Changes the password, signs out every other session, and returns fresh tokens. |
| POST | `/auth/refresh` |  | Swaps a refresh token for a new access token and a new refresh token. |
| POST | `/auth/register` |  | Creates an account and returns tokens. Sends a confirmation email when email is set up. |
| POST | `/auth/resend-verification` | yes | Sends a new email confirmation link. |
| POST | `/auth/reset-password` |  | Sets a new password with a reset token and signs out every session. |
| POST | `/auth/verify-email` |  | Confirms an email address with the token from the confirmation email. |
| GET | `/categories` |  | The built-in attack categories, with what they test and their OWASP mapping. |
| GET | `/download/evidence/{scan_id}` | yes | A testing-evidence PDF for audits and security reviews: scope, method, OWASP LLM Top 10 coverage, results before and after triage, triage decisions, re-test evidence and a sign-off block. Paid plans. |
| GET | `/download/html/{scan_id}` | yes | Downloads the HTML report (rebuilt from the stored results if the file is gone). |
| GET | `/download/json/{scan_id}` | yes | Downloads the raw results as JSON. |
| GET | `/download/md/{scan_id}` | yes | Downloads the Markdown report. |
| GET | `/download/{scan_id}` | yes | Downloads the PDF report. |
| POST | `/gateway/{target_id}/v1/chat/completions` | yes | OpenAI-compatible chat completions through the AI firewall. Set your OpenAI client's base_url to /gateway/{target_id}/v1 and its api_key to an LLM Scanner API key. |
| GET | `/health` |  | Liveness check, plus whether storage, email and billing are configured. |
| GET | `/models` | yes | Groq models this server can use for simulated and Groq targets, and the defaults in use. |
| POST | `/public/leak-check` |  | Free, no account: sends 20 extraction and override attacks at a system prompt on the demo model and says how many got it out. Graded by rules (the canary, verbatim copies); replies are never returned or stored. |
| GET | `/results/{scan_id}` | yes | The full report data (summary + every finding) of a finished scan. |
| POST | `/scan` | yes | Queues a scan. Poll GET /scan/{id} for progress. |
| GET | `/scan/compare/{base_id}/{head_id}` | yes | What got worse or better between two finished scans. |
| DELETE | `/scan/{scan_id}` | yes | Deletes a scan, its findings and its report files. |
| GET | `/scan/{scan_id}` | yes | Status and progress; includes the findings once the scan is complete. |
| POST | `/scan/{scan_id}/cancel` | yes | Stops a queued or running scan. |
| POST | `/scan/{scan_id}/remediate` | yes | Suggests a hardened system prompt based on the attacks that succeeded in this scan (10 a day on Free, 100 on Pro). |
| POST | `/scan/{scan_id}/retest` | yes | Runs only the attacks that failed in this scan again, optionally with a new system prompt. |
| DELETE | `/scan/{scan_id}/share` | yes | Disables the scan's share link. |
| POST | `/scan/{scan_id}/share` | yes | Creates a read-only link to a finished scan that expires after `days` (default 7). |
| PUT | `/scan/{scan_id}/triage` | yes | Marks a failed finding as a false positive or an accepted risk ("open" clears the mark). The mark applies to that attack in every scan of the same target: re-tests, suggestions and regression alerts leave it out, and the scan shows its score after triage. |
| GET | `/scans` | yes | Your scans, newest first (summary only; findings come from /scan/{id}). |
| GET | `/scans/stats` | yes | Totals over all your finished scans: count, average score, critical findings, clean scans. |
| GET | `/shared/{token}` |  | A shared report: findings and summary only, never the target's configuration. |
| POST | `/targets/test` | yes | Sends one harmless question to a target and reports what happened. |
