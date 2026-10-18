# API reference

Interactive docs with request and response schemas: `GET /docs` on your API.

Authenticate with `Authorization: Bearer <access token>` (from `/auth/login`) or with an API key in `X-API-Key: llmsk_...` (create one in Settings or with `POST /api/keys`).

_This page is generated from the FastAPI routes in `backend/api.py`._

| Method | Path | Auth | What it does |
|---|---|---|---|
| GET | `/` |  | API name, version and a link to the interactive docs. |
| GET | `/analytics/categories` | yes | Failure rate per attack category across all your finished scans. |
| POST | `/api/billing/portal` | yes | A link to Stripe's portal to update cards, see invoices or cancel. |
| POST | `/api/checkout` | yes | Creates a Stripe Checkout session for the signed-in user. |
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
| PUT | `/api/webhook` | yes | Sets (or clears, with null) the URL we POST scan events to. Returns the signing |
| POST | `/api/webhook/rotate` | yes | Creates a new webhook signing secret (the old one stops working). |
| POST | `/api/webhook/test` | yes | Sends a test `ping` event to your webhook. |
| POST | `/auth/forgot-password` |  | Emails a password reset link (always answers the same, to avoid revealing accounts). |
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
| GET | `/download/html/{scan_id}` | yes | Downloads the HTML report (rebuilt from the stored results if the file is gone). |
| GET | `/download/json/{scan_id}` | yes | Downloads the raw results as JSON. |
| GET | `/download/md/{scan_id}` | yes | Downloads the Markdown report. |
| GET | `/download/{scan_id}` | yes | Downloads the PDF report. |
| GET | `/health` |  | Liveness check, plus whether storage, email and billing are configured. |
| GET | `/results/{scan_id}` | yes | The full report data (summary + every finding) of a finished scan. |
| POST | `/scan` | yes | Queues a scan. Poll GET /scan/{id} for progress. |
| GET | `/scan/compare/{base_id}/{head_id}` | yes | What got worse or better between two finished scans. |
| DELETE | `/scan/{scan_id}` | yes | Deletes a scan, its findings and its report files. |
| GET | `/scan/{scan_id}` | yes | Status and progress; includes the findings once the scan is complete. |
| POST | `/scan/{scan_id}/cancel` | yes | Stops a queued or running scan. |
| DELETE | `/scan/{scan_id}/share` | yes | Disables the scan's share link. |
| POST | `/scan/{scan_id}/share` | yes | Creates a read-only link to a finished scan that expires after `days`. |
| GET | `/scans` | yes | Your scans, newest first (summary only; findings come from /scan/{id}). |
| GET | `/shared/{token}` |  | A shared report: findings and summary only, never the target's configuration. |
| POST | `/targets/test` | yes | Sends one harmless question to a target and reports what happened. |
