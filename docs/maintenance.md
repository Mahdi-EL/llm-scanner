# Maintenance and operations

## 1. Remove old user data from the public git history

Earlier commits contained `results/llmscanner.db` (with password hashes), `results/waitlist.csv`
(a real email address) and `results/.encryption_key`. The files are no longer tracked, but they are
still in the history of the public repository. Removing them means rewriting history and
force-pushing, which changes every commit hash, so do it when no one else has open branches.

```bash
pip install git-filter-repo
git clone --mirror https://github.com/Mahdi-EL/llm-scanner.git llm-scanner-mirror
cd llm-scanner-mirror
git filter-repo --invert-paths \
  --path-glob 'results/*.db' --path-glob '*.db' \
  --path results/waitlist.csv --path results/.encryption_key \
  --path-glob 'results/*.json' --path-glob 'results/*.pdf'
git push --force --mirror
```

Then:

- Ask GitHub Support to purge cached views of the old commits (forks and caches can keep them).
- Treat every account that was in the old database as exposed: force a password reset (below).
- Everyone with a clone must re-clone; old clones still contain the files.

## 2. Force a password reset for exposed accounts

```bash
python - <<'EOF'
import sys; sys.path.insert(0, "backend")
import auth_db, database, email_service
from db import transaction
database.init_db()
with transaction() as conn:
    users = [dict(r) for r in conn.execute("SELECT id, email FROM users WHERE created_at < '2026-06-18'")]
for user in users:
    auth_db.revoke_all_sessions(user["id"])          # sign them out everywhere
    token = auth_db.create_reset_token(user["email"])
    if token:
        email_service.send_password_reset(user["email"], token)
print(f"reset {len(users)} accounts")
EOF
```

Adjust the date to when the database stopped being committed.

## 3. Backups

The database is a single SQLite file (`DB_PATH`). Copy it safely while the API runs with SQLite's
backup API:

```bash
python - <<'EOF'
import sqlite3, datetime
src = sqlite3.connect("/data/llmscanner.db")
dst = sqlite3.connect(f"/data/backup-{datetime.date.today()}.db")
src.backup(dst); dst.close(); src.close()
EOF
```

Run it daily (cron, a Railway cron service, or a GitHub Action) and copy the file off the server,
or use [Litestream](https://litestream.io) to stream changes to S3-compatible storage continuously.
Reports are built from the database when they're downloaded, so the database is all there is to back up
(`REPORTS_DIR` only holds files written by versions before October 2026; they can be deleted).

**Database size.** A full scan keeps about 1.5 MB of results (a quick scan about a tenth of that), and
scans stay until their owner deletes them. To cap growth, set `SCAN_RETENTION_DAYS` (for example 365):
the hourly housekeeping then deletes finished scans older than that. SQLite reuses the freed space but
doesn't shrink the file; to give it back to the disk, run `VACUUM` at a quiet time (it needs free disk
space about the size of the database):

```bash
python -c "import sqlite3; c = sqlite3.connect('/data/llmscanner.db'); c.execute('VACUUM'); c.close()"
```

## 4. Rotating secrets

- **SECRET_KEY** signs login tokens. Rotating it signs everyone out. If `ENCRYPTION_KEY` is not set,
  it also makes stored target keys unreadable: set `ENCRYPTION_KEY` to a Fernet key first, or ask
  users to re-enter their saved targets' keys.
- **Webhook secrets** rotate per user in Settings → Webhook.
- **API keys** are revoked per key in Settings → API keys.

## 5. Stripe

Quickest: let the setup script create the products, monthly and yearly prices and the webhook,
then paste what it prints into the API's environment. Run it with a test key first; it's safe to
run again.

```bash
STRIPE_SECRET_KEY=sk_test_... python backend/stripe_setup.py --api-url https://<api>
```

Then do step 3 below and buy a plan once with the test card 4242 4242 4242 4242.

Or by hand, in the Stripe dashboard:

1. Create products and monthly prices for Pro and Enterprise; set `STRIPE_PRO_PRICE_ID` and
   `STRIPE_ENTERPRISE_PRICE_ID`. The Pricing page shows the amounts from Stripe. Optional: yearly
   prices in `STRIPE_PRO_YEARLY_PRICE_ID` / `STRIPE_ENTERPRISE_YEARLY_PRICE_ID` add a Monthly/Yearly
   switch, and `STRIPE_TRIAL_DAYS=14` gives first-time customers a trial (one per customer: anyone
   who has paid before is charged straight away). A customer who picks another plan on the Pricing
   page has their subscription switched, prorated, instead of getting a second one; the same goes
   for moving their plan between monthly and yearly billing.
2. Add a webhook endpoint `https://<api>/api/stripe-webhook` for `checkout.session.completed`,
   `customer.subscription.created`, `customer.subscription.updated`,
   `customer.subscription.deleted` and `invoice.payment_failed`; set `STRIPE_WEBHOOK_SECRET`.
3. Enable the customer portal (Settings → Billing → Customer portal) and allow cancellation
   "at the end of the billing period".

## 6. Model costs

Every scan records the model tokens it cost this server (the judge, plus the target for simulation
scans). See them per plan for the last 30 days:

```bash
python backend/cli.py costs --price-in 0.15 --price-out 0.75   # $ per million tokens
```

Compare the cost per user with what each plan pays. To lower it: plain refusals already skip the
judge (`JUDGE_SKIP_CLEAR_REFUSALS`); `JUDGE_REASONING_EFFORT=low` cuts the judge's billed reasoning
tokens (check a few reports first); quick scans run about a tenth of the attacks.
