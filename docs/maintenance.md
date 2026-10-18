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
Reports in `REPORTS_DIR` can always be rebuilt from the database, so they don't need backups.

## 4. Rotating secrets

- **SECRET_KEY** signs login tokens. Rotating it signs everyone out. If `ENCRYPTION_KEY` is not set,
  it also makes stored target keys unreadable: set `ENCRYPTION_KEY` to a Fernet key first, or ask
  users to re-enter their saved targets' keys.
- **Webhook secrets** rotate per user in Settings → Webhook.
- **API keys** are revoked per key in Settings → API keys.

## 5. Stripe

In the Stripe dashboard:

1. Create products and monthly prices for Pro and Enterprise; set `STRIPE_PRO_PRICE_ID` and
   `STRIPE_ENTERPRISE_PRICE_ID`. The Pricing page shows the amounts from Stripe.
2. Add a webhook endpoint `https://<api>/api/stripe-webhook` for `checkout.session.completed`,
   `customer.subscription.created`, `customer.subscription.updated`,
   `customer.subscription.deleted` and `invoice.payment_failed`; set `STRIPE_WEBHOOK_SECRET`.
3. Enable the customer portal (Settings → Billing → Customer portal) and allow cancellation
   "at the end of the billing period".
