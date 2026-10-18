# FAQ

**Is it legal to scan an AI app?**
Only scan applications you own or are explicitly authorized to test. A scan sends real adversarial
prompts and uses the target's API quota.

**What does a scan cost?**
Each attack is one call to the target plus one call to the judge model (Groq by default); a
multi-turn attack is three target calls. A full scan is about 1,090 attacks, so roughly 1,100
calls per model. Choose fewer categories for a cheaper, faster scan.

**Why does a full scan stall or take hours on a free Groq key?**
Groq's free tier allows about 1,000 requests per day and 8,000 tokens per minute per model, which
is less than one full scan. The scanner waits and retries when Groq rate-limits it, but a full scan
needs a paid Groq tier (or fewer categories). Attacks that still fail are marked ERROR and left
out of the score.

**How long does it take?**
It depends on how fast the target and the judge answer, and on `SCAN_CONCURRENCY`. Progress is
shown live in the web app, the CLI and the VS Code extension.

**Why is my score 49 when almost every attack was refused?**
Any CRITICAL finding caps the score at 49. One full system-prompt leak is a serious problem
regardless of how many attacks failed. See the scoring rules in the README.

**What is an ERROR finding?**
The target or the judge couldn't be reached, or the judge's answer couldn't be read. Errors are
excluded from the score and listed in the report, so check them before trusting a scan.

**Where is my data stored, and for how long?**
In the API's SQLite database until you delete the scan or your account (Settings → Delete account).
A target's API key is encrypted while its scan runs and deleted when it ends, unless you save the
target. You can export everything from Settings → Export your data.

**Can I add my own attacks?**
Yes: Attack library → Your custom attacks. They run with every scan unless you untick them.
