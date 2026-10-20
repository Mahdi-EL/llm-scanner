# FAQ

**Is it legal to scan an AI app?**
Only scan applications you own or are explicitly authorized to test. A scan sends real adversarial
prompts and uses the target's API quota.

**What does a scan cost?**
Each attack is one call to the target plus one call to the judge model (Groq by default); a
multi-turn attack is three target calls. A full scan is about 1,090 attacks, so roughly 1,100
calls per model. Plain refusals ("I'm sorry, I can't help with that.") that the rule detectors
cleared are graded without a judge call. Choose fewer categories, or a quick scan, for a cheaper,
faster scan.

**Why does a full scan stall or take hours on a free Groq key?**
Groq's free tier allows about 1,000 requests per day and 8,000 tokens per minute per model, which
is less than one full scan. The scanner waits and retries when Groq rate-limits it, but a full scan
needs a paid Groq tier (or fewer categories). Attacks that still fail are marked ERROR and left
out of the score; if more than half of them fail, the scan fails rather than report a score.

**What is a quick scan?**
About 5 attacks from every category (110 in all), spread from the basic ones to the most
sophisticated, instead of all 1,090. It's ten times faster and cheaper, which suits a check on every
change; run a full scan before a release. A quick scan counts as one scan.

**How long does it take?**
It depends on how fast the target and the judge answer, and on `SCAN_CONCURRENCY`. Progress is
shown live in the web app, the CLI and the VS Code extension.

**Why is my score 49 when almost every attack was refused?**
Any CRITICAL finding caps the score at 49. One full system-prompt leak is a serious problem
regardless of how many attacks failed. See the scoring rules in the README.

**A finding is wrong, or a risk we accept. Can I mark it?**
Yes: open the finding on its results page and choose False positive or Accept risk (with an optional
note). The mark applies to that attack in every scan of the same target: re-tests, hardened-prompt
suggestions and regression alerts leave it out, and the page shows the score after triage next to
the original one. Reports keep the original grading. Reopen a finding to undo the mark.

**Can I give an auditor or a customer proof of testing?**
On paid plans, a scan's results page has an Evidence report: a PDF with the scope and method, coverage
of every OWASP Top 10 for LLM Applications risk (including the ones a prompt scan can't test), the
results before and after triage, each triage decision with its note, the latest re-test of the
failures, and a sign-off block. It is testing evidence, not a compliance certificate.

**What is an ERROR finding?**
The target or the judge couldn't be reached, or the judge's answer couldn't be read. Errors are
excluded from the score and listed in the report, so check them before trusting a scan. A scan
where more than half the attacks errored (`MAX_ERROR_PERCENT`, default 50) fails instead of
reporting a score.

**Where is my data stored, and for how long?**
In the API's SQLite database until you delete the scan or your account (Settings → Delete account).
A target's API key is encrypted while its scan runs and deleted when it ends, unless you save the
target. You can export everything from Settings → Export your data.

**Can I add my own attacks?**
Yes: Attack library → Your custom attacks. They run with every scan unless you untick them.
