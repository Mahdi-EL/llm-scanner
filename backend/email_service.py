"""Transactional emails sent through Resend.

Every value inserted into an email is HTML-escaped. Failures are logged
(with the reason) instead of being silently dropped. With no
RESEND_API_KEY set, emails are skipped and each send returns False.
"""
import html
import logging

import config

log = logging.getLogger("llmscanner.email")


def enabled() -> bool:
    return bool(config.RESEND_API_KEY)


def _send(to: str, subject: str, html_body: str) -> bool:
    if not enabled():
        log.info("Email skipped (RESEND_API_KEY not set): %s", subject)
        return False
    try:
        import resend as _resend
        _resend.api_key = config.RESEND_API_KEY
        _resend.Emails.send({"from": config.FROM_EMAIL, "to": [to], "subject": subject, "html": html_body})
        return True
    except Exception:
        log.warning("Email to %s failed: %s", to, subject, exc_info=True)
        return False


def _layout(title: str, body: str, button_text: str = None, button_url: str = None) -> str:
    e = html.escape
    button = ""
    if button_text and button_url:
        button = (f'<p style="margin:28px 0"><a href="{e(button_url)}" style="background:#1d1b18;color:#ffffff;'
                  f'padding:11px 22px;border-radius:4px;text-decoration:none;font-weight:600">{e(button_text)}</a></p>')
    return (
        '<div style="background:#faf8f4;padding:32px 0">'
        '<div style="max-width:520px;margin:0 auto;background:#ffffff;border:1px solid #e3ded5;'
        'padding:32px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1d1b18;line-height:1.6">'
        '<div style="font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#6b665e">LLM Scanner</div>'
        f'<h1 style="font-family:Georgia,serif;font-weight:600;font-size:24px;margin:8px 0 16px">{e(title)}</h1>'
        f'{body}{button}'
        f'<p style="color:#6b665e;font-size:12px;margin-top:32px">LLM Scanner · {e(config.APP_URL)}</p>'
        '</div></div>'
    )


def send_waitlist_welcome(email: str) -> bool:
    body = ("<p>Thanks for joining. We'll email you when your early access is ready.</p>"
            "<p>LLM Scanner tests AI applications for prompt injection, jailbreaks and data leaks.</p>")
    return _send(email, "You're on the LLM Scanner waitlist",
                 _layout("You're on the waitlist", body, "Visit LLM Scanner", config.APP_URL))


def scan_link(scan_id: str, workspace: str = None) -> str:
    """The scan's page in the app; with workspace (the account the scan belongs to) the app opens it there,
    so a team member doesn't land in their own workspace and get "not found"."""
    return f"{config.APP_URL}/results/{scan_id}" + (f"?workspace={workspace}" if workspace else "")


def send_scan_complete(email: str, target_name: str, score: int, scan_id: str,
                       grade: str = None, critical: int = 0, high: int = 0, workspace: str = None) -> bool:
    import scoring
    e = html.escape
    grade = grade or scoring.grade(score)
    body = (f"<p>Your scan of <strong>{e(target_name)}</strong> has finished.</p>"
            f'<p style="font-family:Georgia,serif;font-size:40px;margin:8px 0">{int(score)}/100 '
            f'<span style="font-size:22px">grade {e(grade)}</span></p>'
            f"<p>{int(critical)} critical and {int(high)} high-severity findings.</p>")
    return _send(email, f"Scan complete: {target_name[:60]} scored {int(score)}/100",
                 _layout("Scan complete", body, "View the report", scan_link(scan_id, workspace)))


def send_scan_failed(email: str, target_name: str, scan_id: str, reason: str, workspace: str = None) -> bool:
    e = html.escape
    body = (f"<p>Your scan of <strong>{e(target_name)}</strong> stopped before it finished.</p>"
            f"<p style=\"color:#6b665e\">{e(reason[:300])}</p>")
    return _send(email, f"Scan failed: {target_name[:60]}",
                 _layout("Scan failed", body, "Open the scan", scan_link(scan_id, workspace)))


def send_score_drop(email: str, target_name: str, old_score: int, new_score: int, scan_id: str,
                    new_critical: int = 0, workspace: str = None) -> bool:
    e = html.escape
    dropped = new_score < old_score
    body = (f"<p>The latest scheduled scan of <strong>{e(target_name)}</strong> scored "
            f"<strong>{int(new_score)}</strong>, " + (f"down from {int(old_score)}.</p>" if dropped
                                                      else f"the previous run scored {int(old_score)}.</p>"))
    if new_critical:
        body += (f"<p>{int(new_critical)} attack{'s' if new_critical != 1 else ''} the previous run withstood "
                 f"now succeed{'s' if new_critical == 1 else ''} at critical severity.</p>")
    subject = (f"Security regression: {target_name[:60]} dropped to {int(new_score)}" if dropped else
               f"Security regression: {int(new_critical)} new critical finding{'s' if new_critical != 1 else ''} "
               f"on {target_name[:60]}")
    return _send(email, subject,
                 _layout("Security score dropped" if dropped else "New critical findings", body, "See what changed",
                         scan_link(scan_id, workspace)))


def send_schedule_skipped(email: str, target_name: str, frequency: str, reason: str) -> bool:
    e = html.escape
    body = (f"<p>The {e(frequency)} scan of <strong>{e(target_name)}</strong> didn't run.</p>"
            f"<p style=\"color:#6b665e\">{e(reason[:300])}</p>"
            "<p>The schedule stays on and tries again at its next run. We won't email you again about "
            "this reason this month.</p>")
    return _send(email, f"Scheduled scan skipped: {target_name[:60]}",
                 _layout("Scheduled scan skipped", body, "See your plan", f"{config.APP_URL}/pricing"))


def send_password_reset(email: str, reset_token: str) -> bool:
    body = ("<p>Click the button below to choose a new password. The link expires in one hour.</p>"
            "<p style=\"color:#6b665e;font-size:13px\">If you didn't ask for this, ignore this email.</p>")
    return _send(email, "Reset your LLM Scanner password",
                 _layout("Reset your password", body, "Choose a new password",
                         f"{config.APP_URL}/reset-password?token={reset_token}"))


def send_verification(email: str, token: str) -> bool:
    body = "<p>Confirm this email address to finish setting up your account. The link expires in two days.</p>"
    return _send(email, "Confirm your email for LLM Scanner",
                 _layout("Confirm your email", body, "Confirm email",
                         f"{config.APP_URL}/verify-email?token={token}"))


def send_team_invite(email: str, inviter: str, workspace: str, link: str) -> bool:
    e = html.escape
    body = (f"<p><strong>{e(inviter)}</strong> invited you to the <strong>{e(workspace)}</strong> workspace on "
            "LLM Scanner. The invite expires in 7 days and works with this email address.</p>")
    return _send(email, f"{inviter[:60]} invited you to LLM Scanner",
                 _layout("You're invited", body, "Join the workspace", link))


def send_payment_failed(email: str) -> bool:
    body = ("<p>We couldn't take your last subscription payment. "
            "Please update your card to keep your plan.</p>")
    return _send(email, "Your LLM Scanner payment failed",
                 _layout("Payment failed", body, "Update billing", f"{config.APP_URL}/settings"))
