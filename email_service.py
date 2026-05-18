import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
from typing import Optional

RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
FROM_EMAIL     = os.getenv("FROM_EMAIL", "noreply@llmscanner.com")
APP_URL        = os.getenv("APP_URL", "https://llmscanner.vercel.app")


def _send(to: str, subject: str, html: str) -> bool:
    """Sends an email via Resend. Returns True on success, silently fails otherwise."""
    if not RESEND_API_KEY:
        return False
    try:
        import resend as _resend
        _resend.api_key = RESEND_API_KEY
        _resend.Emails.send({
            "from"   : FROM_EMAIL,
            "to"     : to,
            "subject": subject,
            "html"   : html
        })
        return True
    except Exception:
        return False


def send_waitlist_welcome(email: str) -> bool:
    """Welcome email sent when a user joins the waitlist."""
    html = f"""
    <div style="font-family:Inter,sans-serif;max-width:520px;margin:0 auto;background:#0a0c14;color:#e2e8f0;padding:40px;border-radius:12px">
      <div style="font-size:24px;font-weight:800;margin-bottom:8px">🔐 LLM<span style="color:#3b82f6">Scanner</span></div>
      <h1 style="font-size:20px;margin:24px 0 12px">You're on the waitlist!</h1>
      <p style="color:#94a3b8;line-height:1.6">
        Thanks for joining. We'll notify you as soon as your early access is ready.
        LLM Scanner automatically detects prompt injection, jailbreaks, and data leaks
        in AI applications — before attackers do.
      </p>
      <a href="{APP_URL}" style="display:inline-block;margin:28px 0;padding:12px 28px;background:#3b82f6;color:white;border-radius:8px;text-decoration:none;font-weight:600">
        Learn More →
      </a>
      <p style="color:#475569;font-size:12px;margin-top:32px;border-top:1px solid #1e2340;padding-top:16px">
        LLM Scanner · Built in Paris 🇫🇷 · <a href="{APP_URL}" style="color:#3b82f6">llmscanner.vercel.app</a>
      </p>
    </div>
    """
    return _send(email, "You're on the LLM Scanner waitlist!", html)


def send_scan_complete(email: str, target_name: str, score: int, scan_id: str) -> bool:
    """Notification email when a scan finishes."""
    color  = "#22c55e" if score >= 70 else "#f97316" if score >= 40 else "#ef4444"
    grade  = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    report = f"{APP_URL}/results/{scan_id}"
    html   = f"""
    <div style="font-family:Inter,sans-serif;max-width:520px;margin:0 auto;background:#0a0c14;color:#e2e8f0;padding:40px;border-radius:12px">
      <div style="font-size:24px;font-weight:800;margin-bottom:8px">🔐 LLM<span style="color:#3b82f6">Scanner</span></div>
      <h1 style="font-size:20px;margin:24px 0 4px">Scan Complete: {target_name}</h1>
      <p style="color:#94a3b8;margin-bottom:24px">Your security scan has finished.</p>
      <div style="background:#111320;border-radius:10px;padding:24px;text-align:center;margin-bottom:28px">
        <div style="font-size:56px;font-weight:900;color:{color}">{score}</div>
        <div style="color:#64748b;font-size:14px">Security Score</div>
        <div style="font-size:32px;font-weight:800;color:{color};margin-top:4px">Grade {grade}</div>
      </div>
      <a href="{report}" style="display:inline-block;padding:12px 28px;background:#3b82f6;color:white;border-radius:8px;text-decoration:none;font-weight:600">
        View Full Report →
      </a>
      <p style="color:#475569;font-size:12px;margin-top:32px;border-top:1px solid #1e2340;padding-top:16px">
        LLM Scanner · <a href="{APP_URL}" style="color:#3b82f6">llmscanner.vercel.app</a>
      </p>
    </div>
    """
    return _send(email, f"Scan complete: {target_name} — Score {score}/100", html)


def send_password_reset(email: str, reset_token: str) -> bool:
    """Password reset email."""
    link = f"{APP_URL}/reset-password?token={reset_token}"
    html = f"""
    <div style="font-family:Inter,sans-serif;max-width:520px;margin:0 auto;background:#0a0c14;color:#e2e8f0;padding:40px;border-radius:12px">
      <div style="font-size:24px;font-weight:800;margin-bottom:8px">🔐 LLM<span style="color:#3b82f6">Scanner</span></div>
      <h1 style="font-size:20px;margin:24px 0 12px">Reset your password</h1>
      <p style="color:#94a3b8;line-height:1.6">
        Click the button below to reset your password. This link expires in 1 hour.
      </p>
      <a href="{link}" style="display:inline-block;margin:28px 0;padding:12px 28px;background:#3b82f6;color:white;border-radius:8px;text-decoration:none;font-weight:600">
        Reset Password →
      </a>
      <p style="color:#475569;font-size:13px">If you didn't request this, ignore this email.</p>
      <p style="color:#475569;font-size:12px;margin-top:32px;border-top:1px solid #1e2340;padding-top:16px">
        LLM Scanner · <a href="{APP_URL}" style="color:#3b82f6">llmscanner.vercel.app</a>
      </p>
    </div>
    """
    return _send(email, "Reset your LLM Scanner password", html)
