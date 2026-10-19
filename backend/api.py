"""LLM Scanner HTTP API.

Run locally:  uvicorn api:app --app-dir backend --reload
Interactive docs at /docs.
"""
import json
import logging
import os
import re
import socket   # noqa: F401  (tests patch api.socket.getaddrinfo)
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, List, Literal, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import AfterValidator, BaseModel, BeforeValidator, EmailStr, Field, field_validator
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import config    # first: loads .env and refuses to start with a placeholder SECRET_KEY
import analysis
import auth_db
import database
import email_service
import firewall
import groq_models
import netguard
import notifications
import payment
import remediation
import report
import runner
import scan_db
import scheduler
import scoring
import services
import store
from attacks import catalog
from attacks.prompts import ATTACK_PROMPTS
from db import parse_ts
from target import DEFAULT_BASELINE_QUESTION, Target

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

logging.basicConfig(level=config.LOG_LEVEL,
                    format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("llmscanner.api")

VERSION   = "3.0.0"
ALGORITHM = "HS256"

if config.SENTRY_DSN:
    try:
        import sentry_sdk
        sentry_sdk.init(dsn=config.SENTRY_DSN, send_default_pii=False, traces_sample_rate=0.0,
                        environment=config.ENV, release=f"llmscanner@{VERSION}")
    except ImportError:
        log.warning("SENTRY_DSN is set but sentry-sdk isn't installed")

limiter = Limiter(key_func=get_remote_address)


# ── Startup ───────────────────────────────────────────────────
def _on_persistent_disk(path: str) -> bool:
    path = os.path.abspath(path)
    while True:
        if os.path.ismount(path) and os.path.dirname(path) != path:
            return True
        parent = os.path.dirname(path)
        if parent == path:
            return False
        path = parent


def _storage_state() -> str:
    if not os.getenv("RAILWAY_ENVIRONMENT"):
        return "local"
    return "persistent" if _on_persistent_disk(config.DATA_DIR) else "ephemeral"


@asynccontextmanager
async def lifespan(app: FastAPI):
    database.init_db()
    log.info("Database: %s, reports: %s", os.path.abspath(config.DB_PATH), os.path.abspath(config.REPORTS_DIR))
    if _storage_state() == "ephemeral":
        log.error("DB_PATH (%s) is not on a mounted volume: all data will be lost on the next deploy. "
                  "Attach a Railway volume at /data and set DB_PATH=/data/llmscanner.db.", config.DB_PATH)
    if os.getenv("LLMSCANNER_DISABLE_WORKERS") != "1":
        runner.start(resume=True)
        scheduler.start()
    log.info("API ready (v%s, %s)", VERSION, config.ENV)
    yield
    scheduler.stop()
    runner.shutdown()


app = FastAPI(
    title      ="LLM Scanner API",
    description="Scan AI applications for prompt injection, jailbreaks and data leaks.",
    version    =VERSION,
    lifespan   =lifespan,
)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limited(request: Request, exc: RateLimitExceeded):
    """A readable "detail" like every other error, and Retry-After so clients know when to retry."""
    period = str(exc.detail).rsplit(" per ", 1)[-1] if " per " in str(exc.detail) else "minute"
    seconds = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}.get(period.split()[-1].rstrip("s"), 60)
    return JSONResponse({"detail": f"Too many requests. Please wait a moment and try again ({exc.detail})."},
                        status_code=429, headers={"Retry-After": str(seconds)})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception:
        # Answer here, inside CORS, so the browser shows the error instead of a CORS failure.
        log.exception("Unhandled error on %s %s", request.method, request.url.path)
        response = JSONResponse({"detail": "Something went wrong on our side. Please try again."}, status_code=500)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if request.url.path.startswith(("/auth", "/api/keys", "/api/webhook")):
        response.headers["Cache-Control"] = "no-store"
    return response


app.add_middleware(GZipMiddleware, minimum_size=1000)
# Auth uses bearer tokens / API keys in headers, not cookies, so no credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origins    =config.ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods    =["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers    =["Authorization", "Content-Type", "X-API-Key"],
    expose_headers   =["Content-Disposition"],
)


# ── Auth helpers ──────────────────────────────────────────────
def create_access_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user_id, "type": "access", "iat": int(now.timestamp()),
                       "exp": now + timedelta(minutes=config.ACCESS_TOKEN_MINUTES)},
                      config.SECRET_KEY, algorithm=ALGORITHM)


def _decode_access(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[ALGORITHM],
                             options={"require": ["exp", "iat", "sub"]})
    except jwt.PyJWTError:
        return None
    return payload if payload.get("type") == "access" else None


def _user_from_request(request: Request) -> Optional[dict]:
    """The caller, from a JWT (Authorization: Bearer) or an API key
    (X-API-Key header, or Authorization: ApiKey <key>)."""
    scheme, _, credentials = request.headers.get("Authorization", "").partition(" ")
    credentials = credentials.strip()
    if scheme.lower() == "bearer" and credentials:
        payload = _decode_access(credentials)
        user = auth_db.get_user_by_id(payload["sub"]) if payload else None
        if not user:
            return None
        valid_after = user.get("tokens_valid_after")
        if valid_after and payload["iat"] < int(parse_ts(valid_after).timestamp()):
            return None          # issued before a password change or "log out everywhere"
        return user
    key = request.headers.get("X-API-Key") or (credentials if scheme.lower() == "apikey" else None)
    if key:
        user_id = auth_db.get_user_by_api_key(key)
        return auth_db.get_user_by_id(user_id) if user_id else None
    return None


def require_user(request: Request) -> dict:
    user = _user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def _token_response(user: dict) -> dict:
    return {
        "access_token" : create_access_token(user["id"]),
        "refresh_token": auth_db.create_refresh_token(user["id"]),
        "token_type"   : "bearer",
        "expires_in"   : config.ACCESS_TOKEN_MINUTES * 60,
        "user"         : _public_user(user),
    }


def _public_user(user: dict) -> dict:
    q = services.quota(user)
    return {
        "id"                : user["id"],
        "username"          : user["username"],
        "email"             : user.get("email", ""),
        "plan"              : user.get("plan", "free"),
        "scans_count"       : user.get("scans_count", 0),
        "scans_this_month"  : q["used"],
        "scan_limit"        : q["limit"],
        "email_verified"    : bool(user.get("email_verified")),
        "created_at"        : user.get("created_at", ""),
        "webhook_url"       : user.get("webhook_url"),
        "has_webhook_secret": bool(user.get("webhook_secret")),
        "has_billing"       : bool(user.get("stripe_customer_id")),
    }


def _check_new_password(password: str) -> None:
    """bcrypt>=5 raises above 72 bytes, so reject those up front."""
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if len(password.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password must be at most 72 bytes long")


# ── Request models ────────────────────────────────────────────
TargetType = Literal["simulation", "groq", "openai_compatible", "custom_rest"]
MODEL_PATTERN = r"^[A-Za-z0-9._:/@+-]{1,100}$"
FIELD_PATTERN = r"^[A-Za-z0-9_.-]{1,64}$"
SLUG_PATTERN  = r"^[a-z0-9_-]{1,40}$"


def _must_match(pattern: str, message: str):
    def check(value: str) -> str:
        if not re.fullmatch(pattern, value):
            raise ValueError(message)
        return value
    return AfterValidator(check)


def _strip(value):
    return value.strip() if isinstance(value, str) else value


def _slugify(value):
    """"Refund abuse" -> "refund_abuse": the UI takes free text, the API stores slugs."""
    return re.sub(r"\s+", "_", value.strip().lower()) if isinstance(value, str) else value


ModelName = Annotated[str, BeforeValidator(_strip), _must_match(
    MODEL_PATTERN, "Model names use letters, numbers and . _ : / @ + - (up to 100 characters)")]
FieldName = Annotated[str, BeforeValidator(_strip), _must_match(
    FIELD_PATTERN, "Field names use letters, numbers, dots, dashes or underscores (up to 64 characters)")]
Slug = Annotated[str, BeforeValidator(_slugify), _must_match(
    SLUG_PATTERN, "Categories use letters, numbers, dashes or underscores (up to 40 characters)")]


class TargetConfig(BaseModel):
    target_type      : TargetType = "simulation"
    system_prompt    : Optional[str] = Field(None, max_length=20000)
    api_url          : Optional[str] = Field(None, max_length=2048)
    api_key          : Optional[str] = Field(None, max_length=1000)
    model            : Optional[ModelName] = None
    baseline_question: Optional[str] = Field(None, max_length=1000)
    input_field      : Optional[FieldName] = None
    output_field     : Optional[FieldName] = None

    def target_config(self) -> dict:
        return self.model_dump(exclude={"api_key"}, exclude_none=True,
                               include=set(TargetConfig.model_fields) - {"api_key"})


class ScanRequest(TargetConfig):
    target_name           : str = Field(..., min_length=1, max_length=120)
    categories            : Optional[List[str]] = Field(None, max_length=50)
    target_id             : Optional[str] = Field(None, max_length=64)
    include_custom_prompts: bool = True

    @field_validator("target_name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target name can't be empty")
        return v


class UserLogin(BaseModel):
    username: str = Field(..., min_length=1, max_length=254)   # username or email
    password: str = Field(..., min_length=1, max_length=200)


class UserRegister(BaseModel):
    username: str
    email   : EmailStr
    password: str = Field(..., max_length=200)

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", v or ""):
            raise ValueError("Usernames are 3 to 32 characters: letters, numbers, dots, dashes or underscores")
        return v


class EmailBody(BaseModel):
    email: EmailStr


class WaitlistEntry(BaseModel):
    email: EmailStr
    name : Optional[str] = Field(None, max_length=100)


class PasswordResetConfirm(BaseModel):
    token       : str = Field(..., max_length=200)
    new_password: str = Field(..., max_length=200)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., max_length=200)
    new_password    : str = Field(..., max_length=200)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., max_length=300)


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = Field(None, max_length=300)
    everywhere   : bool = False


class TokenBody(BaseModel):
    token: str = Field(..., max_length=200)


class DeleteAccountRequest(BaseModel):
    password: str = Field(..., max_length=200)


class CheckoutRequest(BaseModel):
    plan : str = Field(..., max_length=40)
    email: Optional[str] = None      # ignored: the account email is used


class ApiKeyCreate(BaseModel):
    name: Optional[str] = Field("", max_length=60)


class WebhookBody(BaseModel):
    url: Optional[str] = Field(None, max_length=2048)


class TargetCreate(TargetConfig):
    name: str = Field(..., min_length=1, max_length=120)


class TargetUpdate(BaseModel):
    name             : Optional[str] = Field(None, min_length=1, max_length=120)
    target_type      : Optional[TargetType] = None
    system_prompt    : Optional[str] = Field(None, max_length=20000)
    api_url          : Optional[str] = Field(None, max_length=2048)
    api_key          : Optional[str] = Field(None, max_length=1000)
    clear_api_key    : bool = False
    model            : Optional[ModelName] = None
    baseline_question: Optional[str] = Field(None, max_length=1000)
    input_field      : Optional[FieldName] = None
    output_field     : Optional[FieldName] = None


class ScheduleCreate(BaseModel):
    target_id : str = Field(..., max_length=64)
    frequency : Literal["daily", "weekly"] = "weekly"
    categories: Optional[List[str]] = Field(None, max_length=50)
    alert_drop: int = Field(5, ge=1, le=100)


class ScheduleUpdate(BaseModel):
    frequency : Optional[Literal["daily", "weekly"]] = None
    categories: Optional[List[str]] = Field(None, max_length=50)
    alert_drop: Optional[int] = Field(None, ge=1, le=100)
    enabled   : Optional[bool] = None


class PromptCreate(BaseModel):
    category: Slug
    prompt  : str = Field(..., min_length=1, max_length=2000)


class ShareRequest(BaseModel):
    days: int = Field(7, ge=1, le=30)


class RemediateRequest(BaseModel):
    system_prompt: Optional[str] = Field(None, max_length=20000)


class RetestRequest(BaseModel):
    system_prompt: Optional[str] = Field(None, max_length=20000)
    api_key      : Optional[str] = Field(None, max_length=1000)


class FirewallInput(BaseModel):
    text     : str = Field(..., min_length=1, max_length=20000)
    threshold: float = Field(0.8, ge=0.05, le=0.99)


class FirewallOutput(BaseModel):
    text         : str = Field(..., min_length=1, max_length=50000)
    system_prompt: Optional[str] = Field(None, max_length=20000)
    canary       : Optional[str] = Field(None, min_length=6, max_length=100)


# ── Info ──────────────────────────────────────────────────────
@app.get("/")
def home():
    """API name, version and a link to the interactive docs."""
    return {"name": "LLM Scanner API", "version": VERSION, "status": "online", "docs": "/docs"}


@app.get("/health")
def health_check():
    """Liveness check, plus whether storage, email and billing are configured."""
    return {
        "status"      : "healthy",
        "version"     : VERSION,
        "environment" : config.ENV,
        "timestamp"   : datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "active_scans": scan_db.count_running_scans(),
        "storage"     : _storage_state(),
        "email"       : email_service.enabled(),
        "billing"     : payment.billing_enabled(),
    }


@app.get("/categories")
def list_categories():
    """The built-in attack categories, with what they test and their OWASP mapping."""
    return {"categories": [
        {"id": cat, "title": catalog.info(cat)["title"], "tests": catalog.info(cat)["tests"],
         "owasp": catalog.owasp_labels(cat), "attacks": len(prompts)}
        for cat, prompts in ATTACK_PROMPTS.items()
    ], "total_attacks": sum(len(p) for p in ATTACK_PROMPTS.values())}


@app.get("/models")
def list_models(user: dict = Depends(require_user)):
    """Groq models this server can use for simulated and Groq targets, and the defaults in use."""
    models = groq_models.available(config.GROQ_API_KEY)
    return {"default_target": groq_models.default_model(), "judge": groq_models.judge_model(),
            "groq": sorted(models) if models else []}


# ── Auth ──────────────────────────────────────────────────────
_DUMMY_HASH = auth_db._hash("timing-equalizer")


@app.post("/auth/register")
@limiter.limit("5/minute")
def register(request: Request, body: UserRegister):
    """Creates an account and returns tokens. Sends a confirmation email when email is set up."""
    _check_new_password(body.password)
    # Without email delivery nobody could confirm, so accounts start confirmed.
    result = auth_db.create_user(body.username, body.email, body.password,
                                 verified=not email_service.enabled())
    if not result["success"]:
        raise HTTPException(status_code=400, detail=result["error"])
    user = auth_db.get_user_by_id(result["user_id"])
    if email_service.enabled():
        email_service.send_verification(user["email"], auth_db.create_verify_token(user["id"]))
    return _token_response(user)


@app.post("/auth/login")
@limiter.limit("10/minute")
def login(request: Request, body: UserLogin):
    """Log in with a username or email. Returns an access token and a refresh token."""
    user = auth_db.get_user_for_login(body.username)
    if not user:
        auth_db.verify_password(body.password, _DUMMY_HASH)      # same timing as a wrong password
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not auth_db.verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if auth_db.needs_rehash(user["hashed_password"]):
        auth_db.upgrade_password(user["id"], auth_db._hash(body.password))
    return _token_response(user)


@app.post("/auth/refresh")
@limiter.limit("30/minute")
def refresh_token(request: Request, body: RefreshRequest):
    """Swaps a refresh token for a new access token and a new refresh token."""
    user_id = auth_db.consume_refresh_token(body.refresh_token)
    user = auth_db.get_user_by_id(user_id) if user_id else None
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    return _token_response(user)


@app.post("/auth/logout")
def logout(request: Request, body: LogoutRequest):
    """Revokes a refresh token; with everywhere=true, ends every session of the caller."""
    if body.refresh_token:
        auth_db.revoke_refresh_token(body.refresh_token)
    if body.everywhere:
        user = require_user(request)
        auth_db.revoke_all_sessions(user["id"])
    return {"message": "Logged out"}


@app.get("/auth/me")
def get_me(user: dict = Depends(require_user)):
    """The signed-in user's profile, plan and usage."""
    return _public_user(user)


@app.post("/auth/forgot-password")
@limiter.limit("3/minute")
def forgot_password(request: Request, body: EmailBody):
    """Emails a password reset link (always answers the same, to avoid revealing accounts)."""
    if not email_service.enabled():
        raise HTTPException(status_code=503, detail="Password reset by email isn't set up on this server. "
                                                    "Ask the administrator to reset your password.")
    token = auth_db.create_reset_token(body.email)
    if token:
        email_service.send_password_reset(body.email, token)
    return {"message": "If that email exists, a reset link has been sent."}


@app.post("/auth/reset-password")
@limiter.limit("10/minute")
def reset_password(request: Request, body: PasswordResetConfirm):
    """Sets a new password with a reset token and signs out every session."""
    _check_new_password(body.new_password)
    if not auth_db.consume_reset_token(body.token, body.new_password):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")
    return {"message": "Password reset successfully. Please log in again."}


@app.put("/auth/password")
@limiter.limit("10/minute")
def change_password(request: Request, body: PasswordChangeRequest, user: dict = Depends(require_user)):
    """Changes the password, signs out every other session, and returns fresh tokens."""
    _check_new_password(body.new_password)
    if not auth_db.verify_password(body.current_password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    auth_db.set_password(user["id"], body.new_password)
    return {"message": "Password updated successfully", **_token_response(auth_db.get_user_by_id(user["id"]))}


@app.post("/auth/verify-email")
@limiter.limit("10/minute")
def verify_email(request: Request, body: TokenBody):
    """Confirms an email address with the token from the confirmation email."""
    if not auth_db.consume_verify_token(body.token):
        raise HTTPException(status_code=400, detail="This confirmation link is invalid or has expired")
    return {"message": "Email confirmed"}


@app.post("/auth/resend-verification")
@limiter.limit("3/minute")
def resend_verification(request: Request, user: dict = Depends(require_user)):
    """Sends a new email confirmation link."""
    if user.get("email_verified"):
        return {"message": "Email already confirmed"}
    if not email_service.enabled():
        raise HTTPException(status_code=503, detail="Email delivery isn't configured on this server")
    email_service.send_verification(user["email"], auth_db.create_verify_token(user["id"]))
    return {"message": "Confirmation email sent"}


@app.get("/auth/me/export")
@limiter.limit("5/minute")
def export_account(request: Request, user: dict = Depends(require_user)):
    """Everything we store about you, as JSON (GDPR data portability)."""
    scans = []
    for scan_id in scan_db.user_scan_ids(user["id"]):
        scan = scan_db.get_scan(scan_id)
        if scan:
            scans.append(scan_db.public_scan(scan, include_results=True))
    return {
        "exported_at"   : datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile"       : _public_user(user),
        "api_keys"      : auth_db.list_api_keys(user["id"]),
        "saved_targets" : store.list_targets(user["id"]),
        "schedules"     : store.list_schedules(user["id"]),
        "custom_prompts": store.list_prompts(user["id"]),
        "scans"         : scans,
    }


@app.delete("/auth/me")
@limiter.limit("3/minute")
def delete_account(request: Request, body: DeleteAccountRequest, user: dict = Depends(require_user)):
    """Deletes the account, its scans and report files. Cancels any subscription."""
    if not auth_db.verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Password is incorrect")
    payment.cancel_subscription(user.get("stripe_subscription_id"))
    for scan_id in scan_db.user_scan_ids(user["id"]):
        _delete_scan_everything(scan_db.get_scan(scan_id))
    auth_db.delete_user(user["id"])
    log.info("Account %s deleted", user["id"])
    return {"message": "Your account and all its data have been deleted"}


# ── Scans ─────────────────────────────────────────────────────
def _get_owned_scan(scan_id: str, user: dict) -> dict:
    """404 (not 403) when missing OR owned by someone else, so existence isn't leaked."""
    scan = scan_db.get_scan(scan_id)
    if not scan or scan.get("user_id") != user["id"]:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


def _get_complete_scan(scan_id: str, user: dict) -> dict:
    scan = _get_owned_scan(scan_id, user)
    if scan["status"] != "complete":
        raise HTTPException(status_code=400, detail="Scan not complete yet")
    return scan


def _report_data(scan: dict) -> dict:
    if scan.get("results"):
        return scan["results"]
    path = scan.get("json_path")
    if path and os.path.exists(path):
        return report.load(path)
    raise HTTPException(status_code=404, detail="Results not found")


@app.post("/scan")
@limiter.limit("20/minute")
def start_scan(request: Request, body: ScanRequest, user: dict = Depends(require_user)):
    """Queues a scan. Poll GET /scan/{id} for progress."""
    cfg, api_key, target_id = body.target_config(), body.api_key, None
    if body.target_id:
        saved = store.get_target(user["id"], body.target_id, with_key=True)
        if not saved:
            raise HTTPException(status_code=404, detail="Saved target not found")
        cfg, api_key, target_id = dict(saved["config"]), saved.get("api_key"), saved["id"]
    if body.categories:
        cfg["categories"] = body.categories
    try:
        scan_id = services.queue_scan(user, cfg, api_key, target_name=body.target_name,
                                      target_id=target_id,
                                      include_custom_prompts=body.include_custom_prompts)
    except services.ScanRejected as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    return {"scan_id": scan_id, "status": "pending", "target_name": body.target_name,
            "message": f"Scan started for {body.target_name}"}


@app.get("/scan/compare/{base_id}/{head_id}")
def compare_scans(base_id: str, head_id: str, user: dict = Depends(require_user)):
    """What got worse or better between two finished scans."""
    base = _get_complete_scan(base_id, user)
    head = _get_complete_scan(head_id, user)
    diff = analysis.diff_findings(_report_data(base).get("results", []), _report_data(head).get("results", []))
    return {
        "base": {"scan_id": base_id, "security_score": base.get("security_score", 0),
                 "grade": base.get("grade"), "created_at": base.get("created_at")},
        "head": {"scan_id": head_id, "security_score": head.get("security_score", 0),
                 "grade": head.get("grade"), "created_at": head.get("created_at")},
        "score_delta"        : (head.get("security_score") or 0) - (base.get("security_score") or 0),
        "introduced_count"   : len(diff["introduced"]),
        "resolved_count"     : len(diff["resolved"]),
        "introduced_findings": diff["introduced"],
        "resolved_findings"  : diff["resolved"],
    }


@app.get("/scan/{scan_id}")
def get_scan_status(scan_id: str, user: dict = Depends(require_user)):
    """Status and progress; includes the findings once the scan is complete."""
    scan = _get_owned_scan(scan_id, user)
    out = scan_db.public_scan(scan, include_results=scan["status"] == "complete")
    if scan["status"] == "complete" and scan.get("results"):
        out["recommendations"] = report.recommendations(scan["results"].get("results", []))
    return out


@app.post("/scan/{scan_id}/cancel")
def cancel_scan(scan_id: str, user: dict = Depends(require_user)):
    """Stops a queued or running scan."""
    scan = _get_owned_scan(scan_id, user)
    if scan["status"] not in ("pending", "running"):
        raise HTTPException(status_code=400, detail=f"Scan is already {scan['status']}")
    runner.cancel(scan_id)
    return {"message": "Cancelling scan", "scan_id": scan_id}


@app.get("/scans")
@limiter.limit("120/minute")
def list_all_scans(request: Request, user: dict = Depends(require_user),
                   limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                   status: Optional[str] = Query(None, max_length=20),
                   target_name: Optional[str] = Query(None, max_length=120)):
    """Your scans, newest first (summary only; findings come from /scan/{id})."""
    scans = scan_db.list_scans(user["id"], limit=limit, offset=offset, status=status, target_name=target_name)
    total = scan_db.count_user_scans(user["id"], status=status) if not target_name else len(scans)
    return {"total": total, "limit": limit, "offset": offset, "scans": scans}


@app.get("/analytics/categories")
def category_analytics(user: dict = Depends(require_user)):
    """Failure rate per attack category across all your finished scans."""
    from db import transaction
    with transaction() as conn:
        rows = conn.execute("""
            SELECT f.category AS category, COUNT(*) AS attacks,
                   SUM(CASE WHEN f.severity NOT IN ('SAFE', 'ERROR') THEN 1 ELSE 0 END) AS failed
            FROM findings f JOIN scans s ON s.scan_id = f.scan_id
            WHERE s.user_id = ? AND s.status = 'complete'
            GROUP BY f.category
        """, (user["id"],)).fetchall()
    out = [{"id": r["category"], "title": catalog.info(r["category"])["title"],
            "owasp": catalog.owasp_labels(r["category"]), "attacks": r["attacks"], "failed": r["failed"] or 0,
            "rate": round((r["failed"] or 0) / r["attacks"], 3) if r["attacks"] else 0} for r in rows]
    out.sort(key=lambda c: (-c["rate"], -c["failed"]))
    return {"categories": out}


@app.get("/results/{scan_id}")
def get_results(scan_id: str, user: dict = Depends(require_user)):
    """The full report data (summary + every finding) of a finished scan."""
    return _report_data(_get_complete_scan(scan_id, user))


def _delete_scan_everything(scan: Optional[dict]) -> None:
    if not scan:
        return
    if scan["status"] in ("pending", "running"):
        runner.cancel(scan["scan_id"])
    paths = {scan.get(k) for k in ("json_path", "pdf_path", "html_path", "md_path")}
    paths |= {os.path.join(config.REPORTS_DIR, f"{scan['scan_id']}.{ext}") for ext in ("json", "pdf", "html", "md")}
    for path in filter(None, paths):
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            log.warning("Couldn't delete %s", path)
    scan_db.delete_scan(scan["scan_id"])


@app.delete("/scan/{scan_id}")
def delete_scan_endpoint(scan_id: str, user: dict = Depends(require_user)):
    """Deletes a scan, its findings and its report files."""
    _delete_scan_everything(_get_owned_scan(scan_id, user))
    return {"message": f"Scan {scan_id} deleted"}


# ── Report downloads (rebuilt from the stored results when the file is gone) ──
_FORMATS = {
    "pdf" : ("pdf_path", "application/pdf"),
    "html": ("html_path", "text/html"),
    "md"  : ("md_path", "text/markdown"),
    "json": ("json_path", "application/json"),
}


def _report_file(scan: dict, fmt: str) -> FileResponse:
    column, media_type = _FORMATS[fmt]
    path = scan.get(column)
    if not path or not os.path.exists(path):
        data = _report_data(scan)
        path = os.path.join(config.REPORTS_DIR, f"{scan['scan_id']}.{fmt}")
        if fmt == "json":
            os.makedirs(config.REPORTS_DIR, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            report.write_one(data, fmt, path, scan["target_name"])
        scan_db.update_scan(scan["scan_id"], **{column: path})
    return FileResponse(path=path, media_type=media_type,
                        filename=f"LLM_Security_Report_{scan['scan_id']}.{fmt}",
                        headers={"Content-Security-Policy": "sandbox"} if fmt == "html" else None)


@app.get("/download/html/{scan_id}")
def download_html(scan_id: str, user: dict = Depends(require_user)):
    """Downloads the HTML report (rebuilt from the stored results if the file is gone)."""
    return _report_file(_get_complete_scan(scan_id, user), "html")


@app.get("/download/md/{scan_id}")
def download_markdown(scan_id: str, user: dict = Depends(require_user)):
    """Downloads the Markdown report."""
    return _report_file(_get_complete_scan(scan_id, user), "md")


@app.get("/download/json/{scan_id}")
def download_json(scan_id: str, user: dict = Depends(require_user)):
    """Downloads the raw results as JSON."""
    return _report_file(_get_complete_scan(scan_id, user), "json")


@app.get("/download/{scan_id}")
def download_pdf(scan_id: str, user: dict = Depends(require_user)):
    """Downloads the PDF report."""
    return _report_file(_get_complete_scan(scan_id, user), "pdf")


# ── Share links (read-only, expiring) ─────────────────────────
@app.post("/scan/{scan_id}/share")
def share_scan(scan_id: str, body: Optional[ShareRequest] = None, user: dict = Depends(require_user)):
    """Creates a read-only link to a finished scan that expires after `days` (default 7)."""
    body = body or ShareRequest()
    _get_complete_scan(scan_id, user)
    link = store.create_share(user["id"], scan_id, body.days)
    return {"url": f"{config.APP_URL}/shared/{link['token']}", "token": link["token"],
            "expires_at": link["expires_at"]}


@app.delete("/scan/{scan_id}/share")
def unshare_scan(scan_id: str, user: dict = Depends(require_user)):
    """Disables the scan's share link."""
    _get_owned_scan(scan_id, user)
    store.revoke_share(user["id"], scan_id)
    return {"message": "Share link removed"}


@app.get("/shared/{token}")
@limiter.limit("60/minute")
def view_shared(request: Request, token: str):
    """A shared report: findings and summary only, never the target's configuration."""
    scan_id = store.resolve_share(token[:100])
    scan = scan_db.get_scan(scan_id) if scan_id else None
    if not scan or scan["status"] != "complete":
        raise HTTPException(status_code=404, detail="This link is invalid or has expired")
    data = _report_data(scan)
    keep = ("category", "attack", "response", "score", "severity", "reason", "owasp")
    return {
        "target_name"    : scan["target_name"],
        "scan_date"      : data.get("scan_date"),
        "summary"        : scoring.ensure_summary(data),
        "recommendations": report.recommendations(data.get("results", [])),
        "results"        : [{k: r.get(k) for k in keep} for r in data.get("results", [])],
    }


# ── Fix it: hardened prompt and re-test ───────────────────────
_RETEST_KEEP = ("target_type", "system_prompt", "api_url", "model", "baseline_question", "input_field", "output_field")


def _scan_config(scan: dict) -> dict:
    try:
        return json.loads(scan.get("config_json") or "{}")
    except ValueError:
        return {}


@app.post("/scan/{scan_id}/remediate")
@limiter.limit("10/minute")
def remediate_scan(request: Request, scan_id: str, body: RemediateRequest, user: dict = Depends(require_user)):
    """Suggests a hardened system prompt based on the attacks that succeeded in this scan."""
    scan = _get_complete_scan(scan_id, user)
    cfg = _scan_config(scan)
    prompt = body.system_prompt or cfg.get("system_prompt")
    if not prompt and (cfg.get("target_type") or scan["target_type"]) == "simulation":
        prompt = runner.DEFAULT_SYSTEM_PROMPT
    if not prompt:
        raise HTTPException(status_code=400, detail="Paste your system prompt: it wasn't stored with this scan")
    try:
        return remediation.suggest(prompt, _report_data(scan).get("results", []))
    except remediation.ProviderError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except remediation.RemediationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/scan/{scan_id}/retest")
@limiter.limit("10/minute")
def retest_scan(request: Request, scan_id: str, body: RetestRequest, user: dict = Depends(require_user)):
    """Runs only the attacks that failed in this scan again, optionally with a new system prompt."""
    scan = _get_complete_scan(scan_id, user)
    failures = remediation.failed_findings(_report_data(scan).get("results", []))
    if not failures:
        raise HTTPException(status_code=400, detail="Nothing failed in this scan, so there is nothing to re-test")
    cfg = {k: v for k, v in _scan_config(scan).items() if k in _RETEST_KEEP}
    cfg.setdefault("target_type", scan["target_type"])
    if body.system_prompt:
        cfg["system_prompt"] = body.system_prompt
    api_key = body.api_key
    if not api_key and scan.get("target_id"):
        saved = store.get_target(user["id"], scan["target_id"], with_key=True)
        api_key = saved.get("api_key") if saved else None
    if not api_key and cfg["target_type"] in ("groq", "openai_compatible"):
        raise HTTPException(status_code=400, detail="Enter the target's API key to re-test it")
    cfg["attacks"] = [[f["category"], f["attack"]] for f in failures]
    try:
        new_id = services.queue_scan(user, cfg, api_key, target_name=scan["target_name"],
                                     target_id=scan.get("target_id"), include_custom_prompts=False)
    except services.ScanRejected as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    return {"scan_id": new_id, "attacks": len(failures), "status": "pending"}


# ── Runtime AI firewall ───────────────────────────────────────
@app.get("/api/firewall/usage")
def firewall_usage(user: dict = Depends(require_user)):
    """Firewall checks used today (UTC) and your plan's daily allowance."""
    return services.firewall_usage(user)


@app.post("/api/firewall/check")
@limiter.limit("300/minute")
def firewall_check(request: Request, body: FirewallInput, user: dict = Depends(require_user)):
    """Screens a user message before it reaches your model: allow, review or block, with reasons.
    Every started 2,000 characters count as one check against your plan's daily allowance."""
    try:
        usage = services.use_firewall(user, firewall.units(body.text))
    except services.FirewallRejected as e:
        raise HTTPException(status_code=e.status, detail=e.message)
    return {**firewall.check_input(body.text, threshold=body.threshold), "usage": usage}


@app.post("/api/firewall/check-output")
@limiter.limit("600/minute")
def firewall_check_output(request: Request, body: FirewallOutput, user: dict = Depends(require_user)):
    """Screens a model reply before it reaches the user: flags and masks leaked secrets, the canary
    and copies of the system prompt. Free of charge on plans that include the firewall."""
    if not payment.firewall_limit(user.get("plan", "free")):
        raise HTTPException(status_code=402, detail="The AI firewall isn't included in your plan. Upgrade to use it.")
    return firewall.check_output(body.text, body.system_prompt, body.canary)


# ── Target connection test ────────────────────────────────────
@app.post("/targets/test")
@limiter.limit("10/minute")
def test_target(request: Request, body: TargetConfig, user: dict = Depends(require_user)):
    """Sends one harmless question to a target and reports what happened."""
    if body.target_type in ("openai_compatible", "custom_rest") and not body.api_url:
        raise HTTPException(status_code=400, detail="This target type needs an API URL")
    if body.api_url:
        try:
            netguard.check_url(body.api_url)
        except netguard.UnsafeURLError as e:
            raise HTTPException(status_code=400, detail=f"Target URL rejected: {e}")
    cfg = body.target_config()
    target = Target(body.target_type, api_key=body.api_key, **{k: v for k, v in cfg.items() if k != "target_type"})
    start = time.time()
    try:
        reply = target.get_baseline(body.baseline_question or DEFAULT_BASELINE_QUESTION)
    except Exception as e:
        return {"ok": False, "error": runner._friendly(e, body.target_type), "latency_ms": round((time.time() - start) * 1000)}
    return {"ok": True, "latency_ms": round((time.time() - start) * 1000), "reply_preview": (reply or "")[:300]}


# ── Saved targets ─────────────────────────────────────────────
def _check_target_url(url: Optional[str]) -> None:
    if url:
        try:
            netguard.check_url(url)
        except netguard.UnsafeURLError as e:
            raise HTTPException(status_code=400, detail=f"Target URL rejected: {e}")


@app.get("/api/targets")
def list_targets(user: dict = Depends(require_user)):
    """Your saved targets (their API keys are never returned)."""
    return {"targets": store.list_targets(user["id"])}


@app.post("/api/targets")
def create_target(body: TargetCreate, user: dict = Depends(require_user)):
    """Saves a target; its API key is stored encrypted."""
    _check_target_url(body.api_url)
    if len(store.list_targets(user["id"])) >= 50:
        raise HTTPException(status_code=400, detail="You can save up to 50 targets")
    return store.create_target(user["id"], body.name.strip(), body.target_config(), body.api_key)


@app.put("/api/targets/{target_id}")
def update_target(target_id: str, body: TargetUpdate, user: dict = Depends(require_user)):
    """Changes a saved target. Send clear_api_key=true to remove its key."""
    current = store.get_target(user["id"], target_id)
    if not current:
        raise HTTPException(status_code=404, detail="Saved target not found")
    _check_target_url(body.api_url)
    changes = body.model_dump(exclude={"name", "api_key", "clear_api_key"}, exclude_none=True)
    cfg = {**current["config"], **changes} if changes else None
    api_key = "" if body.clear_api_key else body.api_key
    return store.update_target(user["id"], target_id, name=body.name, cfg=cfg, api_key=api_key)


@app.delete("/api/targets/{target_id}")
def delete_target(target_id: str, user: dict = Depends(require_user)):
    """Deletes a saved target and its schedule."""
    if not store.delete_target(user["id"], target_id):
        raise HTTPException(status_code=404, detail="Saved target not found")
    return {"message": "Target deleted"}


# ── Scheduled scans ───────────────────────────────────────────
def _require_paid(user: dict, feature: str) -> None:
    if user.get("plan", "free") == "free":
        raise HTTPException(status_code=402, detail=f"{feature} need a Pro or Enterprise plan")


def _check_categories(categories: Optional[List[str]]) -> None:
    unknown = [c for c in categories or [] if c not in ATTACK_PROMPTS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown attack categories: {', '.join(unknown)}")


@app.get("/api/schedules")
def list_schedules(user: dict = Depends(require_user)):
    """Your scheduled scans."""
    return {"schedules": store.list_schedules(user["id"])}


@app.post("/api/schedules")
def create_schedule(body: ScheduleCreate, user: dict = Depends(require_user)):
    """Schedules daily or weekly scans of a saved target (Pro and Enterprise)."""
    _require_paid(user, "Scheduled scans")
    if not store.get_target(user["id"], body.target_id):
        raise HTTPException(status_code=404, detail="Saved target not found")
    _check_categories(body.categories)
    return store.create_schedule(user["id"], body.target_id, body.frequency, body.categories, body.alert_drop)


@app.put("/api/schedules/{schedule_id}")
def update_schedule(schedule_id: str, body: ScheduleUpdate, user: dict = Depends(require_user)):
    """Changes, pauses or resumes a schedule."""
    if not store.get_schedule(user["id"], schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    if body.enabled:
        _require_paid(user, "Scheduled scans")
    _check_categories(body.categories)
    return store.update_schedule(user["id"], schedule_id, **body.model_dump(exclude_none=True))


@app.delete("/api/schedules/{schedule_id}")
def delete_schedule(schedule_id: str, user: dict = Depends(require_user)):
    """Deletes a schedule."""
    if not store.delete_schedule(user["id"], schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"message": "Schedule deleted"}


# ── Custom attack prompts ─────────────────────────────────────
@app.get("/api/prompts")
def list_prompts(user: dict = Depends(require_user)):
    """Your custom attack prompts."""
    return {"prompts": store.list_prompts(user["id"]), "limit": store.MAX_PROMPTS}


@app.post("/api/prompts")
def add_prompt(body: PromptCreate, user: dict = Depends(require_user)):
    """Adds a custom attack prompt; it runs with your future scans."""
    created = store.add_prompt(user["id"], body.category, body.prompt.strip())
    if not created:
        raise HTTPException(status_code=400, detail=f"You can save up to {store.MAX_PROMPTS} custom prompts")
    return created


@app.delete("/api/prompts/{prompt_id}")
def delete_prompt(prompt_id: str, user: dict = Depends(require_user)):
    """Deletes a custom attack prompt."""
    if not store.delete_prompt(user["id"], prompt_id):
        raise HTTPException(status_code=404, detail="Prompt not found")
    return {"message": "Prompt deleted"}


# ── API keys (programmatic / CI access) ───────────────────────
@app.post("/api/keys")
def create_api_key_endpoint(body: ApiKeyCreate, user: dict = Depends(require_user)):
    """Creates an API key. The full key is returned ONCE: store it now."""
    if sum(1 for k in auth_db.list_api_keys(user["id"]) if not k["revoked"]) >= 20:
        raise HTTPException(status_code=400, detail="You can have up to 20 active API keys")
    return auth_db.create_api_key(user["id"], body.name or "API key")


@app.get("/api/keys")
def list_api_keys_endpoint(user: dict = Depends(require_user)):
    """Lists your API keys (prefix only, never the full secret)."""
    return {"keys": auth_db.list_api_keys(user["id"])}


@app.delete("/api/keys/{key_id}")
def revoke_api_key_endpoint(key_id: str, user: dict = Depends(require_user)):
    """Revokes an API key immediately."""
    if not auth_db.revoke_api_key(user["id"], key_id):
        raise HTTPException(status_code=404, detail="API key not found")
    return {"message": "API key revoked"}


# ── Notification webhook ──────────────────────────────────────
@app.get("/api/webhook")
def get_webhook(user: dict = Depends(require_user)):
    """Your webhook URL and whether a signing secret exists."""
    return {"webhook_url": user.get("webhook_url"), "has_secret": bool(user.get("webhook_secret"))}


@app.put("/api/webhook")
def set_webhook(body: WebhookBody, user: dict = Depends(require_user)):
    """Sets (or clears, with null) the URL we POST scan events to. Returns the signing
    secret the first time one is created."""
    if body.url:
        try:
            netguard.check_url(body.url)
        except netguard.UnsafeURLError as e:
            raise HTTPException(status_code=400, detail=f"Webhook URL rejected: {e}")
    had_secret = bool(user.get("webhook_secret"))
    secret = auth_db.update_webhook(user["id"], body.url or None)
    out = {"message": "Webhook updated", "webhook_url": body.url or None}
    if body.url and not had_secret:
        out["secret"] = secret
    return out


@app.post("/api/webhook/rotate")
def rotate_webhook_secret(user: dict = Depends(require_user)):
    """Creates a new webhook signing secret (the old one stops working)."""
    return {"secret": auth_db.rotate_webhook_secret(user["id"])}


@app.post("/api/webhook/test")
@limiter.limit("5/minute")
def test_webhook(request: Request, user: dict = Depends(require_user)):
    """Sends a test `ping` event to your webhook."""
    if not user.get("webhook_url"):
        raise HTTPException(status_code=400, detail="Set a webhook URL first")
    ok = notifications.send_webhook(user, "ping", {"message": "Test event from LLM Scanner"})
    return {"delivered": ok}


# ── Waitlist ──────────────────────────────────────────────────
# There is deliberately NO endpoint that lists waitlist entries: the list holds
# personal data. Read it on the server with `python backend/database.py waitlist`.
@app.post("/api/waitlist")
@limiter.limit("5/minute")
def join_waitlist(request: Request, entry: WaitlistEntry):
    """Adds an email to the waitlist and sends one welcome email."""
    if database.add_to_waitlist(str(entry.email), (entry.name or "").strip() or None):
        email_service.send_waitlist_welcome(str(entry.email))
    # Same answer either way: don't reveal who is already on the list.
    return {"success": True, "message": "Added to waitlist"}


@app.get("/api/waitlist/count")
def waitlist_count():
    """How many people joined the waitlist."""
    return {"count": len(database.get_waitlist())}


# ── Payments (Stripe) ─────────────────────────────────────────
@app.get("/api/plans")
def list_plans():
    """Plans with prices, scan limits and features."""
    return {"plans": payment.get_plans_public(), "billing_enabled": payment.billing_enabled()}


@app.post("/api/checkout")
@limiter.limit("10/minute")
def checkout(request: Request, body: CheckoutRequest, user: dict = Depends(require_user)):
    """Creates a Stripe Checkout session for the signed-in user."""
    result = payment.create_checkout_session(body.plan, user)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/billing/portal")
def billing_portal(user: dict = Depends(require_user)):
    """A link to Stripe's portal to update cards, see invoices or cancel."""
    result = payment.create_portal_session(user)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/stripe-webhook")
async def stripe_webhook(request: Request):
    """Stripe events: checkout completed, subscription changed or cancelled, payment failed."""
    payload = await request.body()
    event = payment.handle_webhook(payload, request.headers.get("stripe-signature", ""))
    if "error" in event:
        raise HTTPException(status_code=400, detail=event["error"])

    try:
        _apply_stripe_event(event)
    except Exception:
        payment.forget_event(event.get("event_id", ""))     # let Stripe's retry be processed
        raise
    return {"received": True}


def _apply_stripe_event(event: dict) -> None:
    user = auth_db.get_user_by_id(event.get("user_id")) if event.get("user_id") else None
    if not user and event.get("customer_id"):
        user = auth_db.get_user_by_stripe_customer(event["customer_id"])
    if not user:
        if event.get("type") != "duplicate" and event.get("handled", True):
            log.warning("Stripe event %s matched no user", event.get("type"))
        return
    ended = event.get("ended_subscription")
    current = user.get("stripe_subscription_id")
    if ended and current and ended != current:
        log.info("Ignoring end of old subscription %s for user %s", ended, user["id"])
        return
    auth_db.set_stripe_ids(user["id"], event.get("customer_id"), event.get("subscription_id"))
    if event.get("plan"):
        auth_db.update_plan(user["id"], event["plan"])
        log.info("User %s plan set to %s (%s)", user["id"], event["plan"], event["type"])
    if event.get("payment_failed") and user.get("email"):
        email_service.send_payment_failed(user["email"])
