import sys
sys.stdout.reconfigure(encoding='utf-8')

import os
import json
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional, List
from pydantic import BaseModel


# ── Version Config ────────────────────────────────────────────
API_VERSIONS = {
    "v1": {
        "version"    : "1.0.0",
        "status"     : "deprecated",
        "sunset_date": "2027-01-01",
        "description": "Legacy API — migrate to v2",
        "features"   : [
            "basic_scan",
            "pdf_report",
            "scan_status"
        ]
    },
    "v2": {
        "version"    : "2.0.0",
        "status"     : "stable",
        "sunset_date": None,
        "description": "Current stable API",
        "features"   : [
            "basic_scan",
            "deep_scan",
            "pdf_report",
            "html_report",
            "markdown_report",
            "websocket",
            "jwt_auth",
            "rate_limiting",
            "gzip",
            "scan_comparison",
            "auto_discovery"
        ]
    },
    "v3": {
        "version"    : "3.0.0",
        "status"     : "beta",
        "sunset_date": None,
        "description": "Beta API with enterprise features",
        "features"   : [
            "basic_scan",
            "deep_scan",
            "pdf_report",
            "html_report",
            "markdown_report",
            "websocket",
            "jwt_auth",
            "rate_limiting",
            "gzip",
            "scan_comparison",
            "auto_discovery",
            "multi_tenant",
            "rbac",
            "webhooks",
            "scheduling",
            "custom_branding",
            "async_scan",
            "queue_system"
        ]
    }
}

CURRENT_VERSION = "v2"
LATEST_VERSION  = "v3"


# ── Version Router ────────────────────────────────────────────
class APIVersionRouter:
    """
    Routes API requests to the correct version handler.
    Adds deprecation warnings to old version responses.
    """

    def __init__(self, app: FastAPI):
        self.app = app

    def add_version_middleware(self):
        """Adds version checking middleware to FastAPI app."""

        @self.app.middleware("http")
        async def version_middleware(request: Request, call_next):
            # Extract version from URL path
            path    = request.url.path
            version = None

            for v in API_VERSIONS.keys():
                if f"/api/{v}/" in path or path.startswith(f"/api/{v}"):
                    version = v
                    break

            # Process request
            response = await call_next(request)

            # Add version headers
            if version:
                ver_info = API_VERSIONS[version]
                response.headers["X-API-Version"]  = ver_info["version"]
                response.headers["X-API-Status"]   = ver_info["status"]
                response.headers["X-Latest-Version"] = \
                    API_VERSIONS[LATEST_VERSION]["version"]

                # Add deprecation warning
                if ver_info["status"] == "deprecated":
                    response.headers["Warning"] = (
                        f'299 - "API version {version} is deprecated. '
                        f'Please migrate to {LATEST_VERSION}. '
                        f'Sunset date: {ver_info["sunset_date"]}"'
                    )
                    response.headers["Sunset"]    = ver_info["sunset_date"]
                    response.headers["Link"]      = \
                        f'</api/{LATEST_VERSION}/docs>; rel="successor-version"'

                # Add beta warning
                elif ver_info["status"] == "beta":
                    response.headers["Warning"] = (
                        f'199 - "API version {version} is in beta. '
                        f'Use {CURRENT_VERSION} for production."'
                    )

            return response


# ── Version Models ────────────────────────────────────────────

# V1 Models (simple, legacy)
class ScanRequestV1(BaseModel):
    target_name  : str
    system_prompt: Optional[str] = None


class ScanResponseV1(BaseModel):
    scan_id    : str
    status     : str
    target_name: str


# V2 Models (current)
class ScanRequestV2(BaseModel):
    target_name  : str
    target_type  : str = "simulation"
    system_prompt: Optional[str] = None
    api_url      : Optional[str] = None
    api_key      : Optional[str] = None
    model        : Optional[str] = "llama-3.3-70b-versatile"
    categories   : Optional[List[str]] = None


class ScanResponseV2(BaseModel):
    scan_id    : str
    status     : str
    target_name: str
    api_version: str = "v2"
    features   : List[str] = []


# V3 Models (enterprise)
class ScanRequestV3(BaseModel):
    target_name  : str
    target_type  : str = "simulation"
    system_prompt: Optional[str] = None
    api_url      : Optional[str] = None
    api_key      : Optional[str] = None
    model        : Optional[str] = "llama-3.3-70b-versatile"
    categories   : Optional[List[str]] = None
    profile      : Optional[str] = "standard"
    tenant_id    : Optional[str] = None
    priority     : int = 5
    webhook_url  : Optional[str] = None
    schedule     : Optional[str] = None
    branding     : Optional[dict] = None


class ScanResponseV3(BaseModel):
    scan_id    : str
    status     : str
    target_name: str
    api_version: str = "v3"
    queue_position: Optional[int] = None
    estimated_time: Optional[str] = None
    features   : List[str] = []


# ── Version Checker ───────────────────────────────────────────
class VersionChecker:
    """
    Validates API version and checks feature availability.
    """

    @staticmethod
    def is_valid(version):
        """Checks if version is valid."""
        return version in API_VERSIONS

    @staticmethod
    def is_deprecated(version):
        """Checks if version is deprecated."""
        return API_VERSIONS.get(version, {}).get("status") == "deprecated"

    @staticmethod
    def has_feature(version, feature):
        """Checks if version supports a feature."""
        ver_info = API_VERSIONS.get(version, {})
        return feature in ver_info.get("features", [])

    @staticmethod
    def require_version(min_version):
        """
        Decorator that requires a minimum API version.
        """
        versions_list = list(API_VERSIONS.keys())

        def decorator(func):
            async def wrapper(*args, **kwargs):
                request = kwargs.get("request")
                path    = getattr(request, "url", None)
                if path:
                    path_str = str(path.path)
                    for v in versions_list:
                        if f"/api/{v}" in path_str:
                            current_idx = versions_list.index(v)
                            min_idx     = versions_list.index(min_version)
                            if current_idx < min_idx:
                                raise HTTPException(
                                    status_code=426,
                                    detail={
                                        "error"          : "Upgrade Required",
                                        "message"        : f"This feature requires {min_version} or higher",
                                        "current_version": v,
                                        "minimum_version": min_version,
                                        "upgrade_url"    : f"/api/{min_version}/docs"
                                    }
                                )
                return await func(*args, **kwargs)
            return wrapper
        return decorator


# ── Version Info Endpoints ────────────────────────────────────
def create_versioned_app():
    """
    Creates a FastAPI app with versioned routes.
    """
    app = FastAPI(
        title      ="LLM Scanner API",
        description="AI Security Scanner — Multi-version API",
        version    =API_VERSIONS[CURRENT_VERSION]["version"]
    )

    # ── Global version info ───────────────────────────────────
    @app.get("/api/versions")
    async def get_versions():
        """Returns all available API versions."""
        return {
            "current_version": CURRENT_VERSION,
            "latest_version" : LATEST_VERSION,
            "versions"       : API_VERSIONS
        }

    @app.get("/api/{version}/info")
    async def version_info(version: str):
        """Returns info about a specific API version."""
        if not VersionChecker.is_valid(version):
            raise HTTPException(
                status_code=404,
                detail=f"API version {version} not found"
            )

        ver_info = API_VERSIONS[version]
        return {
            "version"     : version,
            "info"        : ver_info,
            "is_current"  : version == CURRENT_VERSION,
            "is_latest"   : version == LATEST_VERSION,
            "upgrade_to"  : LATEST_VERSION if version != LATEST_VERSION else None,
            "docs_url"    : f"/api/{version}/docs"
        }

    # ── V1 Routes (Legacy) ────────────────────────────────────
    @app.post("/api/v1/scan")
    async def scan_v1(request: Request, scan_request: ScanRequestV1):
        """
        V1 Scan endpoint — Legacy.
        Only supports simulation mode.
        """
        import uuid
        scan_id = str(uuid.uuid4())[:8]

        return {
            "scan_id"    : scan_id,
            "status"     : "started",
            "target_name": scan_request.target_name,
            "_warning"   : "V1 API is deprecated. Please migrate to v2.",
            "_migrate_to": "/api/v2/scan"
        }

    @app.get("/api/v1/scan/{scan_id}")
    async def get_scan_v1(scan_id: str):
        """V1 Get scan status."""
        return {
            "scan_id": scan_id,
            "status" : "complete",
            "_warning": "V1 API is deprecated."
        }

    # ── V2 Routes (Current) ───────────────────────────────────
    @app.post("/api/v2/scan")
    async def scan_v2(request: Request, scan_request: ScanRequestV2):
        """
        V2 Scan endpoint — Current stable.
        Supports all target types and report formats.
        """
        import uuid
        scan_id = str(uuid.uuid4())[:8]

        return {
            "scan_id"    : scan_id,
            "status"     : "started",
            "target_name": scan_request.target_name,
            "target_type": scan_request.target_type,
            "api_version": "v2",
            "features"   : API_VERSIONS["v2"]["features"],
            "links"      : {
                "status"  : f"/api/v2/scan/{scan_id}",
                "download": f"/api/v2/scan/{scan_id}/download",
                "results" : f"/api/v2/scan/{scan_id}/results"
            }
        }

    @app.get("/api/v2/scan/{scan_id}")
    async def get_scan_v2(scan_id: str):
        """V2 Get scan status with full details."""
        return {
            "scan_id"    : scan_id,
            "status"     : "complete",
            "api_version": "v2",
            "links"      : {
                "pdf"     : f"/api/v2/download/{scan_id}/pdf",
                "html"    : f"/api/v2/download/{scan_id}/html",
                "markdown": f"/api/v2/download/{scan_id}/md",
                "results" : f"/api/v2/results/{scan_id}"
            }
        }

    @app.get("/api/v2/scans")
    async def list_scans_v2(
        limit : int = 20,
        offset: int = 0,
        status: Optional[str] = None
    ):
        """V2 List scans with pagination."""
        return {
            "api_version": "v2",
            "total"      : 0,
            "limit"      : limit,
            "offset"     : offset,
            "scans"      : []
        }

    # ── V3 Routes (Beta / Enterprise) ────────────────────────
    @app.post("/api/v3/scan")
    async def scan_v3(request: Request, scan_request: ScanRequestV3):
        """
        V3 Scan endpoint — Beta Enterprise.
        Supports multi-tenant, queue, webhooks, scheduling.
        """
        import uuid
        scan_id  = str(uuid.uuid4())[:8]
        priority = scan_request.priority

        response = {
            "scan_id"       : scan_id,
            "status"        : "queued",
            "target_name"   : scan_request.target_name,
            "api_version"   : "v3",
            "profile"       : scan_request.profile,
            "priority"      : priority,
            "queue_position": priority,
            "estimated_time": "10-15 minutes",
            "features"      : API_VERSIONS["v3"]["features"],
            "links"         : {
                "status"    : f"/api/v3/scan/{scan_id}",
                "queue"     : f"/api/v3/queue/{scan_id}",
                "websocket" : f"/api/v3/ws/{scan_id}",
                "results"   : f"/api/v3/results/{scan_id}"
            }
        }

        # Handle tenant
        if scan_request.tenant_id:
            response["tenant_id"] = scan_request.tenant_id

        # Handle webhook
        if scan_request.webhook_url:
            response["webhook_registered"] = True
            response["webhook_url"]        = scan_request.webhook_url

        # Handle branding
        if scan_request.branding:
            response["branding_applied"] = True

        return response

    @app.get("/api/v3/scan/{scan_id}")
    async def get_scan_v3(scan_id: str):
        """V3 Get scan status with enterprise details."""
        return {
            "scan_id"    : scan_id,
            "status"     : "complete",
            "api_version": "v3",
            "enterprise" : {
                "tenant_id"   : None,
                "webhook_fired": False,
                "branding"    : None,
                "audit_logged": True
            },
            "links": {
                "pdf"           : f"/api/v3/download/{scan_id}/pdf",
                "html"          : f"/api/v3/download/{scan_id}/html",
                "markdown"      : f"/api/v3/download/{scan_id}/md",
                "branded_pdf"   : f"/api/v3/download/{scan_id}/branded",
                "attack_graph"  : f"/api/v3/download/{scan_id}/graph",
                "narrative"     : f"/api/v3/download/{scan_id}/narrative",
                "results"       : f"/api/v3/results/{scan_id}",
                "compare"       : f"/api/v3/compare/{scan_id}"
            }
        }

    @app.get("/api/v3/queue")
    async def get_queue_v3():
        """V3 Queue status — Enterprise feature."""
        return {
            "api_version": "v3",
            "queue"      : {
                "pending" : 0,
                "running" : 0,
                "complete": 0,
                "workers" : 2
            }
        }

    @app.get("/api/v3/tenants")
    async def list_tenants_v3():
        """V3 Tenant list — Enterprise feature."""
        return {
            "api_version": "v3",
            "total"      : 0,
            "tenants"    : []
        }

    # ── Version router middleware ─────────────────────────────
    router = APIVersionRouter(app)
    router.add_version_middleware()

    return app


# ── Migration Guide ───────────────────────────────────────────
MIGRATION_GUIDES = {
    "v1_to_v2": """
# Migrating from V1 to V2

## Breaking Changes
- POST /scan now requires 'target_type' field
- Response includes 'api_version' field
- JWT authentication now required for /scans endpoint

## New Features
- Multiple report formats (PDF, HTML, Markdown)
- WebSocket support
- Rate limiting headers
- Scan comparison

## Quick Migration
# V1
curl -X POST /api/v1/scan -d '{"target_name": "My App"}'

# V2
curl -X POST /api/v2/scan \\
  -H "Authorization: Bearer YOUR_JWT" \\
  -d '{"target_name": "My App", "target_type": "simulation"}'
""",
    "v2_to_v3": """
# Migrating from V2 to V3

## New Features
- Multi-tenant support (add 'tenant_id' to requests)
- Queue system (scans are queued with priority)
- Webhook support (add 'webhook_url' to requests)
- Custom branding (add 'branding' dict to requests)
- Attack graph endpoint
- Narrative report endpoint

## Quick Migration
# V2
curl -X POST /api/v2/scan \\
  -d '{"target_name": "My App", "target_type": "simulation"}'

# V3
curl -X POST /api/v3/scan \\
  -d '{
    "target_name" : "My App",
    "target_type" : "simulation",
    "tenant_id"   : "ten_abc123",
    "priority"    : 3,
    "webhook_url" : "https://your-app.com/webhook",
    "profile"     : "deep"
  }'
"""
}


# ── Print Migration Guide ─────────────────────────────────────
def print_migration_guide(from_ver, to_ver):
    """Prints migration guide between versions."""
    key = f"{from_ver}_to_{to_ver}"
    if key in MIGRATION_GUIDES:
        print(MIGRATION_GUIDES[key])
    else:
        print(f"No migration guide for {from_ver} → {to_ver}")


# ── CLI ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="LLM Scanner — API Versioning"
    )
    subparsers = parser.add_subparsers(dest="command")

    # List versions
    subparsers.add_parser("list")

    # Migration guide
    p_migrate = subparsers.add_parser("migrate")
    p_migrate.add_argument("from_ver", choices=list(API_VERSIONS.keys()))
    p_migrate.add_argument("to_ver",   choices=list(API_VERSIONS.keys()))

    # Run versioned app
    subparsers.add_parser("serve")

    args = parser.parse_args()

    if args.command == "list":
        print("\n  API Versions :")
        print(f"  {'='*50}")
        for ver, info in API_VERSIONS.items():
            current = " ← CURRENT" if ver == CURRENT_VERSION else ""
            latest  = " ← LATEST"  if ver == LATEST_VERSION  else ""
            print(f"\n  {ver.upper()} ({info['version']}) "
                  f"[{info['status'].upper()}]{current}{latest}")
            print(f"    {info['description']}")
            print(f"    Features: {len(info['features'])}")
            if info.get("sunset_date"):
                print(f"    Sunset: {info['sunset_date']}")

    elif args.command == "migrate":
        print_migration_guide(args.from_ver, args.to_ver)

    elif args.command == "serve":
        import uvicorn
        app = create_versioned_app()
        uvicorn.run(app, host="0.0.0.0", port=8001)

    else:
        parser.print_help()
        