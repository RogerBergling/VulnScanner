"""FastAPI application entry point."""

from __future__ import annotations

import hmac
import logging
import os
from contextlib import asynccontextmanager
from urllib.parse import quote

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api import router as api_router
from .audit import record_request
from .config import (
    BASE_DIR,
    HOST,
    PORT,
    data_dir,
    migrate_env_tool_paths,
    reload_tool_paths,
)
from .database import database_path, init_db
from .jobs import shutdown
from .routes.audit import router as audit_router
from .routes.auth import router as auth_router
from .routes.inventory import router as inventory_router
from .routes.maintenance import router as maintenance_router
from .routes.storage import router as storage_router
from .scheduler import start_scheduler, stop_scheduler
from .scans import recover_interrupted_scans
from .security import (
    admin_auth_enabled,
    admin_user,
    migrate_env_admin_password,
    mfa_enabled,
)
from .sessions import CSRF_HEADER, authenticate_request, cleanup_sessions

logging.basicConfig(
    level=os.getenv("VS_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("vulnscanner")

STATIC_DIR = BASE_DIR / "app" / "static"
AGENT_DIR = BASE_DIR / "agent"
AGENT_DIR.mkdir(parents=True, exist_ok=True)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    migrate_env_admin_password()
    migrate_env_tool_paths()
    reload_tool_paths()
    cleanup_sessions()
    recover_interrupted_scans()
    start_scheduler()
    data_dir()
    scheme = "https" if os.getenv("VS_SSL", "true").lower() in {"1", "true", "yes", "on"} else "http"
    logger.info("VulnScanner %s starting on %s://%s:%s", __version__, scheme, HOST, PORT)
    logger.info("Database: %s", database_path())
    if admin_auth_enabled():
        logger.info(
            "Dashboard authentication is enabled (user: %s, MFA: %s)",
            admin_user(),
            "enabled" if mfa_enabled() else "disabled",
        )
    else:
        if HOST in {"127.0.0.1", "::1", "localhost"}:
            logger.warning(
                "Dashboard authentication is disabled. The listener is bound to %s; "
                "set VS_ADMIN_PASSWORD before exposing the server to a network.",
                HOST,
            )
        else:
            logger.warning(
                "Dashboard authentication is disabled and the listener is bound to %s. "
                "Anyone who can reach this port has full access. Set VS_ADMIN_PASSWORD "
                "or restrict access before using this server on a network.",
                HOST,
            )
    yield
    shutdown(wait=False)
    stop_scheduler()


app = FastAPI(
    title="VulnScanner",
    version=__version__,
    description="Local-first vulnerability scanner and management platform.",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
)
app.include_router(api_router)
app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(inventory_router)
app.include_router(maintenance_router)
app.include_router(storage_router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

_PUBLIC_PREFIXES = (
    "/api/health",
    "/api/agent/",
    "/agent/",
    "/static/",
    "/api/auth/login",
    "/api/auth/status",
    "/api/docs",
    "/api/openapi.json",
    "/login",
    "/favicon.ico",
)
_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def _secure_response(response: Response, path: str) -> Response:
    for key, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    if not path.startswith("/api/") and not path.startswith("/agent/"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
    return response


@app.middleware("http")
async def security_and_auth(request: Request, call_next):
    path = request.url.path
    public = any(path.startswith(prefix) for prefix in _PUBLIC_PREFIXES)
    auth = authenticate_request(request)
    request.state.auth = auth
    request.state.actor = auth.actor

    if not auth.authenticated and not public:
        if path.startswith("/api/"):
            body = {"detail": auth.detail or "Authentication required"}
            body.update(auth.metadata)
            return _secure_response(
                JSONResponse(
                    body,
                    status_code=401,
                    headers={
                        "WWW-Authenticate": 'Basic realm="VulnScanner", charset="UTF-8"'
                    },
                ),
                path,
            )
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            target = quote(
                path + (("?" + request.url.query) if request.url.query else ""),
                safe="/",
            )
            return _secure_response(
                RedirectResponse(url=f"/login?next={target}", status_code=303), path
            )
        return _secure_response(
            Response(
                "Authentication required",
                status_code=401,
                headers={
                    "WWW-Authenticate": 'Basic realm="VulnScanner", charset="UTF-8"'
                },
            ),
            path,
        )

    # Cookie-authenticated browser requests need an explicit CSRF token. API
    # clients using Basic auth are stateless and do not use cookies, so they are
    # not vulnerable to cross-site request forgery.
    if (
        auth.authenticated
        and auth.method == "session"
        and request.method.upper() in _UNSAFE_METHODS
        and not path.startswith("/api/auth/login")
    ):
        supplied = request.headers.get(CSRF_HEADER, "")
        if not supplied or not hmac.compare_digest(supplied, auth.csrf_token):
            return _secure_response(
                JSONResponse(
                    {"detail": "CSRF token missing or invalid. Reload the page and retry."},
                    status_code=403,
                ),
                path,
            )

    if path == "/login" and auth.authenticated and auth.method != "disabled":
        return _secure_response(RedirectResponse(url="/", status_code=303), path)

    response = await call_next(request)
    _secure_response(response, path)

    if (
        path.startswith("/api/")
        and request.method.upper() in _UNSAFE_METHODS
        and not path.startswith("/api/auth/login")
        and not path.startswith("/api/agent/")
    ):
        record_request(
            request,
            f"{request.method.lower()} {path}",
            category="api",
            detail=f"HTTP {response.status_code}",
            outcome="success" if response.status_code < 400 else "failure",
        )
    return response


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/login", include_in_schema=False)
def login_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/manual", include_in_schema=False)
def manual() -> FileResponse:
    """The full manual is also available as a Markdown file in docs/."""
    return FileResponse(
        BASE_DIR / "docs" / "USER_MANUAL.md",
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": "inline; filename=USER_MANUAL.md"},
    )


@app.get("/agent/download/{filename}", include_in_schema=False)
def download_agent(filename: str) -> FileResponse:
    allowed = {
        "vulnscanner_agent.py",
        "VulnScannerAgent.ps1",
        "ad_audit.ps1",
        "install-linux.sh",
        "install-windows.ps1",
        "install-windows-agent.ps1",
    }
    if filename not in allowed:
        return Response("Not found", status_code=404)
    return FileResponse(AGENT_DIR / filename, filename=filename)


# The static mount must be registered after the allow-listed download route,
# otherwise /agent/{path} would shadow /agent/download/{filename}.
app.mount("/agent", StaticFiles(directory=AGENT_DIR), name="agent")


def run() -> None:
    import uvicorn

    ssl_enabled = os.getenv("VS_SSL", "true").lower() in {"1", "true", "yes", "on"}
    log_level = os.getenv("VS_LOG_LEVEL", "info").lower()
    if ssl_enabled:
        from .certs import get_cert_paths

        cert_path, key_path = get_cert_paths()
        logger.info("SSL enabled: cert=%s key=%s", cert_path, key_path)
        uvicorn.run(
            app,
            host=HOST,
            port=PORT,
            reload=False,
            ssl_keyfile=key_path,
            ssl_certfile=cert_path,
            log_level=log_level,
        )
    else:
        uvicorn.run(app, host=HOST, port=PORT, reload=False, log_level=log_level)


if __name__ == "__main__":
    run()
