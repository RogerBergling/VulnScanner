"""FastAPI application entry point."""

from __future__ import annotations

import base64
import logging
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api import router
from .config import BASE_DIR, HOST, PORT, data_dir
from .database import init_db
from .jobs import shutdown
from .scheduler import start_scheduler, stop_scheduler
from .scans import recover_interrupted_scans

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
    recover_interrupted_scans()
    start_scheduler()
    data_dir()
    admin_password = os.getenv("VS_ADMIN_PASSWORD")
    scheme = "https" if os.getenv("VS_SSL", "true").lower() in {"1", "true", "yes", "on"} else "http"
    logger.info("VulnScanner %s starting on %s://%s:%s", __version__, scheme, HOST, PORT)
    logger.info("Database: %s", data_dir() / "vulnscanner.db")
    if admin_password:
        logger.info("Dashboard Basic Authentication is enabled (user: %s)", os.getenv("VS_ADMIN_USER", "admin"))
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
app.include_router(router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.middleware("http")
async def security_and_auth(request: Request, call_next):
    path = request.url.path
    admin_password = os.getenv("VS_ADMIN_PASSWORD", "")
    public_prefixes = ("/api/health", "/api/agent/", "/agent/", "/static/", "/api/docs", "/api/openapi.json")
    if admin_password and not any(path.startswith(prefix) for prefix in public_prefixes):
        header = request.headers.get("authorization", "")
        authorized = False
        if header.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
                username, password = decoded.split(":", 1)
                expected_user = os.getenv("VS_ADMIN_USER", "admin")
                authorized = secrets.compare_digest(username, expected_user) and secrets.compare_digest(
                    password, admin_password
                )
            except (ValueError, UnicodeDecodeError):
                authorized = False
        if not authorized:
            return Response(
                "Authentication required",
                status_code=401,
                headers={
                    "WWW-Authenticate": 'Basic realm="VulnScanner", charset="UTF-8"',
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                },
            )
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if not path.startswith("/api/") and not path.startswith("/agent/"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
    return response


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


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
