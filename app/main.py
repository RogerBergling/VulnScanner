"""FastAPI application entry point."""

from __future__ import annotations

import hmac
import logging
import os
import ssl
import threading
from contextlib import asynccontextmanager
from urllib.parse import quote, urlparse

from fastapi import FastAPI, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .api import router as api_router
from .audit import record_request
from .body_limit import BodySizeLimitMiddleware
from .config import (
    BASE_DIR,
    HOST,
    PORT,
    SATELLITE_HOST,
    SATELLITE_PORT,
    allowed_hosts,
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
from .sessions import (
    CSRF_HEADER,
    authenticate_request,
    cleanup_sessions,
    request_is_secure,
)

logging.basicConfig(
    level=os.getenv("VS_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("vulnscanner")

STATIC_DIR = BASE_DIR / "app" / "static"
AGENT_DIR = BASE_DIR / "agent"
AGENT_DIR.mkdir(parents=True, exist_ok=True)

# Inject the release version into the SPA shell so the sidebar is correct even
# before app.js fetches /api/health. Avoids a second hard-coded version string.
_INDEX_HTML = (STATIC_DIR / "index.html").read_text(encoding="utf-8").replace(
    "{{VERSION}}", __version__
)


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
    # Launchers that use ``uvicorn app.main:app`` never call ``run()``. Start
    # the optional satellite listener here as well; the guard in
    # _start_satellite_listener prevents a second thread when run() already did.
    if SATELLITE_PORT:
        if scheme == "https":
            try:
                from .certs import get_cert_paths

                cert_path, key_path = get_cert_paths()
                _start_satellite_listener(
                    cert_path,
                    key_path,
                    os.getenv("VS_LOG_LEVEL", "info").lower(),
                )
            except Exception:
                logger.exception("Could not start the satellite mTLS listener")
        else:
            logger.warning(
                "VS_SATELLITE_PORT is set but VS_SSL is disabled; the mTLS "
                "satellite listener needs TLS and was not started."
            )
    logger.info("VulnScanner %s starting on %s://%s:%s", __version__, scheme, HOST, PORT)
    logger.info("Database: %s", database_path())
    if HOST not in {"127.0.0.1", "::1", "localhost"} and not os.getenv(
        "VS_ALLOWED_HOSTS", ""
    ).strip():
        logger.warning(
            "VS_ALLOWED_HOSTS is not set while listening on %s. Requests with "
            "Host headers other than loopback/localhost will be rejected; set "
            "VS_ALLOWED_HOSTS to the DNS name(s) clients use.",
            HOST,
        )
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
    _stop_satellite_listener()
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

# Reject oversized bodies before FastAPI/Pydantic parses them. TrustedHost
# protects against Host-header poisoning when the listener is not loopback-only.
app.add_middleware(BodySizeLimitMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts())

_PUBLIC_PREFIXES = (
    "/api/health",
    "/api/agent/",
    "/api/satellite/",
    "/agent/",
    "/static/",
    "/api/auth/login",
    "/api/auth/status",
    "/api/docs",
    "/api/openapi.json",
    "/login",
    "/favicon.ico",
)
_satellite_lock = threading.Lock()
_satellite_thread: threading.Thread | None = None
_satellite_server = None

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Permitted-Cross-Domain-Policies": "none",
}


def _secure_response(
    response: Response, path: str, request: Request | None = None
) -> Response:
    for key, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    if request is not None and request_is_secure(request):
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000"
        )
    if path.startswith("/api/") or path in {"/", "/login"}:
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")
    if path.startswith("/api/") and not path.startswith("/api/docs"):
        # JSON/API responses never need to render active content. The report
        # export endpoint supplies its own style-only policy before this runs.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'none'",
        )
    if not path.startswith("/api/") and not path.startswith("/agent/"):
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "object-src 'none'; frame-src 'none'; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'",
        )
    return response


def _origin_parts(value: str) -> tuple[str, str, int] | None:
    """Return (scheme, hostname, port) for an absolute or scheme-relative URL."""
    try:
        parsed = urlparse(value if "://" in value else "//" + value)
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            return None
        host = (parsed.hostname or "").lower().strip("[]")
        if not host:
            return None
        port = parsed.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def _allowed_origin(parts: tuple[str, str, int]) -> bool:
    """Return True when an allowed host entry covers a candidate origin."""
    scheme, host, port = parts
    for item in allowed_hosts():
        text = item.strip().lower()
        if not text:
            continue
        if text == "*":
            return True
        try:
            parsed = urlparse(text if "://" in text else "//" + text)
            allowed_host = (parsed.hostname or "").lower().strip("[]")
            allowed_port = parsed.port
            allowed_scheme = (parsed.scheme or "").lower() if "://" in text else ""
        except ValueError:
            continue
        if not allowed_host:
            continue
        if allowed_host.startswith("*."):
            suffix = allowed_host[1:]
            if not host.endswith(suffix) or host == allowed_host[2:]:
                continue
        elif allowed_host != host:
            continue
        if allowed_port is not None and allowed_port != port:
            continue
        if allowed_scheme and allowed_scheme != scheme:
            continue
        return True
    return False


def _origin_allowed(request: Request) -> bool:
    """Reject cross-origin state-changing browser requests.

    The CSRF token remains the primary control. Origin/Referer validation is
    defence in depth and also protects the unauthenticated login endpoint.
    CLI/API clients that do not send Origin or Referer continue to work.
    """
    candidate = request.headers.get("origin") or request.headers.get("referer")
    if not candidate:
        return True
    if candidate.strip().lower() == "null":
        return False
    origin = _origin_parts(candidate)
    if origin is None:
        return False

    request_scheme = "https" if request_is_secure(request) else "http"
    request_host_header = request.headers.get("host", "")
    if request_host_header:
        request_origin = _origin_parts(f"{request_scheme}://{request_host_header}")
    else:
        request_host = (request.url.hostname or "").lower().strip("[]")
        request_port = request.url.port or (443 if request_scheme == "https" else 80)
        request_origin = (
            (request_scheme, request_host, request_port) if request_host else None
        )
    if request_origin is None:
        return False
    if origin[1] == request_origin[1]:
        # Same hostname must be an exact scheme/host/port match.
        return origin == request_origin
    return _allowed_origin(origin)


@app.middleware("http")
async def security_and_auth(request: Request, call_next):
    path = request.url.path
    # The dedicated satellite listener is mTLS-only and exposes just the
    # satellite API. Do not serve the UI or management API on that port.
    if SATELLITE_PORT:
        server = request.scope.get("server") or ("", 0)
        try:
            request_port = int(server[1] or 0)
        except (TypeError, ValueError):
            request_port = 0
        if request_port == SATELLITE_PORT and not (
            path.startswith("/api/satellite/") or path == "/api/health"
        ):
            return _secure_response(
                JSONResponse({"detail": "Not found"}, status_code=404),
                path,
                request,
            )
    public = any(path.startswith(prefix) for prefix in _PUBLIC_PREFIXES)
    auth = authenticate_request(request)
    request.state.auth = auth
    request.state.actor = auth.actor

    if request.method.upper() in _UNSAFE_METHODS and not _origin_allowed(request):
        return _secure_response(
            JSONResponse(
                {"detail": "Cross-origin request rejected"},
                status_code=403,
            ),
            path,
            request,
        )

    if not auth.authenticated and not public:
        if auth.metadata.get("rate_limited"):
            retry = int(auth.metadata.get("retry_after") or 1)
            return _secure_response(
                JSONResponse(
                    {"detail": auth.detail, "retry_after": retry},
                    status_code=429,
                    headers={"Retry-After": str(retry)},
                ),
                path,
                request,
            )
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
                request,
            )
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            target = quote(
                path + (("?" + request.url.query) if request.url.query else ""),
                safe="/",
            )
            return _secure_response(
                RedirectResponse(url=f"/login?next={target}", status_code=303),
                path,
                request,
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
            request,
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
                request,
            )

    if path == "/login" and auth.authenticated and auth.method != "disabled":
        return _secure_response(
            RedirectResponse(url="/", status_code=303), path, request
        )

    response = await call_next(request)
    _secure_response(response, path, request)

    if (
        path.startswith("/api/")
        and request.method.upper() in _UNSAFE_METHODS
        and not path.startswith("/api/auth/login")
        and not path.startswith("/api/agent/")
        and not path.startswith("/api/satellite/")
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
def index() -> HTMLResponse:
    return HTMLResponse(_INDEX_HTML)


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


def _start_satellite_listener(
    cert_path: str,
    key_path: str,
    log_level: str,
) -> threading.Thread | None:
    """Start the optional mTLS-only satellite listener exactly once.

    The main listener stays usable by browsers and agents. Satellites can be
    required to connect to a separate port that requests a client certificate
    signed by the internal CA. The same ASGI app is used, but the middleware
    rejects every path except ``/api/satellite/*`` and ``/api/health`` on that
    port.
    """
    global _satellite_server, _satellite_thread

    if not SATELLITE_PORT:
        return None
    if SATELLITE_PORT == PORT:
        logger.error(
            "VS_SATELLITE_PORT must differ from VS_PORT; the mTLS satellite "
            "listener was not started."
        )
        return None
    with _satellite_lock:
        if _satellite_thread is not None and _satellite_thread.is_alive():
            return _satellite_thread

        import uvicorn

        from .certs import satellite_client_ca_path

        ca_path = satellite_client_ca_path()
        config = uvicorn.Config(
            app,
            host=SATELLITE_HOST,
            port=SATELLITE_PORT,
            log_level=log_level,
            lifespan="off",
            ssl_keyfile=key_path,
            ssl_certfile=cert_path,
            ssl_ca_certs=ca_path,
            ssl_cert_reqs=ssl.CERT_REQUIRED,
        )
        server = uvicorn.Server(config)

        def _serve() -> None:
            server.run()

        thread = threading.Thread(
            target=_serve,
            name="vulnscanner-satellite-listener",
            daemon=True,
        )
        _satellite_server = server
        _satellite_thread = thread
        thread.start()
    logger.info(
        "Satellite mTLS listener enabled on https://%s:%s (client CA: %s)",
        SATELLITE_HOST,
        SATELLITE_PORT,
        ca_path,
    )
    return thread


def _stop_satellite_listener() -> None:
    """Ask the optional satellite listener to exit during application shutdown."""
    global _satellite_server, _satellite_thread
    with _satellite_lock:
        server = _satellite_server
        thread = _satellite_thread
        _satellite_server = None
        _satellite_thread = None
    if server is not None:
        server.should_exit = True
    if thread is not None and thread.is_alive():
        thread.join(timeout=5)


def run() -> None:
    import uvicorn

    # Initialize the schema before the optional satellite listener starts; the
    # main lifespan repeats this idempotently.
    init_db()
    ssl_enabled = os.getenv("VS_SSL", "true").lower() in {"1", "true", "yes", "on"}
    log_level = os.getenv("VS_LOG_LEVEL", "info").lower()
    if ssl_enabled:
        from .certs import get_cert_paths

        cert_path, key_path = get_cert_paths()
        logger.info("SSL enabled: cert=%s key=%s", cert_path, key_path)
        _start_satellite_listener(cert_path, key_path, log_level)
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
        if SATELLITE_PORT:
            logger.warning(
                "VS_SATELLITE_PORT is set but VS_SSL is disabled; the mTLS "
                "satellite listener needs TLS and was not started."
            )
        uvicorn.run(app, host=HOST, port=PORT, reload=False, log_level=log_level)


if __name__ == "__main__":
    run()
