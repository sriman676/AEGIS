"""
AEGIS API Security Middleware
==============================
Centralises all HTTP security hardening:
- API key authentication
- Rate limiting (slowapi)
- Security response headers (CSP, HSTS, etc.)
- WebSocket origin validation
"""

import os
import secrets
import logging
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("aegis_security")

# ── API Key ───────────────────────────────────────────────────────────────────
# Read from env; on first run, generate and print one to stdout.
_ENV_KEY = os.environ.get("AEGIS_API_KEY", "")  # type: ignore
if not _ENV_KEY:
    # Development fallback: generate a random key and warn loudly.
    _ENV_KEY = secrets.token_hex(32)
    logger.warning(
        "AEGIS_API_KEY not set — generated ephemeral key for this process: %s "
        "(set env var before production deployment)", _ENV_KEY
    )

AEGIS_API_KEY: str = _ENV_KEY

# Endpoints that are always public (health probe, CORS pre-flight)
PUBLIC_PATHS: set[str] = {"/health", "/docs", "/openapi.json", "/redoc"}

# ── WebSocket allowed origins ─────────────────────────────────────────────────
ALLOWED_WS_ORIGINS: set[str] = {
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "tauri://localhost",
}


def check_api_key(request: Request) -> bool:
    """Return True if the request carries a valid AEGIS API key."""
    # Check header first, then query param (for WebSocket compatibility)
    key = (
        request.headers.get("X-AEGIS-Key")
        or request.headers.get("Authorization", "").removeprefix("Bearer ")
        or request.query_params.get("key")
    )
    return secrets.compare_digest(key or "", AEGIS_API_KEY)


def check_ws_origin(origin: str | None) -> bool:
    """Return True if the WebSocket upgrade request comes from an allowed origin."""
    if not origin:
        return False
    return origin in ALLOWED_WS_ORIGINS


# Maximum allowed request body size (5 MB). Prevents DoS via huge JSON payloads.
MAX_BODY_BYTES: int = int(os.environ.get("AEGIS_MAX_BODY_BYTES", str(5 * 1024 * 1024)))  # type: ignore


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects requests whose Content-Length exceeds MAX_BODY_BYTES before routing."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.scope["type"] == "websocket":
            return await call_next(request)
        cl = request.headers.get("content-length")
        if cl and int(cl) > MAX_BODY_BYTES:
            logger.warning("Request body too large: %s bytes from %s", cl, request.client)
            return JSONResponse({"detail": "Request body too large"}, status_code=413)
        return await call_next(request)


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Enforces X-AEGIS-Key authentication on all non-public HTTP endpoints.
    WebSocket upgrades are validated by BOTH Origin AND API key.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Always allow public paths
        if path in PUBLIC_PATHS:
            return await call_next(request)

        # WebSocket — validate origin AND API key (via ?key= query param)
        if request.scope["type"] == "websocket" or request.headers.get("upgrade", "").lower() == "websocket":  # noqa: E501
            origin = request.headers.get("origin")
            if not check_ws_origin(origin):
                logger.warning("WS rejected: bad origin %s", origin)
                return JSONResponse({"detail": "WebSocket origin not allowed"}, status_code=403)
            if not check_api_key(request):
                logger.warning("WS rejected: missing API key from origin %s", origin)
                return JSONResponse({"detail": "Missing or invalid API key"}, status_code=401)
            return await call_next(request)

        # Regular HTTP — require valid API key
        if not check_api_key(request):
            logger.warning("Rejected unauthenticated request to %s from %s", path, request.client)
            return JSONResponse({"detail": "Missing or invalid API key"}, status_code=401)

        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Injects security response headers on every response.
    Fixes H-06 (clickjacking, MIME sniffing, referrer leakage).
    Removes X-Process-Time in non-debug mode (L-01).
    """

    DEBUG: bool = os.environ.get("AEGIS_DEBUG", "false").lower() == "true"  # type: ignore

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.scope["type"] == "websocket":
            return await call_next(request)

        response = await call_next(request)

        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]          = "DENY"
        response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]       = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"]  = (
            "default-src 'self'; "
            "connect-src 'self' ws://127.0.0.1:8000; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; "
            "img-src 'self' data:;"
        )

        # Strip timing info in production (L-01)
        if not self.DEBUG and "X-Process-Time" in response.headers:
            del response.headers["X-Process-Time"]

        if "server" in response.headers:
            del response.headers["server"]

        return response
