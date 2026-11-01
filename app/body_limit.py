"""ASGI middleware that bounds request bodies before application parsing.

FastAPI/Pydantic normally parses a JSON or multipart body before a route-level
size check runs.  That is too late for an unauthenticated oversized request or
a compromised agent token.  This middleware rejects a declared oversized body
immediately and also counts streamed bytes when ``Content-Length`` is absent.

The body is buffered up to the configured limit (32 MiB by default) so the
downstream application can consume it normally.  The limit is deliberately
larger than the 25 MiB agent result and 20 MiB AD report limits.
"""

from __future__ import annotations

import json

from .config import max_request_bytes

_BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_REJECT_HEADERS = [
    (b"content-type", b"application/json; charset=utf-8"),
    (b"cache-control", b"no-store"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
]


class BodySizeLimitMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or scope.get("method", "").upper() not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return

        limit = max_request_bytes()
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        declared = headers.get("content-length")
        if declared:
            try:
                if int(declared) > limit:
                    await self._reject(send, limit)
                    return
            except ValueError:
                # Let the downstream server reject a malformed Content-Length.
                pass

        body = bytearray()
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return
            if message.get("type") != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > limit:
                await self._reject(send, limit)
                return
            if not message.get("more_body", False):
                break

        delivered = False

        async def replay_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _reject(send, limit: int) -> None:
        payload = json.dumps(
            {
                "detail": "Request body is too large",
                "limit_bytes": limit,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        headers = list(_REJECT_HEADERS)
        headers.append((b"content-length", str(len(payload)).encode("ascii")))
        await send({"type": "http.response.start", "status": 413, "headers": headers})
        await send({"type": "http.response.body", "body": payload})
