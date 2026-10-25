"""Small test doubles used by scanner tests."""

from __future__ import annotations

from typing import Any


class DummyContext:
    """A ScanContext-compatible object that records progress instead of DB writes."""

    def __init__(self, options: dict[str, Any] | None = None, target: str = "https://example.test"):
        self.scan_id = 1
        self.target = target
        self.options = options or {}
        self.logs: list[tuple[str, str]] = []
        self.progress_updates: list[tuple[int, str | None]] = []
        self.is_cancelled = False

    def log(self, message: str, level: str = "info") -> None:
        self.logs.append((level, message))

    def progress(self, value: int, stage: str | None = None) -> None:
        self.progress_updates.append((value, stage))

    def cancelled(self) -> bool:
        return self.is_cancelled

    def check_cancel(self) -> None:
        if self.is_cancelled:
            raise RuntimeError("cancelled")

    def option(self, name: str, default: Any = None) -> Any:
        return self.options.get(name, default)

    def option_bool(self, name: str, default: bool = False) -> bool:
        value = self.options.get(name, default)
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)


class FakeRawHeaders:
    def __init__(self, cookies: list[str] | None = None):
        self._cookies = cookies or []

    def getlist(self, name: str) -> list[str]:
        return list(self._cookies) if name.lower() == "set-cookie" else []


class FakeRaw:
    def __init__(self, cookies: list[str] | None = None):
        self.headers = FakeRawHeaders(cookies)


class FakeResponse:
    def __init__(
        self,
        *,
        url: str = "https://example.test",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        body: str = "",
        content_type: str = "text/html",
        cookies: list[str] | None = None,
    ):
        self.url = url
        self.status_code = status_code
        self.headers = "CaseInsensitiveDict"
        from requests.structures import CaseInsensitiveDict

        self.headers = CaseInsensitiveDict(headers or {"Content-Type": content_type})
        self.content = body.encode("utf-8")
        self.encoding = "utf-8"
        self.raw = FakeRaw(cookies)


class FakeSession:
    """Requests-session double with a URL->response callable."""

    def __init__(self, handler):
        self.handler = handler
        self.calls: list[str] = []

    def get(self, url: str, **_kwargs):
        self.calls.append(url)
        return self.handler(url)

    def close(self) -> None:
        return None
