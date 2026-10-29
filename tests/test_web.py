from urllib.parse import parse_qs, urlparse

from app.scanners.base import ScanResult
from app.scanners.web import (
    SQL_ERROR_RE,
    _add_header_findings,
    _exposed_files,
    _injection_checks,
    _run_nuclei,
    _title,
)
from tests.helpers import DummyContext, FakeResponse, FakeSession


def test_title_extraction():
    assert _title("<html><title>  Hello\n  world </title></html>") == "Hello world"
    assert _title("<html>no title</html>") == ""
    assert len(_title("<title>" + "x" * 500 + "</title>")) == 160


def test_sql_error_patterns():
    assert SQL_ERROR_RE.search("You have an error in your SQL syntax; check the manual... MySQL")
    assert SQL_ERROR_RE.search("ORA-01756: quoted string not properly terminated")
    assert not SQL_ERROR_RE.search("The page loaded successfully")


def test_header_findings_on_plain_http_response():
    response = FakeResponse(
        url="http://example.test/",
        headers={"Server": "nginx/1.24.0", "Content-Type": "text/html"},
        body="<html><title>Index of /</title></html>",
        cookies=["sessionid=abc123; Path=/"],
    )
    result = ScanResult()
    _add_header_findings(result, "http://example.test/", response, "<html><title>Index of /</title></html>", DummyContext())
    findings = result.normalized()
    keys = {finding["key"] for finding in findings}
    assert "web-http" in keys
    assert "header:content-security-policy" in keys
    assert "header:frame-options" in keys
    assert "header:version-banner" in keys
    assert "cookie:sessionid:HttpOnly,SameSite" in keys
    assert "web-directory-listing" in keys
    assert "header:cors" not in keys
    assert "header:cors-wildcard" not in keys


def test_header_findings_on_hardened_https_response():
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
        "X-Frame-Options": "DENY",
        "Server": "generic",
    }
    response = FakeResponse(url="https://example.test/", headers=headers)
    result = ScanResult()
    _add_header_findings(result, "https://example.test/", response, "<html></html>", DummyContext())
    assert result.normalized() == []


def test_cors_and_cookie_findings():
    headers = {
        "Strict-Transport-Security": "max-age=1",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=()",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }
    response = FakeResponse(url="https://example.test/", headers=headers)
    result = ScanResult()
    _add_header_findings(result, "https://example.test/", response, "", DummyContext())
    keys = {finding["key"] for finding in result.normalized()}
    assert "header:cors" in keys
    assert "header:cors-wildcard" not in keys


def test_exposed_git_metadata_is_detected():
    def handler(url):
        if url.endswith(".git/HEAD"):
            return FakeResponse(url=url, body="ref: refs/heads/main\n", content_type="text/plain")
        return FakeResponse(url=url, status_code=404, body="not found")

    result = ScanResult()
    session = FakeSession(handler)
    _exposed_files(result, session, "https://example.test/path?q=1", DummyContext())
    findings = result.normalized()
    assert len(findings) == 1
    assert findings[0]["title"] == "Exposed Git repository metadata"
    assert findings[0]["severity"] == "high"


def test_injection_checks_detect_sql_and_reflection():
    def handler(url):
        query = parse_qs(urlparse(url).query)
        value = (query.get("q") or [""])[0]
        if value.endswith("'"):
            return FakeResponse(url=url, body="SQL syntax error near MySQL server", content_type="text/html")
        if '"><vs' in value:
            return FakeResponse(url=url, body=f"<html>{value}</html>", content_type="text/html")
        return FakeResponse(url=url, body="<html>ok</html>", content_type="text/html")

    result = ScanResult()
    session = FakeSession(handler)
    ctx = DummyContext()
    _injection_checks(
        result,
        session,
        "https://example.test/search?q=test",
        FakeResponse(url="https://example.test/search?q=test"),
        "ok",
        ctx,
    )
    titles = {finding["title"] for finding in result.normalized()}
    assert "Possible SQL injection in parameter 'q'" in titles
    assert "Reflected HTML injection in parameter 'q'" in titles
    assert len(session.calls) == 2


def test_injection_checks_can_be_disabled():
    result = ScanResult()
    session = FakeSession(lambda url: FakeResponse(url=url))
    ctx = DummyContext({"active": False})
    _injection_checks(
        result,
        session,
        "https://example.test/?q=1",
        FakeResponse(url="https://example.test/?q=1"),
        "",
        ctx,
    )
    assert result.findings == []
    assert session.calls == []


def test_nuclei_json_is_imported(monkeypatch):
    from app.scanners import web

    class Proc:
        returncode = 0
        stdout = (
            '{"template-id":"CVE-2026-0001","matcher-name":"v1","matched-at":"https://example.test/x",'
            '"info":{"name":"Example issue","severity":"high","description":"desc","remediation":"fix",'
            '"classification":{"cve-id":["CVE-2026-0001"],"cwe-id":["CWE-79"],"cvss-score":8.1},'
            '"tags":["xss"]}}\n'
            'not json\n'
        )
        stderr = ""

    monkeypatch.setattr(web, "tool_path", lambda name: "/usr/bin/nuclei")
    monkeypatch.setattr(web, "run_tool", lambda *_args, **_kwargs: Proc())
    monkeypatch.setattr(web, "get_setting", lambda *_args, **_kwargs: "true")
    monkeypatch.setattr(web, "ENABLE_EXTERNAL_APIS", True)
    result = ScanResult()
    _run_nuclei(result, "https://example.test/", DummyContext({"external_tools": True}))
    finding = result.normalized()[0]
    assert finding["title"] == "Example issue"
    assert finding["severity"] == "high"
    assert finding["cve"] == "CVE-2026-0001"
    assert finding["cvss"] == 8.1
    assert finding["raw"]["template_id"] == "CVE-2026-0001"


def test_optional_tools_are_skipped_by_default():
    result = ScanResult()
    ctx = DummyContext()
    _run_nuclei(result, "https://example.test/", ctx)
    assert result.findings == []
    assert ctx.logs == []


def test_get_does_not_follow_cross_host_redirects():
    from app.scanners.web import _get

    def handler(url):
        return FakeResponse(
            url=url,
            status_code=302,
            headers={"Location": "https://elsewhere.test/secret"},
        )

    session = FakeSession(handler)
    response = _get(session, "https://example.test/")
    assert response.status_code == 302
    assert len(session.calls) == 1


def test_get_follows_same_host_redirect():
    from app.scanners.web import _get

    def handler(url):
        if url.endswith("/start"):
            return FakeResponse(
                url=url,
                status_code=302,
                headers={"Location": "/final"},
            )
        return FakeResponse(url=url, status_code=200, body="ok")

    session = FakeSession(handler)
    response = _get(session, "https://example.test/start")
    assert response.status_code == 200
    assert session.calls == ["https://example.test/start", "https://example.test/final"]
