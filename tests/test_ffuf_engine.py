"""
Tests for beatrix.core.ffuf_engine (issue #3).

``_filter_results_by_regex`` existed but was never wired into the pipeline —
every ffuf hit became a Finding regardless of whether the response body
actually contained the vuln-specific signal. These tests cover the fix:
capturing response bodies via ffuf's ``-od`` flag, extracting them out of
ffuf's interleaved request/response capture format, and using them to confirm
(or reject) each hit before it becomes a Finding.
"""

from __future__ import annotations

import http.server
import shutil
import threading

import pytest

from beatrix.core.ffuf_engine import (
    FFufEngine,
    FuzzResult,
    VulnType,
    _extract_response_body,
)

_HAS_FFUF = shutil.which("ffuf") is not None
_needs_ffuf = pytest.mark.skipif(not _HAS_FFUF, reason="ffuf binary not installed")


def _result(url: str, **kwargs) -> FuzzResult:
    defaults = dict(
        url=url, payload="p", status_code=200, content_length=1,
        words=1, lines=1, duration_ms=1,
    )
    defaults.update(kwargs)
    return FuzzResult(**defaults)


# ── _extract_response_body: parsing ffuf's -od capture format ───────────
def test_extract_response_body_strips_request_and_headers():
    raw = (
        "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"
        "---- ↑ Request ---- Response ↓ ----\r\n"
        "\r\n"
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        "<html>hit</html>"
    )
    assert _extract_response_body(raw) == "<html>hit</html>"


def test_extract_response_body_handles_lf_only():
    raw = (
        "GET /x HTTP/1.1\nHost: h\n\n"
        "---- Response ----\n\n"
        "HTTP/1.1 200 OK\n\n"
        "body-content"
    )
    assert _extract_response_body(raw) == "body-content"


def test_extract_response_body_no_marker_degrades_to_raw():
    assert _extract_response_body("no marker here") == "no marker here"


def test_extract_response_body_no_header_body_separator():
    raw = "---- Response ----\r\n\r\nHTTP/1.1 200 OK-with-no-blank-line-after"
    assert _extract_response_body(raw) == "HTTP/1.1 200 OK-with-no-blank-line-after"


def test_extract_response_body_empty_string():
    assert _extract_response_body("") == ""


# ── _filter_results_by_regex / _results_to_findings: pure logic, no self ─
# Neither method touches `self`, so they're exercised unbound — no ffuf
# binary or SecLists manager needed for these.
def test_filter_results_by_regex_keeps_only_confirmed_hits():
    results = [_result("http://h/a"), _result("http://h/b")]
    responses = {
        "http://h/a": "You have an error in your SQL syntax near line 1",
        "http://h/b": "nothing interesting here",
    }
    filtered = FFufEngine._filter_results_by_regex(None, results, VulnType.SQLI, responses)
    assert [r.url for r in filtered] == ["http://h/a"]
    assert filtered[0].matched_by


def test_filter_results_by_regex_xss_reflection_fallback():
    # A payload that matches none of XSS's match_regex patterns (no <script>,
    # no on*= handler, no javascript:) but is reflected verbatim — only the
    # XSS-only reflection fallback should confirm this one.
    results = [_result("http://h/a", payload="ZZ_XSS_PROBE_12345")]
    responses = {"http://h/a": "echo: ZZ_XSS_PROBE_12345"}
    filtered = FFufEngine._filter_results_by_regex(None, results, VulnType.XSS, responses)
    assert len(filtered) == 1
    assert filtered[0].matched_by == "payload_reflection"


def test_filter_results_by_regex_no_matcher_returns_unfiltered():
    # OPEN_REDIRECT has no match_regex — nothing to confirm against, so the
    # step is a no-op (ffuf's own -mc/-fc already did the filtering).
    results = [_result("http://h/a"), _result("http://h/b")]
    filtered = FFufEngine._filter_results_by_regex(
        None, results, VulnType.OPEN_REDIRECT, {}
    )
    assert filtered == results


def test_results_to_findings_confidence_levels():
    # Regression test: matched_by held the raw pattern text (e.g. the SQLi
    # regex source), so the old `"regex" in result.matched_by` check was
    # always False and every match landed on "medium".
    regex_hit = _result("u1", matched_by=r"SQL syntax.*MySQL")
    reflection_hit = _result("u2", matched_by="payload_reflection")
    unmatched = _result("u3")

    findings = FFufEngine._results_to_findings(
        None, [regex_hit, reflection_hit, unmatched], VulnType.SQLI, parameter="q"
    )
    confidence = {f.url: f.confidence for f in findings}
    assert confidence["u1"] == "high"
    assert confidence["u2"] == "medium"
    assert confidence["u3"] == "low"


# ── _build_ffuf_command / _load_response_bodies: need a real engine ─────
@pytest.fixture
def engine(monkeypatch, tmp_path):
    # ffuf reads $HOME/.config/ffuf on startup; some sandboxes have a HOME
    # whose .config/ffuf isn't readable by the test user, so point it
    # somewhere guaranteed writable instead of relying on the ambient HOME.
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return FFufEngine(threads=5, verbose=False)


@_needs_ffuf
def test_build_ffuf_command_only_adds_od_when_requested(engine, tmp_path):
    common = dict(
        url="http://x/FUZZ", wordlist=tmp_path / "w.txt",
        output_file=tmp_path / "o.json", vuln_type=VulnType.XSS,
    )
    assert "-od" not in engine._build_ffuf_command(**common)

    od_dir = tmp_path / "od"
    cmd = engine._build_ffuf_command(**common, od_dir=od_dir)
    assert "-od" in cmd
    assert str(od_dir) in cmd


@_needs_ffuf
def test_load_response_bodies_reads_files_and_skips_missing(engine, tmp_path):
    od_dir = tmp_path / "od"
    od_dir.mkdir()
    (od_dir / "abc123").write_text(
        "GET /x HTTP/1.1\r\nHost: h\r\n\r\n"
        "---- Response ----\r\n\r\n"
        "HTTP/1.1 200 OK\r\n\r\n"
        "SQL syntax error near"
    )
    results = [
        _result("http://h/x", resultfile="abc123"),
        _result("http://h/y", resultfile=""),          # never captured
        _result("http://h/z", resultfile="missing"),   # file vanished
    ]
    bodies = engine._load_response_bodies(results, od_dir)
    assert bodies == {"http://h/x": "SQL syntax error near"}


# ── End-to-end: fuzz_endpoint against a real ffuf + local HTTP fixture ───
class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    routes = {
        "/vulnpath": (200, b"Error: You have an error in your SQL syntax near line 1"),
        "/safepath": (200, b"Just a normal safe page with no vulnerability indicators."),
    }

    def do_GET(self):
        status, body = self.routes.get(self.path, (404, b"not found"))
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):  # noqa: A002 - silence test server logs
        pass


@pytest.fixture
def fixture_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=5)


@_needs_ffuf
def test_fuzz_endpoint_confirms_hits_against_response_body(engine, fixture_server):
    url = f"http://127.0.0.1:{fixture_server}/FUZZ"
    findings = engine.fuzz_endpoint(
        url=url, payloads=["vulnpath", "safepath"], vuln_type=VulnType.SQLI,
    )

    urls = {f.url for f in findings}
    assert any("vulnpath" in u for u in urls)
    assert not any("safepath" in u for u in urls), (
        "safepath's response never contained a SQLi signal — verify_reflection "
        "should have filtered it out instead of reporting every ffuf hit"
    )
    vuln_finding = next(f for f in findings if "vulnpath" in f.url)
    assert vuln_finding.confidence == "high"

    # The -od scratch directory for this call must not survive the call.
    assert not any(engine.temp_dir.glob("od_*"))


@_needs_ffuf
def test_fuzz_endpoint_verify_reflection_false_skips_filtering(engine, fixture_server):
    url = f"http://127.0.0.1:{fixture_server}/FUZZ"
    findings = engine.fuzz_endpoint(
        url=url, payloads=["vulnpath", "safepath"], vuln_type=VulnType.SQLI,
        verify_reflection=False,
    )
    urls = {f.url for f in findings}
    # Opt-out preserves ffuf's raw, unconfirmed hits (both matched status 200).
    assert any("vulnpath" in u for u in urls)
    assert any("safepath" in u for u in urls)
    assert all(f.confidence == "low" for f in findings)
