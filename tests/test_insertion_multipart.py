"""
Tests for multipart/form-data insertion-point handling (issue #4).

Previously ``InsertionPointDetector._parse_body`` returned an empty ``{}`` for
any ``multipart/form-data`` request, so every injection scanner
(SQLi/XSS/CMDi/SSTI) silently skipped all fields in multipart requests — a
blind spot for file-upload endpoints. These tests cover the parsing,
detection, and injection that close that gap.
"""

from __future__ import annotations

import pytest

from beatrix.core.types import InsertionPointType
from beatrix.scanners.insertion import (
    BodyFormat,
    InsertionPointDetector,
    MultipartPart,
    _extract_boundary,
    parse_multipart,
    serialize_multipart,
)

BOUNDARY = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
CRLF = "\r\n"


def _build_body(boundary: str = BOUNDARY) -> bytes:
    return (
        f"--{boundary}{CRLF}"
        f'Content-Disposition: form-data; name="username"{CRLF}{CRLF}'
        f"alice{CRLF}"
        f"--{boundary}{CRLF}"
        f'Content-Disposition: form-data; name="bio"{CRLF}{CRLF}'
        f"line one\r\nline two{CRLF}"  # value containing a CRLF
        f"--{boundary}{CRLF}"
        f'Content-Disposition: form-data; name="avatar"; filename="pic.png"{CRLF}'
        f"Content-Type: image/png{CRLF}{CRLF}"
        f"PNGDATA{CRLF}"
        f"--{boundary}--{CRLF}"
    ).encode()


def _parse(body: bytes = None, boundary: str = BOUNDARY):
    det = InsertionPointDetector()
    return det, det.parse_request(
        method="POST",
        url="https://target.com/upload",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        body=body if body is not None else _build_body(boundary),
    )


# ── boundary extraction ──────────────────────────────────────────────────
def test_extract_boundary_plain_and_quoted():
    assert _extract_boundary("multipart/form-data; boundary=abcXYZ") == "abcXYZ"
    assert _extract_boundary('multipart/form-data; boundary="abc XYZ"') == "abc XYZ"
    assert _extract_boundary("application/json") is None


# ── low-level parse ──────────────────────────────────────────────────────
def test_parse_multipart_extracts_all_parts():
    parts = parse_multipart(_build_body(), f"multipart/form-data; boundary={BOUNDARY}")
    assert [p.name for p in parts] == ["username", "bio", "avatar"]

    username, bio, avatar = parts
    assert username.text_value == "alice" and not username.is_file
    # A CRLF inside a value must survive (boundary split is unambiguous).
    assert bio.text_value == "line one\r\nline two"
    assert avatar.is_file
    assert avatar.filename == "pic.png"
    assert avatar.content_type == "image/png"
    assert avatar.content == b"PNGDATA"


def test_parse_multipart_missing_boundary_returns_empty():
    assert parse_multipart(_build_body(), "multipart/form-data") == []


def test_parse_multipart_empty_body_returns_empty():
    assert parse_multipart(b"", f"multipart/form-data; boundary={BOUNDARY}") == []


def test_parse_multipart_preserves_binary_content():
    raw = bytes(range(256))
    body = (
        f"--{BOUNDARY}{CRLF}"
        f'Content-Disposition: form-data; name="f"; filename="b.bin"{CRLF}'
        f"Content-Type: application/octet-stream{CRLF}{CRLF}"
    ).encode() + raw + f"{CRLF}--{BOUNDARY}--{CRLF}".encode()

    parts = parse_multipart(body, f"multipart/form-data; boundary={BOUNDARY}")
    assert len(parts) == 1 and parts[0].content == raw


# ── round-trip ───────────────────────────────────────────────────────────
def test_serialize_round_trips():
    parts = parse_multipart(_build_body(), f"multipart/form-data; boundary={BOUNDARY}")
    rebuilt = serialize_multipart(parts, BOUNDARY)
    reparsed = parse_multipart(rebuilt, f"multipart/form-data; boundary={BOUNDARY}")
    assert [(p.name, p.content, p.filename) for p in reparsed] == \
           [(p.name, p.content, p.filename) for p in parts]


# ── parse_request integration ────────────────────────────────────────────
def test_parse_request_populates_multipart_state():
    _, req = _parse()
    assert req.body_format == BodyFormat.MULTIPART
    # Regression: this used to be {} — text fields must now be exposed.
    assert req.body_params == {"username": "alice", "bio": "line one\r\nline two"}
    assert len(req.multipart_parts) == 3


# ── detection ────────────────────────────────────────────────────────────
def test_detect_creates_multipart_insertion_points():
    det, req = _parse()
    points = det.detect(req)
    mp = [p for p in points if p.type == InsertionPointType.MULTIPART]

    # Regression: zero insertion points were produced for multipart before.
    by_name = {p.name: p for p in mp}
    assert set(by_name) == {"username", "bio", "avatar"}

    # Text fields target their value; the file field targets its filename.
    assert by_name["username"].position == (0, 0)
    assert by_name["bio"].position == (1, 0)
    assert by_name["avatar"].position == (2, 1)
    assert by_name["avatar"].value == "pic.png"  # current filename


# ── injection ────────────────────────────────────────────────────────────
def test_inject_into_text_field_value():
    det, req = _parse()
    ip = next(p for p in det.detect(req) if p.name == "username")
    payload = "alice' OR 1=1-- -"
    _, _, body = det.build_request_with_payload(req, ip, payload)

    parts = parse_multipart(body, f"multipart/form-data; boundary={BOUNDARY}")
    injected = next(p for p in parts if p.name == "username")
    assert injected.text_value == payload
    # Other fields untouched.
    assert next(p for p in parts if p.name == "bio").text_value == "line one\r\nline two"


def test_inject_into_filename():
    det, req = _parse()
    ip = next(p for p in det.detect(req) if p.name == "avatar")
    payload = "../../../../etc/passwd"
    _, _, body = det.build_request_with_payload(req, ip, payload)

    parts = parse_multipart(body, f"multipart/form-data; boundary={BOUNDARY}")
    avatar = next(p for p in parts if p.name == "avatar")
    assert avatar.filename == payload
    assert avatar.content == b"PNGDATA"  # file content preserved
    assert avatar.content_type == "image/png"


def test_injection_does_not_mutate_original_request():
    det, req = _parse()
    original_body = req.body
    for ip in det.detect(req):
        det.build_request_with_payload(req, ip, "<PAYLOAD>")
    # The shared request is reused across every payload — it must be pristine.
    assert req.body == original_body
    assert req.multipart_parts[0].content == b"alice"
    assert req.multipart_parts[2].filename == "pic.png"


def test_injected_body_uses_original_boundary():
    det, req = _parse()
    ip = next(p for p in det.detect(req) if p.name == "username")
    _, _, body = det.build_request_with_payload(req, ip, "x")
    # Body boundary must match the (unchanged) Content-Type header's boundary.
    assert ("--" + BOUNDARY).encode() in body
    assert body.rstrip().endswith(("--" + BOUNDARY + "--").encode())


# ── scanner wiring ───────────────────────────────────────────────────────
def test_scanner_gives_multipart_full_payload_categories():
    from beatrix.core.types import InsertionPoint
    from beatrix.scanners.injection import InjectionScanner

    scanner = InjectionScanner()
    ip = InsertionPoint(
        name="username", value="alice",
        type=InsertionPointType.MULTIPART, position=(0, 0),
    )
    cats = scanner._select_categories(ip)
    assert set(cats) == {"sqli", "xss", "ssti", "cmdi", "path"}
