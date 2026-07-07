"""
Tests for the Beatrix Suite central dashboard (`beatrix-suite`).

The suite unifies the existing GUIs behind ONE stdlib http.server: the shell at
/, the auth GUI mounted verbatim at /auth (+ its /api/* backend), and a Ghost
tool that streams a run's events at /ghost/events. These tests exercise the
route wiring and the ghost event plumbing over real HTTP without a browser,
LLM, or API key.
"""

from __future__ import annotations

import json
import urllib.request

import pytest

from beatrix.cli.ghost_web import _Broker
from beatrix.cli.suite import _AUTH_GET, _AUTH_POST, SuiteServer


@pytest.fixture
def server():
    srv = SuiteServer(host="127.0.0.1", port=0)
    srv.start(open_browser=False)
    try:
        yield srv
    finally:
        srv.stop()


def _get(srv, path):
    with urllib.request.urlopen(srv.url.rstrip("/") + path, timeout=5) as r:
        return r.getcode(), r.read()


def _post(srv, path, obj):
    req = urllib.request.Request(
        srv.url.rstrip("/") + path, data=json.dumps(obj).encode(), method="POST"
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.getcode(), json.loads(r.read())


# ── One server, all tools: route wiring ─────────────────────────────────
def test_shell_served_at_root(server):
    code, body = _get(server, "/")
    assert code == 200
    text = body.decode()
    # Top tab bar with the three v1 tools.
    for tab in ('data-tab="dashboard"', 'data-tab="auth"', 'data-tab="ghost"'):
        assert tab in text


def test_auth_gui_mounted_same_origin(server):
    # The Auth tab iframes /auth on the SAME origin — full reuse of the existing page.
    code, body = _get(server, "/auth")
    assert code == 200
    assert b"Beatrix Auth" in body


def test_auth_api_dispatches_to_backend(server):
    # A GET auth route returns the same JSON shape the standalone auth GUI serves.
    code, body = _get(server, "/api/list")
    assert code == 200
    assert isinstance(json.loads(body), dict)


def test_auth_routes_match_standalone_gui():
    # Suite mounts exactly the auth GUI's route set (no drift).
    assert set(_AUTH_GET) == {"/api/list", "/api/keys", "/api/model", "/api/models"}
    assert set(_AUTH_POST) == {"/api/save", "/api/clear", "/api/keys", "/api/model"}


# ── Ghost tool: run validation + event streaming ────────────────────────
def test_ghost_events_empty_before_any_run(server):
    code, body = _get(server, "/ghost/events?since=0")
    assert code == 200
    assert json.loads(body) == {"events": [], "done": False}


def test_ghost_run_rejects_empty_target(server):
    code, result = _post(server, "/ghost/run", {"target": "  "})
    assert code == 200
    assert result["ok"] is False and "target" in result["error"].lower()


def test_ghost_events_stream_from_broker(server):
    # Simulate a run's broker (what run_investigation's on_event feeds) and
    # confirm the /ghost/events contract the page polls.
    b = _Broker(meta={"target": "https://x"})
    server.ghost_broker = b
    b.emit({"type": "agent_start", "text": "GHOST engaged"})
    b.emit({"type": "finding", "text": "SQLi", "detail": "id param"})

    code, body = _get(server, "/ghost/events?since=0")
    data = json.loads(body)
    assert [e["type"] for e in data["events"]] == ["agent_start", "finding"]
    assert data["done"] is False

    # `since` cursor only returns newer events.
    last = data["events"][-1]["seq"]
    _, body2 = _get(server, "/ghost/events?since=%d" % last)
    assert json.loads(body2)["events"] == []

    b.finish()
    _, body3 = _get(server, "/ghost/events?since=0")
    assert json.loads(body3)["done"] is True


def test_ghost_state_reflects_current_run(server):
    assert _get(server, "/ghost/state")[0] == 200
    assert json.loads(_get(server, "/ghost/state")[1]) == {}  # no run yet
    server.ghost_broker = _Broker(meta={"target": "https://x", "model": "m"})
    state = json.loads(_get(server, "/ghost/state")[1])
    assert state["target"] == "https://x" and state["model"] == "m"


def test_unknown_route_404s(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(server, "/nope")
    assert exc.value.code == 404
