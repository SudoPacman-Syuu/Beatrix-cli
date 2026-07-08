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
from beatrix.cli.suite import _AUTH_GET, _AUTH_POST, _ProjectStore, SuiteServer


@pytest.fixture
def server(tmp_path):
    # Isolate the project store from the real ~/.beatrix/suite.
    srv = SuiteServer(host="127.0.0.1", port=0, state_dir=tmp_path / "suite")
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


# ── Ghost tool: run validation + event streaming (per-project) ──────────
def test_ghost_events_empty_before_any_run(server):
    # No broker yet for this project => reported "done" so a client never
    # sits in an infinite poll loop for a project that never ran anything.
    code, body = _get(server, "/ghost/events?since=0&project=1")
    assert code == 200
    assert json.loads(body) == {"events": [], "done": True}


def test_ghost_run_rejects_empty_target(server):
    code, result = _post(server, "/ghost/run", {"target": "  ", "project": 1})
    assert code == 200
    assert result["ok"] is False and "target" in result["error"].lower()


def test_ghost_events_stream_from_broker(server):
    # Simulate a run's broker (what run_investigation's on_event feeds) and
    # confirm the /ghost/events contract the page polls.
    b = _Broker(meta={"target": "https://x"})
    server.ghost_brokers["1"] = b
    b.emit({"type": "agent_start", "text": "GHOST engaged"})
    b.emit({"type": "finding", "text": "SQLi", "detail": "id param"})

    code, body = _get(server, "/ghost/events?since=0&project=1")
    data = json.loads(body)
    assert [e["type"] for e in data["events"]] == ["agent_start", "finding"]
    assert data["done"] is False

    # `since` cursor only returns newer events.
    last = data["events"][-1]["seq"]
    _, body2 = _get(server, "/ghost/events?since=%d&project=1" % last)
    assert json.loads(body2)["events"] == []

    b.finish()
    _, body3 = _get(server, "/ghost/events?since=0&project=1")
    assert json.loads(body3)["done"] is True


def test_ghost_state_reflects_current_run(server):
    assert _get(server, "/ghost/state?project=1")[0] == 200
    assert json.loads(_get(server, "/ghost/state?project=1")[1]) == {}  # no run yet
    server.ghost_brokers["1"] = _Broker(meta={"target": "https://x", "model": "m"})
    state = json.loads(_get(server, "/ghost/state?project=1")[1])
    assert state["target"] == "https://x" and state["model"] == "m"
    assert state["running"] is True  # broker not finished yet


def test_ghost_events_isolated_between_projects(server):
    # This is the exact bug: project 1 has a run streaming; switching to /
    # creating project 2 must NOT clobber or hide project 1's events.
    b1 = _Broker(meta={"target": "https://one.com"})
    server.ghost_brokers["1"] = b1
    b1.emit({"type": "agent_start", "text": "GHOST engaged"})
    b1.emit({"type": "finding", "text": "SQLi on one.com"})

    # A second project is created and has never run anything.
    code, d2 = _post(server, "/projects/new", {})
    new_id = d2["projects"][-1]["id"]
    assert json.loads(_get(server, "/ghost/state?project=%d" % new_id)[1]) == {}

    # Project 1's stream is completely unaffected by project 2 existing/being active.
    data = json.loads(_get(server, "/ghost/events?since=0&project=1")[1])
    assert [e["type"] for e in data["events"]] == ["agent_start", "finding"]
    state1 = json.loads(_get(server, "/ghost/state?project=1")[1])
    assert state1["target"] == "https://one.com" and state1["running"] is True


def test_ghost_run_defaults_to_active_project_when_unspecified(server):
    # Client omits `project` -> server uses the currently active project.
    _post(server, "/projects/select", {"id": 1})
    code, result = _post(server, "/ghost/run", {"target": ""})  # empty target, no project
    assert result["ok"] is False  # still validates target; proves the route was reached

    assert json.loads(_get(server, "/ghost/events?since=0")[1]) == {"events": [], "done": True}


def test_ghost_run_rejects_concurrent_run_on_same_project(server):
    server.ghost_brokers["1"] = _Broker(meta={"target": "https://x"})  # still running
    code, result = _post(server, "/ghost/run", {"target": "https://y", "project": 1})
    assert result["ok"] is False
    assert "already running" in result["error"].lower()


def test_unknown_route_404s(server):
    with pytest.raises(urllib.error.HTTPError) as exc:
        _get(server, "/nope")
    assert exc.value.code == 404


# ── Projects rail: create / switch / delete over HTTP ───────────────────
def test_projects_seeded_with_one_active(server):
    code, body = _get(server, "/projects")
    assert code == 200
    d = json.loads(body)
    assert len(d["projects"]) == 1
    assert d["projects"][0]["id"] == 1 and d["projects"][0]["name"] == "Project 1"
    assert d["active"] == 1


def test_projects_created_numerically_and_active(server):
    _, d2 = _post(server, "/projects/new", {})
    assert [p["id"] for p in d2["projects"]] == [1, 2]
    assert d2["active"] == 2  # newest becomes active
    _, d3 = _post(server, "/projects/new", {})
    assert [p["name"] for p in d3["projects"]] == ["Project 1", "Project 2", "Project 3"]


def test_project_select_switches_active(server):
    _post(server, "/projects/new", {})           # -> active 2
    _, r = _post(server, "/projects/select", {"id": 1})
    assert r == {"ok": True, "active": 1}
    assert json.loads(_get(server, "/projects")[1])["active"] == 1


def test_project_delete_removes_and_fixes_active(server):
    _post(server, "/projects/new", {})           # 2 (active)
    _post(server, "/projects/new", {})           # 3 (active)
    _, r = _post(server, "/projects/delete", {"id": 3})
    assert r["ok"] is True
    assert [p["id"] for p in r["projects"]] == [1, 2]
    assert r["active"] == 1  # active fell back off the deleted one


def test_ids_are_stable_after_delete(server):
    _post(server, "/projects/new", {})           # 2
    _post(server, "/projects/new", {})           # 3
    _post(server, "/projects/delete", {"id": 2})  # gap: [1, 3]
    ids = [p["id"] for p in json.loads(_get(server, "/projects")[1])["projects"]]
    assert ids == [1, 3]                          # not renumbered
    _, d = _post(server, "/projects/new", {})     # next monotonic id
    assert d["projects"][-1]["id"] == 4


def test_deleting_last_project_reseeds(server):
    _, r = _post(server, "/projects/delete", {"id": 1})
    assert r["ok"] is True
    assert len(r["projects"]) == 1                # never empty
    assert r["active"] == r["projects"][0]["id"]


def test_delete_unknown_project_is_noop(server):
    _, r = _post(server, "/projects/delete", {"id": 999})
    assert r["ok"] is False


def test_projects_persist_across_restart(tmp_path):
    sd = tmp_path / "suite"
    s1 = SuiteServer(host="127.0.0.1", port=0, state_dir=sd)
    s1.start(open_browser=False)
    try:
        _post(s1, "/projects/new", {})            # now [1, 2]
    finally:
        s1.stop()
    # New server instance, same state dir -> projects survive.
    store = _ProjectStore(sd)
    st = store.state()
    assert [p["id"] for p in st["projects"]] == [1, 2]


def test_project_workspace_dir_created_and_removed(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    store.new()  # id 2
    assert (tmp_path / "suite" / "projects" / "2").is_dir()
    store.delete(2)
    assert not (tmp_path / "suite" / "projects" / "2").exists()
