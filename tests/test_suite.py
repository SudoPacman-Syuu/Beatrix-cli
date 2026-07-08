"""
Tests for the Beatrix Suite central dashboard (`beatrix-suite`).

The suite unifies the existing GUIs behind ONE stdlib http.server: the shell at
/, the auth GUI mounted verbatim at /auth (+ its /api/* backend), a Ghost tool
that streams a run's events at /ghost/events, and a Hunt tool (the Dashboard's
module/preset control panel + terminal) that streams at /hunt/events. These
tests exercise the route wiring and event plumbing over real HTTP without a
browser, LLM, API key, or a real scan.
"""

from __future__ import annotations

import json
import urllib.request

import pytest

from beatrix.cli.ghost_web import _Broker
from beatrix.cli.suite import _AUTH_GET, _AUTH_POST, _IssueStore, _ProjectStore, SuiteServer


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


def test_ghost_pane_has_original_dashboard_controls(server):
    # Regression: the Ghost pane must carry the same controls the standalone
    # GHOST v2 dashboard has — autoscroll toggle, Save HTML, and the
    # events/tools/elapsed stat readout — not just the bare log.
    text = _get(server, "/")[1].decode()
    for needle in ('id="g-autoscroll"', 'id="g-save"', 'id="g-count"',
                   'id="g-tools"', 'id="g-elapsed"', "saveGhostHtml"):
        assert needle in text, f"missing {needle!r} from Ghost pane"


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


# ── Hunt tool: catalog, validation, per-project run isolation ────────────
def test_hunt_catalog_shape(server):
    code, body = _get(server, "/hunt/catalog")
    assert code == 200
    cat = json.loads(body)
    assert len(cat["modules"]) >= 30  # BeatrixEngine's real module count
    assert {"key", "name", "category", "description"} <= set(cat["modules"][0])
    preset_keys = {p["key"] for p in cat["presets"]}
    assert {"quick", "standard", "full", "stealth"} <= preset_keys


def test_hunt_catalog_full_preset_is_every_module(server):
    cat = json.loads(_get(server, "/hunt/catalog")[1])
    full = next(p for p in cat["presets"] if p["key"] == "full")
    assert set(full["modules"]) == {m["key"] for m in cat["modules"]}


def test_hunt_catalog_modules_grouped_by_category(server):
    # Regression: modules used to be sorted by key, not category, so same-
    # category modules weren't adjacent and the panel printed a near-duplicate
    # header per module instead of grouping them.
    cat = json.loads(_get(server, "/hunt/catalog")[1])
    cats_in_order = [m["category"] for m in cat["modules"]]
    # Every occurrence of a category must be contiguous (no A, B, A pattern).
    seen = set()
    prev = None
    for c in cats_in_order:
        if c != prev:
            assert c not in seen, f"category {c!r} appeared in two separate groups"
            seen.add(c)
        prev = c


def test_hunt_run_rejects_empty_target(server):
    code, result = _post(server, "/hunt/run", {"target": "  ", "modules": ["headers"], "project": 1})
    assert code == 200
    assert result["ok"] is False and "target" in result["error"].lower()


def test_hunt_run_rejects_empty_module_selection(server):
    # Empty modules must NOT silently mean "run everything" (that's what an
    # empty list means to BeatrixEngine.hunt/kill_chain) — it must be rejected.
    code, result = _post(server, "/hunt/run", {"target": "example.com", "modules": [], "project": 1})
    assert result["ok"] is False
    assert "module" in result["error"].lower()


def test_hunt_events_empty_before_any_run(server):
    code, body = _get(server, "/hunt/events?since=0&project=1")
    assert code == 200
    assert json.loads(body) == {"events": [], "done": True}


def test_hunt_events_stream_from_broker(server):
    b = _Broker(meta={"target": "https://x", "modules": ["headers"]})
    server.hunt_brokers["1"] = b
    b.emit({"type": "scanner_start", "text": "▸ headers → https://x"})
    b.emit({"type": "finding", "text": "[LOW] Missing CSP", "detail": "URL: https://x"})

    data = json.loads(_get(server, "/hunt/events?since=0&project=1")[1])
    assert [e["type"] for e in data["events"]] == ["scanner_start", "finding"]
    assert data["done"] is False

    b.finish()
    assert json.loads(_get(server, "/hunt/events?since=0&project=1")[1])["done"] is True


def test_hunt_state_reflects_current_run(server):
    assert json.loads(_get(server, "/hunt/state?project=1")[1]) == {}
    server.hunt_brokers["1"] = _Broker(meta={"target": "https://x", "modules": ["headers"]})
    state = json.loads(_get(server, "/hunt/state?project=1")[1])
    assert state["target"] == "https://x" and state["running"] is True


def test_hunt_run_isolated_between_projects(server):
    b1 = _Broker(meta={"target": "https://one.com"})
    server.hunt_brokers["1"] = b1
    b1.emit({"type": "scanner_start", "text": "▸ headers"})

    _post(server, "/projects/new", {})  # project 2, never ran anything
    assert json.loads(_get(server, "/hunt/state?project=2")[1]) == {}

    state1 = json.loads(_get(server, "/hunt/state?project=1")[1])
    assert state1["target"] == "https://one.com" and state1["running"] is True


def test_hunt_run_rejects_concurrent_run_on_same_project(server):
    server.hunt_brokers["1"] = _Broker(meta={"target": "https://x"})  # still running
    code, result = _post(server, "/hunt/run",
                          {"target": "https://y", "modules": ["headers"], "project": 1})
    assert result["ok"] is False
    assert "already running" in result["error"].lower()


def test_hunt_event_translator_covers_kill_chain_event_types():
    # The translator must produce a sensible line for every event type
    # kill_chain.py actually emits (scanner_start/done/error, phase_*, crawl_*,
    # finding, info) so nothing silently vanishes from the terminal.
    from types import SimpleNamespace

    from beatrix.cli.suite import _hunt_event_to_line

    assert _hunt_event_to_line("phase_start", {"phase": "Recon", "description": "d"})["type"] == "phase"
    assert _hunt_event_to_line("phase_done", {"phase": "Recon", "findings": 2, "duration": 1.0})["type"] == "phase_done"
    assert _hunt_event_to_line("crawl_start", {})["type"] == "info"
    assert _hunt_event_to_line("crawl_done", {"pages": 1})["type"] == "info"
    assert _hunt_event_to_line("crawl_error", {"error": "x"})["type"] == "scanner_error"
    assert _hunt_event_to_line("scanner_start", {"scanner": "cors"})["type"] == "scanner_start"
    assert _hunt_event_to_line("scanner_done", {"scanner": "cors", "findings": 0}) is None  # quiet on zero
    assert _hunt_event_to_line("scanner_done", {"scanner": "cors", "findings": 1})["type"] == "scanner_done"
    assert _hunt_event_to_line("scanner_error", {"scanner": "cors", "error": "boom"})["type"] == "scanner_error"
    finding = SimpleNamespace(title="XSS", url="https://x", parameter="q", severity=None, evidence="ev")
    line = _hunt_event_to_line("finding", {"finding": finding})
    assert line["type"] == "finding" and "XSS" in line["text"]
    assert _hunt_event_to_line("info", {"message": "hi"})["type"] == "info"
    assert _hunt_event_to_line("unknown_event_type", {}) is None


# ── Scope: parsing/matching helpers ──────────────────────────────────────
def test_parse_scope_entry_normalizes_urls_and_bare_hosts():
    from beatrix.cli.suite import _parse_scope_entry

    assert _parse_scope_entry("https://Example.com/path?x=1") == "example.com"
    assert _parse_scope_entry("example.com:8443") == "example.com"
    assert _parse_scope_entry("  EXAMPLE.com  ") == "example.com"
    assert _parse_scope_entry("*.example.com") == "*.example.com"
    assert _parse_scope_entry("10.0.0.1") == "10.0.0.1"
    assert _parse_scope_entry("   ") is None
    assert _parse_scope_entry("") is None


def test_is_ip_literal():
    from beatrix.cli.suite import _is_ip_literal

    assert _is_ip_literal("10.0.0.1") is True
    assert _is_ip_literal("::1") is True
    assert _is_ip_literal("example.com") is False


def test_expand_for_crawler_adds_wildcards_except_ips_and_existing_wildcards():
    from beatrix.cli.suite import _expand_for_crawler

    assert _expand_for_crawler(["example.com"]) == ["example.com", "*.example.com"]
    assert _expand_for_crawler(["*.example.com"]) == ["*.example.com"]
    assert _expand_for_crawler(["10.0.0.1"]) == ["10.0.0.1"]


def test_host_in_scope_matches_subdomains():
    from beatrix.cli.suite import _host_in_scope

    assert _host_in_scope("https://api.example.com/x", ["example.com"]) is True
    assert _host_in_scope("https://example.com", ["example.com"]) is True
    assert _host_in_scope("https://evil.com", ["example.com"]) is False


def test_parse_scope_text_splits_dedups_and_drops_junk():
    from beatrix.cli.suite import _parse_scope_text

    raw = "https://example.com/x, api.example.com\n  ,, example.com   10.0.0.1"
    assert _parse_scope_text(raw) == ["example.com", "api.example.com", "10.0.0.1"]


# ── Scope: per-project storage (_ProjectStore) ───────────────────────────
def test_project_store_scope_starts_empty(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    assert store.get_scope(1) == []


def test_project_store_add_scope_merges_sorted_and_dedups(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    r = store.add_scope(1, ["b.com", "a.com"])
    assert r == {"ok": True, "scope": ["a.com", "b.com"]}
    r2 = store.add_scope(1, ["a.com", "c.com"])
    assert r2["scope"] == ["a.com", "b.com", "c.com"]


def test_project_store_remove_scope(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    store.add_scope(1, ["a.com", "b.com"])
    r = store.remove_scope(1, "a.com")
    assert r == {"ok": True, "scope": ["b.com"]}


def test_project_store_clear_scope(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    store.add_scope(1, ["a.com", "b.com"])
    r = store.clear_scope(1)
    assert r == {"ok": True, "scope": []}


def test_project_store_scope_isolated_per_project(tmp_path):
    store = _ProjectStore(tmp_path / "suite")
    store.new()  # project 2
    store.add_scope(1, ["a.com"])
    store.add_scope(2, ["b.com"])
    assert store.get_scope(1) == ["a.com"]
    assert store.get_scope(2) == ["b.com"]


def test_project_store_scope_persists_across_restart(tmp_path):
    sd = tmp_path / "suite"
    store = _ProjectStore(sd)
    store.add_scope(1, ["a.com"])
    store2 = _ProjectStore(sd)
    assert store2.get_scope(1) == ["a.com"]


# ── Scope: HTTP routes ────────────────────────────────────────────────────
def test_scope_get_empty_by_default(server):
    code, body = _get(server, "/scope?project=1")
    assert code == 200
    assert json.loads(body) == {"scope": []}


def test_scope_get_defaults_to_active_project(server):
    _post(server, "/scope/add", {"project": 1, "text": "example.com"})
    assert json.loads(_get(server, "/scope")[1]) == {"scope": ["example.com"]}


def test_scope_add_route_parses_pasted_text(server):
    code, r = _post(server, "/scope/add",
                     {"project": 1, "text": "https://example.com/x, evil.com"})
    assert code == 200
    assert r == {"ok": True, "scope": ["evil.com", "example.com"]}


def test_scope_add_route_rejects_unparseable_text(server):
    code, r = _post(server, "/scope/add", {"project": 1, "text": "   "})
    assert code == 200
    assert r["ok"] is False
    assert "no valid" in r["error"]


def test_scope_remove_route(server):
    _post(server, "/scope/add", {"project": 1, "text": "a.com b.com"})
    code, r = _post(server, "/scope/remove", {"project": 1, "entry": "a.com"})
    assert code == 200
    assert r == {"ok": True, "scope": ["b.com"]}


def test_scope_clear_route(server):
    _post(server, "/scope/add", {"project": 1, "text": "a.com b.com"})
    code, r = _post(server, "/scope/clear", {"project": 1})
    assert code == 200
    assert r == {"ok": True, "scope": []}


def test_scope_isolated_between_projects_over_http(server):
    _post(server, "/projects/new", {})  # project 2
    _post(server, "/scope/add", {"project": 1, "text": "a.com"})
    _post(server, "/scope/add", {"project": 2, "text": "b.com"})
    assert json.loads(_get(server, "/scope?project=1")[1]) == {"scope": ["a.com"]}
    assert json.loads(_get(server, "/scope?project=2")[1]) == {"scope": ["b.com"]}


# ── Scope: enforcement wired into start_hunt_run / start_ghost_run ───────
def test_start_ghost_run_passes_project_scope_as_allowed_hosts(server, monkeypatch):
    # start_ghost_run does `from ...runner import run_investigation` and
    # `from ...config import GhostV2Config` locally on every call, so patch
    # the attributes on those modules directly (the local import resolves to
    # whatever's on the module at call time).
    import beatrix.ai.ghost2.config as config_mod
    import beatrix.ai.ghost2.core.runner as runner_mod

    captured = {}

    async def fake_run_investigation(target, **kwargs):
        captured["allowed_hosts"] = kwargs.get("allowed_hosts")
        return {"verdict": "SECURE", "final_output": ""}

    monkeypatch.setattr(runner_mod, "run_investigation", fake_run_investigation)
    monkeypatch.setattr(config_mod.GhostV2Config, "missing_key_message", lambda self: None)
    monkeypatch.setattr(config_mod.GhostV2Config, "load",
                         staticmethod(lambda: config_mod.GhostV2Config(model="openrouter/x/y", api_key="k")))

    server.projects.add_scope(1, ["example.com", "api.example.com"])
    result = server.start_ghost_run("https://example.com", "find bugs", 1)
    assert result["ok"] is True

    import time
    for _ in range(50):
        if "allowed_hosts" in captured:
            break
        time.sleep(0.05)
    assert captured["allowed_hosts"] == ["api.example.com", "example.com"]


def test_start_hunt_run_filters_out_of_scope_findings(server, monkeypatch):
    from datetime import datetime
    from types import SimpleNamespace

    from beatrix.core.types import Finding, Severity

    async def fake_hunt(self, target, preset, ai, modules, scope=None):
        in_scope_finding = Finding(
            title="SQLi", url="https://example.com/x", severity=Severity.HIGH,
            scanner_module="injection",
        )
        out_of_scope_finding = Finding(
            title="XSS", url="https://evil.com/x", severity=Severity.HIGH,
            scanner_module="injection",
        )
        self.findings = [in_scope_finding, out_of_scope_finding]
        if self._on_event:
            self._on_event("finding", {"finding": in_scope_finding})
            self._on_event("finding", {"finding": out_of_scope_finding})
        return SimpleNamespace(started_at=datetime.now(), phase_results={})

    import beatrix.core.engine as engine_mod
    monkeypatch.setattr(engine_mod.BeatrixEngine, "hunt", fake_hunt)

    server.projects.add_scope(1, ["example.com"])
    result = server.start_hunt_run("https://example.com", ["injection"], "custom", False, 1)
    assert result["ok"] is True

    import time
    broker = server.hunt_brokers.get("1")
    for _ in range(50):
        if broker is not None and broker.since(10**9)["done"]:
            break
        time.sleep(0.05)

    events = broker.since(0)["events"]
    texts = " ".join(e.get("text", "") for e in events)
    assert "Skipped out-of-scope finding" in texts
    assert "excluded from the final report" in texts
    finding_events = [e for e in events if e["type"] == "finding"]
    assert len(finding_events) == 1  # the evil.com finding never became a terminal line


# ── Stop button: cancel an in-flight Ghost/Hunt run on demand ────────────
def test_stop_ghost_run_when_nothing_running(server):
    code, r = _post(server, "/ghost/stop", {"project": 1})
    assert code == 200
    assert r["ok"] is False
    assert "no scan running" in r["error"].lower()


def test_stop_hunt_run_when_nothing_running(server):
    code, r = _post(server, "/hunt/stop", {"project": 1})
    assert code == 200
    assert r["ok"] is False
    assert "no scan running" in r["error"].lower()


def test_ghost_stop_cancels_in_flight_run(server, monkeypatch):
    import asyncio
    import time

    import beatrix.ai.ghost2.config as config_mod
    import beatrix.ai.ghost2.core.runner as runner_mod

    async def fake_run_investigation(target, **kwargs):
        await asyncio.Event().wait()  # blocks forever unless the task is cancelled

    monkeypatch.setattr(runner_mod, "run_investigation", fake_run_investigation)
    monkeypatch.setattr(config_mod.GhostV2Config, "missing_key_message", lambda self: None)
    monkeypatch.setattr(config_mod.GhostV2Config, "load",
                         staticmethod(lambda: config_mod.GhostV2Config(model="openrouter/x/y", api_key="k")))

    assert server.start_ghost_run("https://example.com", "find bugs", 1)["ok"] is True

    for _ in range(50):
        if "1" in server.ghost_tasks:
            break
        time.sleep(0.05)
    assert "1" in server.ghost_tasks

    assert server.stop_ghost_run(1) == {"ok": True}

    broker = server.ghost_brokers["1"]
    for _ in range(50):
        if broker.since(10**9)["done"]:
            break
        time.sleep(0.05)
    events = broker.since(0)["events"]
    assert events[-1]["type"] == "verdict" and events[-1]["text"] == "stopped"
    assert "1" not in server.ghost_tasks  # cleaned up after teardown


def test_hunt_stop_cancels_in_flight_run(server, monkeypatch):
    import asyncio
    import time

    from beatrix.core.types import Finding, Severity

    async def fake_hunt(self, target, preset, ai, modules, scope=None):
        self.findings = [Finding(title="partial", url=target, severity=Severity.LOW)]
        await asyncio.Event().wait()  # blocks forever unless the task is cancelled

    import beatrix.core.engine as engine_mod
    monkeypatch.setattr(engine_mod.BeatrixEngine, "hunt", fake_hunt)

    assert server.start_hunt_run("https://example.com", ["injection"], "custom", False, 1)["ok"] is True

    for _ in range(50):
        if "1" in server.hunt_tasks:
            break
        time.sleep(0.05)
    assert "1" in server.hunt_tasks

    assert server.stop_hunt_run(1) == {"ok": True}

    broker = server.hunt_brokers["1"]
    for _ in range(50):
        if broker.since(10**9)["done"]:
            break
        time.sleep(0.05)
    events = broker.since(0)["events"]
    assert events[-1]["type"] == "verdict" and events[-1]["text"] == "stopped"
    assert "1 finding" in events[-1]["detail"]
    assert "1" not in server.hunt_tasks


def test_stop_route_defaults_to_active_project(server, monkeypatch):
    import asyncio
    import time

    import beatrix.ai.ghost2.config as config_mod
    import beatrix.ai.ghost2.core.runner as runner_mod

    async def fake_run_investigation(target, **kwargs):
        await asyncio.Event().wait()

    monkeypatch.setattr(runner_mod, "run_investigation", fake_run_investigation)
    monkeypatch.setattr(config_mod.GhostV2Config, "missing_key_message", lambda self: None)
    monkeypatch.setattr(config_mod.GhostV2Config, "load",
                         staticmethod(lambda: config_mod.GhostV2Config(model="openrouter/x/y", api_key="k")))

    _post(server, "/ghost/run", {"target": "https://example.com", "project": 1})
    for _ in range(50):
        if "1" in server.ghost_tasks:
            break
        time.sleep(0.05)

    code, r = _post(server, "/ghost/stop", {})  # no project -> active project (1)
    assert code == 200 and r["ok"] is True


# ── Issues: per-project store (serialization, dedup, edit, delete) ───────
def _finding(**kw):
    from beatrix.core.types import Confidence, Finding, Severity
    defaults = dict(title="SQLi in id", severity=Severity.HIGH, confidence=Confidence.FIRM,
                    url="https://example.com/search?id=1", parameter="id", payload="1'",
                    description="classic sqli", impact="db read", remediation="parameterize",
                    evidence={"error": "SQL syntax"}, cwe_id="CWE-89",
                    references=["https://owasp.org/sqli"], scanner_module="injection",
                    request="GET /search?id=1", response="SQL error", poc_curl="curl ...",
                    reproduction_steps=["step1", "step2"], validated=True)
    defaults.update(kw)
    return Finding(**defaults)


def test_issue_serialization_full_detail(tmp_path):
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    summary = store.add_finding(1, _finding(), "injection", "hunt")
    assert summary["id"] == 1 and summary["severity"] == "high" and summary["host"] == "example.com"
    d = store.get(1, 1)
    assert d["path"] == "/search" and d["parameter"] == "id" and d["module"] == "injection"
    assert d["cwe"] == "CWE-89" and d["origin"] == "hunt" and d["validated"] is True
    # references include the finding's own + a derived CWE docs link
    assert "https://owasp.org/sqli" in d["references"]
    assert "https://cwe.mitre.org/data/definitions/89.html" in d["references"]
    # dict evidence is stringified
    assert "SQL syntax" in d["evidence"]
    assert d["reproduction_steps"] == ["step1", "step2"]


def test_issue_dedup_is_idempotent(tmp_path):
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    assert store.add_finding(1, _finding(), "injection", "hunt") is not None
    assert store.add_finding(1, _finding(), "injection", "hunt") is None  # same key -> no dup
    assert store.count(1) == 1
    # a different URL is a distinct issue
    assert store.add_finding(1, _finding(url="https://example.com/x?id=2"), "injection", "hunt") is not None
    assert store.count(1) == 2


def test_issue_update_severity_and_highlight(tmp_path):
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    store.add_finding(1, _finding(), "injection", "hunt")
    assert store.update(1, 1, severity="critical")["issue"]["severity"] == "critical"
    assert store.update(1, 1, highlight="red")["issue"]["highlight"] == "red"
    assert store.update(1, 1, highlight="none")["issue"]["highlight"] is None
    assert store.update(1, 1, severity="bogus")["ok"] is False
    assert store.update(1, 1, highlight="chartreuse")["ok"] is False
    assert store.update(1, 999, severity="low")["ok"] is False


def test_issue_edit_survives_completion_sweep(tmp_path):
    # A user re-triages an issue; a later re-add of the same finding (the Ghost
    # completion sweep, or a scanner re-emit) must NOT reset their severity.
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    store.add_finding(1, _finding(), "injection", "hunt")
    store.update(1, 1, severity="low")
    assert store.add_finding(1, _finding(), "injection", "hunt") is None
    assert store.get(1, 1)["severity"] == "low"


def test_issue_delete_and_clear(tmp_path):
    store = _IssueStore(_ProjectStore(tmp_path / "suite"))
    store.add_finding(1, _finding(), "injection", "hunt")
    store.add_finding(1, _finding(url="https://example.com/x?id=2"), "injection", "hunt")
    assert store.delete(1, 1)["ok"] is True
    assert store.delete(1, 1)["ok"] is False
    assert store.count(1) == 1
    store.clear(1)
    assert store.count(1) == 0


def test_issues_isolated_and_persisted_per_project(tmp_path):
    ps = _ProjectStore(tmp_path / "suite")
    ps.new()  # project 2
    store = _IssueStore(ps)
    store.add_finding(1, _finding(), "injection", "hunt")
    store.add_finding(2, _finding(url="https://example.com/x?id=2"), "injection", "hunt")
    assert store.count(1) == 1 and store.count(2) == 1
    # a fresh store over the same dir sees the persisted issues
    store2 = _IssueStore(ps)
    assert store2.count(1) == 1 and store2.get(1, 1)["title"] == "SQLi in id"


# ── Issues: HTTP routes ──────────────────────────────────────────────────
def test_issues_routes_empty_by_default(server):
    assert json.loads(_get(server, "/issues?project=1")[1]) == {"issues": []}
    assert json.loads(_get(server, "/issues/count?project=1")[1]) == {"count": 0}
    assert json.loads(_get(server, "/issues/detail?project=1&id=1")[1]) == {"issue": None}


def test_issues_routes_full_lifecycle(server):
    server.issues.add_finding(1, _finding(), "injection", "hunt")
    lst = json.loads(_get(server, "/issues?project=1")[1])["issues"]
    assert len(lst) == 1 and lst[0]["title"] == "SQLi in id"
    assert json.loads(_get(server, "/issues/count?project=1")[1])["count"] == 1
    detail = json.loads(_get(server, "/issues/detail?project=1&id=1")[1])["issue"]
    assert detail["remediation"] == "parameterize"

    up = _post(server, "/issues/update", {"project": 1, "id": 1, "severity": "critical", "highlight": "blue"})[1]
    assert up["ok"] is True and up["issue"]["severity"] == "critical" and up["issue"]["highlight"] == "blue"

    assert _post(server, "/issues/delete", {"project": 1, "id": 1})[1]["ok"] is True
    assert json.loads(_get(server, "/issues/count?project=1")[1])["count"] == 0


def test_issues_route_defaults_to_active_project(server):
    server.issues.add_finding(1, _finding(), "injection", "hunt")
    assert json.loads(_get(server, "/issues")[1])["issues"][0]["id"] == 1


def test_issues_clear_route(server):
    server.issues.add_finding(1, _finding(), "injection", "hunt")
    server.issues.add_finding(1, _finding(url="https://example.com/x?id=2"), "injection", "hunt")
    assert _post(server, "/issues/clear", {"project": 1})[1]["ok"] is True
    assert json.loads(_get(server, "/issues/count?project=1")[1])["count"] == 0


# ── Issues: live capture from Hunt + Ghost runs ──────────────────────────
def test_hunt_run_captures_findings_as_issues(server, monkeypatch):
    from datetime import datetime
    from types import SimpleNamespace

    from beatrix.core.types import Finding, Severity

    async def fake_hunt(self, target, preset, ai, modules, scope=None):
        f = Finding(title="Missing CSP", url="https://example.com/", severity=Severity.LOW,
                    scanner_module="headers")
        self.findings = [f]
        if self._on_event:
            self._on_event("finding", {"finding": f, "scanner": "headers"})
        return SimpleNamespace(started_at=datetime.now(), phase_results={})

    import beatrix.core.engine as engine_mod
    monkeypatch.setattr(engine_mod.BeatrixEngine, "hunt", fake_hunt)

    server.start_hunt_run("https://example.com", ["headers"], "custom", False, 1)
    import time
    for _ in range(60):
        if server.issues.count(1) >= 1:
            break
        time.sleep(0.05)
    issues = server.issues.list(1)
    assert len(issues) == 1
    assert issues[0]["title"] == "Missing CSP" and issues[0]["origin"] == "hunt"
    assert issues[0]["module"] == "headers"


def test_ghost_run_captures_findings_as_issues(server, monkeypatch):
    import beatrix.ai.ghost2.config as config_mod
    import beatrix.ai.ghost2.core.runner as runner_mod
    from beatrix.core.types import Finding, Severity

    captured_finding = Finding(title="SSRF in url param", url="https://example.com/fetch?url=x",
                               severity=Severity.HIGH, scanner_module="ghost2", parameter="url")

    async def fake_run_investigation(target, **kwargs):
        # exercise the live sink exactly like session.add_finding would
        cb = kwargs.get("on_finding")
        if cb:
            cb(captured_finding)
        return {"verdict": "VULNERABLE", "final_output": "", "findings": [captured_finding]}

    monkeypatch.setattr(runner_mod, "run_investigation", fake_run_investigation)
    monkeypatch.setattr(config_mod.GhostV2Config, "missing_key_message", lambda self: None)
    monkeypatch.setattr(config_mod.GhostV2Config, "load",
                        staticmethod(lambda: config_mod.GhostV2Config(model="openrouter/x/y", api_key="k")))

    assert server.start_ghost_run("https://example.com", "find bugs", 1)["ok"] is True
    import time
    for _ in range(60):
        if server.issues.count(1) >= 1:
            break
        time.sleep(0.05)
    # live sink + completion sweep must NOT double-count (dedup)
    issues = server.issues.list(1)
    assert len(issues) == 1
    assert issues[0]["title"] == "SSRF in url param" and issues[0]["origin"] == "ghost"


def test_ghost_session_on_finding_sink_fires():
    # The mechanism the Suite relies on: add_finding invokes session.on_finding
    # with the full Finding object (root + subagents share the session).
    import asyncio

    from beatrix.ai.ghost2.core.session import GhostSession, Scope
    from beatrix.core.types import Finding, Severity

    seen = []

    async def run():
        s = GhostSession(Scope(target="https://example.com"))
        s.on_finding = lambda f: seen.append(f)
        await s.add_finding(Finding(title="x", url="https://example.com", severity=Severity.LOW))
        # duplicate (same title+url) shouldn't fire the sink again
        await s.add_finding(Finding(title="x", url="https://example.com", severity=Severity.LOW))

    asyncio.run(run())
    assert len(seen) == 1 and seen[0].title == "x"
