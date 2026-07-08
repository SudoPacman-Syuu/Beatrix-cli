"""
Beatrix Suite — the central dashboard (`beatrix-suite`).

One local server, one port, one browser tab. A Burp-Suite-style top tab bar
switches between tools *inside the page* (client-side show/hide) instead of the
old "one server + one port + one new tab per tool" pattern.

Layout:
  * Left rail  — Projects: numbered workspaces the user switches between (each
                 sections off its own scan data / scope). "+" creates a project;
                 right-click a project -> Delete.
  * Top tabs   — Tools within the active project:
      - Auth   — the existing auth GUI, rendered inline in a same-origin
                 ``<iframe>`` (its ``/api/*`` calls are mounted on this server).
      - Ghost  — a target/objective form that launches a GHOST v2 investigation
                 in a background thread and streams its events inline.

Everything is stdlib ``http.server`` — no web-framework dependency, same toolkit
as the two GUIs it unifies. Only one ``webbrowser.open`` ever fires, at launch.
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

# Reuse the auth GUI wholesale: its self-contained page + the exact backend
# functions the standalone `beatrix auth gui` uses, so saved data is identical.
from beatrix.cli.auth_gui import (
    _PAGE as _AUTH_PAGE,
    _build_and_save,
    _clear_auth,
    _get_model_settings,
    _list_auth,
    _list_keys,
    _list_openrouter_models,
    _save_keys,
    _save_model_settings,
)
# Reuse the ghost dashboard's thread-safe event ring buffer.
from beatrix.cli.ghost_web import _Broker

DEFAULT_PORT = 8790
DEFAULT_STATE_DIR = Path.home() / ".beatrix" / "suite"

# Auth route -> backend fn, mirroring auth_gui._Handler exactly.
_AUTH_GET = {
    "/api/list": _list_auth,
    "/api/keys": _list_keys,
    "/api/model": _get_model_settings,
    "/api/models": _list_openrouter_models,
}
_AUTH_POST = {
    "/api/save": _build_and_save,
    "/api/clear": _clear_auth,
    "/api/keys": _save_keys,
    "/api/model": _save_model_settings,
}


# ── Projects ─────────────────────────────────────────────────────────────────
class _ProjectStore:
    """Persistent list of projects (workspaces) the dashboard switches between.

    v1: projects are numerically labeled in creation order, persisted to
    ``<state_dir>/projects.json``; each gets its own workspace dir under
    ``<state_dir>/projects/<id>/`` (the future home for that project's scan
    data / output / scope). IDs are monotonic (never reused), so a label always
    identifies the same project even after deletions. At least one project
    always exists — deleting the last one re-seeds a fresh one.
    """

    def __init__(self, state_dir: Path):
        self.root = Path(state_dir)
        self.file = self.root / "projects.json"
        self._lock = threading.Lock()
        self.root.mkdir(parents=True, exist_ok=True)
        self._data = self._read()
        if not self._data["projects"]:
            self._create_locked()
            self._write()

    # ── persistence ──────────────────────────────────────────────────────
    def _read(self) -> Dict[str, Any]:
        try:
            d = json.loads(self.file.read_text())
            d.setdefault("projects", [])
            d.setdefault("active", None)
            d.setdefault("next_id", 1)
            return d
        except Exception:
            return {"projects": [], "active": None, "next_id": 1}

    def _write(self) -> None:
        try:
            self.file.write_text(json.dumps(self._data, indent=2))
        except Exception:
            pass

    def _proj_dir(self, pid: int) -> Path:
        return self.root / "projects" / str(pid)

    def _create_locked(self) -> Dict[str, Any]:
        """Append a new project + make it active. Caller holds the lock."""
        pid = self._data["next_id"]
        self._data["next_id"] = pid + 1
        proj = {"id": pid, "name": f"Project {pid}", "created_at": time.time()}
        self._data["projects"].append(proj)
        self._data["active"] = pid
        try:
            self._proj_dir(pid).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return proj

    # ── API ──────────────────────────────────────────────────────────────
    def state(self) -> Dict[str, Any]:
        with self._lock:
            return {"projects": list(self._data["projects"]), "active": self._data["active"]}

    def new(self) -> Dict[str, Any]:
        with self._lock:
            self._create_locked()
            self._write()
            return {"ok": True, "projects": list(self._data["projects"]),
                    "active": self._data["active"]}

    def select(self, pid: Any) -> Dict[str, Any]:
        with self._lock:
            if any(p["id"] == pid for p in self._data["projects"]):
                self._data["active"] = pid
                self._write()
                return {"ok": True, "active": pid}
            return {"ok": False, "error": "no such project"}

    def delete(self, pid: Any) -> Dict[str, Any]:
        with self._lock:
            before = len(self._data["projects"])
            self._data["projects"] = [p for p in self._data["projects"] if p["id"] != pid]
            if len(self._data["projects"]) == before:
                return {"ok": False, "error": "no such project"}
            shutil.rmtree(self._proj_dir(pid), ignore_errors=True)
            # Keep at least one project, and keep `active` valid.
            if not self._data["projects"]:
                self._create_locked()
            elif self._data["active"] == pid:
                self._data["active"] = self._data["projects"][0]["id"]
            self._write()
            return {"ok": True, "projects": list(self._data["projects"]),
                    "active": self._data["active"]}


# ── Shell page ───────────────────────────────────────────────────────────────
# Left project rail + top tab bar (Dashboard | Auth | Ghost); panes swap
# client-side. Theme-aware, inline CSS/JS, no external requests.
_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Beatrix Suite</title>
<style>
  :root { --bg:#0b0e14; --panel:#11151f; --border:#222a38; --fg:#c9d4e5; --muted:#6b7787;
    --accent:#3fd0d6; --red:#ff6b6b; --green:#5fd479; --yellow:#e5c07b; --violet:#b98cff; --blue:#5aa9ff; }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f7f9fc; --panel:#fff; --border:#dce3ec; --fg:#1f2733; --muted:#6b7787;
      --accent:#0b8a90; --red:#c0392b; --green:#1a7f37; --yellow:#8a6d1a; --violet:#7a3ff2; --blue:#0969da; } }
  * { box-sizing:border-box; }
  html, body { height:100%; }
  body { margin:0; display:flex; flex-direction:column; background:var(--bg); color:var(--fg);
    font:14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  header { display:flex; align-items:center; gap:16px; padding:10px 18px;
    background:var(--panel); border-bottom:1px solid var(--border); }
  header .t { font-weight:700; font-size:15px; }
  header .t .g { color:var(--red); }
  header .proj-label { margin-left:auto; color:var(--muted); font-size:12px; }
  header .status { color:var(--muted); font-size:12px; }
  .dot { width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:6px;
    background:var(--green); vertical-align:middle; }

  .body { flex:1; min-height:0; display:flex; }

  /* Left project rail */
  .projects { width:54px; flex-shrink:0; background:var(--panel); border-right:1px solid var(--border);
    display:flex; flex-direction:column; align-items:center; gap:6px; padding:8px 0; overflow-y:auto; }
  .proj { width:38px; height:38px; border-radius:8px; border:1px solid var(--border); background:var(--bg);
    color:var(--muted); font:inherit; font-weight:700; cursor:pointer; flex-shrink:0;
    display:flex; align-items:center; justify-content:center; }
  .proj:hover { color:var(--fg); border-color:var(--accent); }
  .proj.active { color:var(--fg); border-color:var(--accent); background:rgba(63,208,214,.12);
    box-shadow:inset 3px 0 0 var(--accent); }
  .proj.add { color:var(--muted); font-weight:400; font-size:20px; border-style:dashed; }
  .proj.add:hover { color:var(--accent); }

  .workspace { flex:1; min-width:0; display:flex; flex-direction:column; }
  nav { display:flex; gap:2px; padding:0 12px; background:var(--panel); border-bottom:1px solid var(--border); }
  nav button { font:inherit; font-size:13px; color:var(--muted); background:transparent; border:none;
    border-bottom:2px solid transparent; padding:9px 16px; cursor:pointer; }
  nav button:hover { color:var(--fg); }
  nav button.active { color:var(--fg); border-bottom-color:var(--accent); }
  main { flex:1; min-height:0; position:relative; }
  .pane { position:absolute; inset:0; display:none; overflow:auto; }
  .pane.active { display:block; }
  .pane.frame { overflow:hidden; }
  iframe { width:100%; height:100%; border:0; display:block; }

  /* Right-click context menu for project tabs */
  .ctx { position:fixed; z-index:50; display:none; background:var(--panel); border:1px solid var(--border);
    border-radius:6px; padding:4px; min-width:130px; box-shadow:0 8px 24px rgba(0,0,0,.35); }
  .ctx button { display:block; width:100%; text-align:left; font:inherit; font-size:13px; color:var(--red);
    background:transparent; border:0; padding:6px 10px; border-radius:4px; cursor:pointer; }
  .ctx button:hover { background:var(--bg); }

  .pad { padding:20px 24px; }
  h2 { font-size:16px; margin:0 0 8px; }
  p.sub { color:var(--muted); margin:0 0 18px; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:flex-end; margin-bottom:12px; }
  label { display:block; font-size:12px; color:var(--muted); margin-bottom:4px; }
  input[type=text] { font:inherit; color:var(--fg); background:var(--bg); border:1px solid var(--border);
    border-radius:6px; padding:7px 10px; min-width:280px; }
  button.run { font:inherit; color:#08131a; background:var(--accent); border:0; border-radius:6px;
    padding:8px 16px; cursor:pointer; font-weight:600; }
  button.run:disabled { opacity:.5; cursor:default; }
  #ghost-log { margin-top:14px; border-top:1px solid var(--border); padding-top:12px; }
  .ev { padding:2px 0; white-space:pre-wrap; word-break:break-word; }
  .ev .ts { color:var(--muted); margin-right:8px; font-size:12px; }
  .ev .tag { font-weight:700; margin-right:8px; }
  .ev.tool_start .tag { color:var(--yellow); } .ev.tool_end .tag { color:var(--blue); }
  .ev.agent_start .tag { color:var(--accent); } .ev.agent_end .tag { color:var(--muted); }
  .ev.reasoning .tag, .ev.thinking .tag { color:var(--violet); }
  .ev.finding .tag { color:var(--red); } .ev.verdict .tag { color:var(--green); }
  .ev .detail { display:block; color:var(--muted); margin:2px 0 2px 84px; padding:6px 9px;
    background:var(--panel); border:1px solid var(--border); border-radius:6px; max-height:220px; overflow:auto; }
  .card { border:1px solid var(--border); border-radius:8px; background:var(--panel); padding:16px 18px; max-width:640px; }
</style>
</head>
<body>
<header>
  <span class="t">👻 <span class="g">Beatrix Suite</span></span>
  <span class="proj-label" id="proj-label">—</span>
  <span class="status"><span class="dot"></span>connected</span>
</header>
<div class="body">
  <aside id="projects" class="projects"></aside>
  <div class="workspace">
    <nav>
      <button data-tab="dashboard" class="active">Dashboard</button>
      <button data-tab="auth">Auth</button>
      <button data-tab="ghost">Ghost</button>
    </nav>
    <main>
      <section id="pane-dashboard" class="pane active">
        <div class="pad">
          <h2>Beatrix Suite</h2>
          <p class="sub">Active project: <b id="dash-project">—</b> · pick a tool from the tabs above.</p>
          <div class="card">
            <b>Projects</b>
            <p style="margin:6px 0 0; color:var(--muted);">Use the left rail to switch workspaces.
              <b>+</b> creates a project; right-click a project to delete it. Each project keeps its
              own scan data and scope separate.</p>
          </div>
        </div>
      </section>

      <section id="pane-auth" class="pane frame"></section>

      <section id="pane-ghost" class="pane">
        <div class="pad">
          <h2>Ghost — autonomous investigation</h2>
          <p class="sub">Enter a target and run. Events stream below in real time.</p>
          <div class="row">
            <div><label>Target</label><input id="g-target" type="text" placeholder="https://example.com"></div>
            <div><label>Objective (optional)</label><input id="g-obj" type="text" placeholder="Find and validate security vulnerabilities."></div>
            <button id="g-run" class="run">Run</button>
          </div>
          <div id="g-msg" style="color:var(--muted); font-size:12px;"></div>
          <div id="ghost-log"></div>
        </div>
      </section>
    </main>
  </div>
</div>
<div id="ctxmenu" class="ctx"><button id="ctx-del">Delete project</button></div>
<script>
const TAGS = { thinking:"🧠 thinking", system_prompt:"📋 system", prompt:"📤 prompt",
  reasoning:"💭 reasoning", tool_start:"🔧 tool", tool_end:"↳ result", agent_start:"▶ agent",
  agent_end:"■ agent", finding:"⚑ finding", verdict:"✔ verdict", done:"● done" };
const esc = s => String(s).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const $ = id => document.getElementById(id);

// ── Tabs: swap panes in-place, never open a new tab/port ──
let authLoaded = false;
document.querySelectorAll("nav button").forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll("nav button").forEach(b => b.classList.toggle("active", b === btn));
    const tab = btn.dataset.tab;
    document.querySelectorAll(".pane").forEach(p => p.classList.toggle("active", p.id === "pane-" + tab));
    if (tab === "auth" && !authLoaded) {           // lazy-load the auth GUI iframe once
      $("pane-auth").innerHTML = '<iframe src="/auth" title="Beatrix Auth"></iframe>';
      authLoaded = true;
    }
  };
});

// ── Ghost: each project has its OWN run + event stream on the server.
// `pollProject` is the project id the in-flight poll loop belongs to; every
// poll checks it's still current before rendering or rescheduling, so a run
// left going in another project can never leak into (or get cut off by
// switching away from) the one currently on screen.
let since = 0, pollProject = null;
function renderEvent(ev) {
  const d = document.createElement("div");
  d.className = "ev " + ev.type;
  const tag = TAGS[ev.type] || ev.type;
  let html = `<span class="ts">${new Date(ev.ts*1000).toLocaleTimeString()}</span><span class="tag">${tag}</span>${esc(ev.text||"")}`;
  if (ev.detail) html += `<span class="detail">${esc(ev.detail)}</span>`;
  d.innerHTML = html;
  $("ghost-log").appendChild(d);
}
async function poll(id) {
  if (id !== pollProject) return;               // a different project is on screen now
  let r;
  try {
    r = await (await fetch("/ghost/events?since=" + since + "&project=" + id)).json();
  } catch (e) { setTimeout(() => poll(id), 600); return; }
  if (id !== pollProject) return;                // switched away while this fetch was in flight
  for (const ev of r.events) { renderEvent(ev); since = ev.seq; }
  $("ghost-log").scrollTop = $("ghost-log").scrollHeight;
  if (r.done) { $("g-run").disabled = false; $("g-msg").textContent = "Run finished."; return; }
  $("g-run").disabled = true;
  setTimeout(() => poll(id), 600);
}
// Rebuild the Ghost pane for `id`: clear the shared log DOM, then replay that
// project's own event history from the server (not from memory — the whole
// point is this survives having been switched away from) and resume polling
// if it's still running.
async function loadGhostViewFor(id) {
  $("ghost-log").innerHTML = ""; since = 0;
  pollProject = id;
  $("g-run").disabled = false; $("g-msg").textContent = "";
  let st = {};
  try { st = await (await fetch("/ghost/state?project=" + id)).json(); } catch (e) {}
  if (id !== pollProject) return;                 // switched again while loading
  if (st && st.target) {
    $("g-target").value = st.target;
    $("g-obj").value = st.objective || "";
    $("g-msg").textContent = st.running ? "Running: " + st.target : "Run finished.";
    poll(id);                                     // replays history; keeps going if still running
  } else {
    $("g-target").value = ""; $("g-obj").value = "";
  }
}
$("g-run").onclick = async () => {
  const target = $("g-target").value.trim();
  if (!target) { $("g-msg").textContent = "Enter a target first."; return; }
  $("g-run").disabled = true; $("g-msg").textContent = "Starting…";
  $("ghost-log").innerHTML = ""; since = 0; pollProject = activeProject;
  try {
    const r = await (await fetch("/ghost/run", { method:"POST",
      body: JSON.stringify({ target, objective: $("g-obj").value.trim(), project: activeProject }) })).json();
    if (!r.ok) { $("g-msg").textContent = "Error: " + (r.error || "could not start"); $("g-run").disabled = false; return; }
    $("g-msg").textContent = "Running: " + target;
    poll(activeProject);
  } catch (e) { $("g-msg").textContent = "Error: " + e; $("g-run").disabled = false; }
};

// ── Projects: left rail (switch / create / delete) ──
let projects = [], activeProject = null;
function renderProjects() {
  const rail = $("projects"); rail.innerHTML = "";
  for (const p of projects) {
    const b = document.createElement("button");
    b.className = "proj" + (p.id === activeProject ? " active" : "");
    b.textContent = p.id; b.title = p.name;
    b.onclick = () => selectProject(p.id);
    b.oncontextmenu = (e) => { e.preventDefault(); showCtx(e, p.id); };
    rail.appendChild(b);
  }
  const add = document.createElement("button");
  add.className = "proj add"; add.textContent = "+"; add.title = "New project";
  add.onclick = newProject;
  rail.appendChild(add);
  const ap = projects.find(p => p.id === activeProject);
  $("proj-label").textContent = ap ? ap.name : "—";
  $("dash-project").textContent = ap ? ap.name : "—";
}
function applyState(d) { projects = d.projects || []; activeProject = d.active; renderProjects(); }
async function loadProjects() { applyState(await (await fetch("/projects")).json()); }
async function selectProject(id) {
  if (id === activeProject) return;
  await fetch("/projects/select", { method:"POST", body: JSON.stringify({ id }) });
  activeProject = id; renderProjects(); onProjectSwitch();
}
async function newProject() {
  applyState(await (await fetch("/projects/new", { method:"POST", body:"{}" })).json());
  onProjectSwitch();
}
async function deleteProject(id) {
  const d = await (await fetch("/projects/delete", { method:"POST", body: JSON.stringify({ id }) })).json();
  if (d.ok) { applyState(d); onProjectSwitch(); }
}
function onProjectSwitch() {
  // Rebuild (never just clear) the per-project tool views from server state,
  // so a run left going in another project stays visible when you switch back.
  loadGhostViewFor(activeProject);
}

// Context menu
function showCtx(e, id) {
  const m = $("ctxmenu");
  m.style.display = "block"; m.style.left = e.clientX + "px"; m.style.top = e.clientY + "px";
  m.dataset.pid = id;
}
document.addEventListener("click", () => { $("ctxmenu").style.display = "none"; });
$("ctx-del").onclick = () => {
  const id = parseInt($("ctxmenu").dataset.pid, 10);
  $("ctxmenu").style.display = "none";
  deleteProject(id);
};

loadProjects().then(() => loadGhostViewFor(activeProject));  // restore any run in progress on load/refresh
</script>
</body>
</html>"""


class SuiteServer:
    """The single central-dashboard server. One port, all tools + projects."""

    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_PORT,
                 state_dir: Optional[Path] = None):
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None
        self.url: str = ""
        self.public_url: Optional[str] = None
        self.projects = _ProjectStore(Path(state_dir) if state_dir else DEFAULT_STATE_DIR)
        # One ghost run + event broker PER project (keyed by str(project id)), so
        # switching projects preserves each project's live run view.
        self.ghost_brokers: Dict[str, _Broker] = {}
        self._lock = threading.Lock()

    # ── Ghost run lifecycle ──────────────────────────────────────────────
    def start_ghost_run(self, target: str, objective: str, project_id: Any) -> Dict[str, Any]:
        """Launch a GHOST v2 investigation in a background thread, scoped to
        ``project_id``.

        Each project keeps its own event broker (keyed by ``str(project_id)``)
        so switching projects never loses or clobbers another project's live
        run view — that was the v1 bug: a single shared broker meant creating
        or switching to a different project blew away whatever the previous
        project's run had streamed, even though the run itself kept going.

        Returns an ack dict; run output is streamed via that project's broker.
        Guards the ``[agent]`` extra + missing-API-key the same way the CLI does.
        """
        target = (target or "").strip()
        if not target:
            return {"ok": False, "error": "target required"}

        key = str(project_id)
        with self._lock:
            existing = self.ghost_brokers.get(key)
            # since(<huge>) is a read-only way to ask "is this broker done?"
            # without reaching into _Broker's private _done attribute.
            if existing is not None and not existing.since(10**9)["done"]:
                return {"ok": False, "error": "A scan is already running for this project."}

        try:
            from beatrix.ai.ghost2.config import GhostV2Config
            from beatrix.ai.ghost2.core.runner import run_investigation
        except ImportError:
            return {"ok": False, "error": "GHOST v2 needs the 'agent' extra "
                    "(pip install 'beatrix-cli[agent]')."}

        cfg = GhostV2Config.load()
        key_hint = cfg.missing_key_message()
        if key_hint:
            return {"ok": False, "error": key_hint}

        objective = (objective or "").strip() or "Find and validate security vulnerabilities."
        broker = _Broker(meta={"target": target, "model": cfg.model,
                               "objective": objective, "auth": "none"})
        with self._lock:
            self.ghost_brokers[key] = broker

        def _run() -> None:
            import asyncio
            try:
                result = asyncio.run(run_investigation(
                    target, cfg=cfg, objective=objective,
                    on_event=broker.emit, persist=True,
                ))
                broker.emit({"type": "verdict", "text": result.get("verdict", "done"),
                             "detail": result.get("final_output") or ""})
            except Exception as e:  # noqa: BLE001 — surface any failure to the pane
                broker.emit({"type": "verdict", "text": "error",
                             "detail": f"{type(e).__name__}: {e}"})
            finally:
                broker.finish()

        threading.Thread(target=_run, daemon=True).start()
        return {"ok": True, "target": target}

    def ghost_events(self, since: int, project_id: Any) -> Dict[str, Any]:
        b = self.ghost_brokers.get(str(project_id))
        # No broker for this project => nothing has run there; report "done"
        # so a client never sits in a poll loop for a project with no run.
        return b.since(since) if b is not None else {"events": [], "done": True}

    def ghost_state(self, project_id: Any) -> Dict[str, Any]:
        b = self.ghost_brokers.get(str(project_id))
        if b is None:
            return {}
        state = dict(b.meta)
        state["running"] = not b.since(10**9)["done"]
        return state

    # ── HTTP ─────────────────────────────────────────────────────────────
    def start(self, open_browser: bool = True) -> str:
        suite = self

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, code: int, body: bytes, ctype: str):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _json(self, obj: Any):
                self._send(200, json.dumps(obj).encode("utf-8"), "application/json")

            def do_GET(self):
                path = urlparse(self.path).path
                if path in ("/", "/index.html"):
                    self._send(200, _PAGE.encode("utf-8"), "text/html; charset=utf-8")
                elif path == "/auth":
                    # Existing auth GUI, verbatim, same origin (its /api/* calls
                    # resolve to the handlers below).
                    self._send(200, _AUTH_PAGE.encode("utf-8"), "text/html; charset=utf-8")
                elif path == "/projects":
                    self._json(suite.projects.state())
                elif path in _AUTH_GET:
                    try:
                        result = _AUTH_GET[path]()
                    except Exception as e:  # noqa: BLE001
                        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                    self._json(result)
                elif path == "/ghost/events":
                    q = parse_qs(urlparse(self.path).query)
                    since = int((q.get("since") or ["0"])[0])
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.ghost_events(since, proj))
                elif path == "/ghost/state":
                    q = parse_qs(urlparse(self.path).query)
                    proj = (q.get("project") or [None])[0]
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.ghost_state(proj))
                else:
                    self._send(404, b"not found", "text/plain")

            def do_POST(self):
                path = urlparse(self.path).path
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    payload = json.loads(raw or b"{}")
                except Exception:
                    payload = {}

                if path in _AUTH_POST:
                    try:
                        result = _AUTH_POST[path](payload)
                    except Exception as e:  # noqa: BLE001
                        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                    self._json(result)
                elif path == "/ghost/run":
                    proj = payload.get("project")
                    if proj is None:
                        proj = suite.projects.state().get("active")
                    self._json(suite.start_ghost_run(
                        payload.get("target", ""), payload.get("objective", ""), proj))
                elif path == "/projects/new":
                    self._json(suite.projects.new())
                elif path == "/projects/select":
                    self._json(suite.projects.select(payload.get("id")))
                elif path == "/projects/delete":
                    self._json(suite.projects.delete(payload.get("id")))
                else:
                    self._send(404, b"not found", "text/plain")

        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port), _H)
        except OSError:
            # Port busy — fall back to an ephemeral free port rather than fail.
            self._httpd = ThreadingHTTPServer((self.host, 0), _H)
        self.port = self._httpd.server_address[1]
        display_host = "127.0.0.1" if self.host in ("0.0.0.0", "::") else self.host
        self.url = f"http://{display_host}:{self.port}/"
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

        codespace = os.environ.get("CODESPACE_NAME")
        fwd = os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN")
        if codespace and fwd:
            self.public_url = f"https://{codespace}-{self.port}.{fwd}/"

        if open_browser:
            threading.Thread(target=lambda: webbrowser.open(self.url), daemon=True).start()
        return self.url

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


def main(host: str = "0.0.0.0", port: int = DEFAULT_PORT, open_browser: bool = True) -> None:
    """Launch the Beatrix Suite dashboard and block until Ctrl-C."""
    # Load ~/.beatrix/.env so AI keys are available to the Ghost tool, matching
    # the CLI startup path.
    try:
        from beatrix.cli.auth_gui import load_beatrix_env
        load_beatrix_env()
    except Exception:
        pass

    server = SuiteServer(host=host, port=port)
    server.start(open_browser=open_browser)
    print(f"Beatrix Suite → {server.url}", flush=True)
    if server.public_url:
        print(f"   Codespaces → {server.public_url}", flush=True)
    print("Press Ctrl-C to stop.", flush=True)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
