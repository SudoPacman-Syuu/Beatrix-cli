"""
Beatrix Suite — the central dashboard (`beatrix-suite`).

One local server, one port, one browser tab. A Burp-Suite-style top tab bar
switches between tools *inside the page* (client-side show/hide) instead of the
old "one server + one port + one new tab per tool" pattern. v1 ships two tools:

  * Auth  — the existing auth GUI, rendered inline in a same-origin ``<iframe>``
            (its ``/api/*`` calls are mounted on this same server, so the whole
            page is reused verbatim — see ``beatrix/cli/auth_gui.py``).
  * Ghost — a target/objective form that launches a GHOST v2 investigation in a
            background thread and streams its events inline (reusing the ghost
            dashboard's ``_Broker`` event model — see ``beatrix/cli/ghost_web.py``).

Everything is stdlib ``http.server`` — no web-framework dependency, same toolkit
as the two GUIs it unifies. Only one ``webbrowser.open`` ever fires, at launch.
"""

from __future__ import annotations

import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
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


# ── Shell page ───────────────────────────────────────────────────────────────
# Top tab bar (Dashboard | Auth | Ghost); panes swap client-side. Theme-aware,
# inline CSS/JS, no external requests.
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
  header .status { margin-left:auto; color:var(--muted); font-size:12px; }
  .dot { width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:6px;
    background:var(--green); vertical-align:middle; }
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
  <span class="status"><span class="dot"></span>connected</span>
</header>
<nav>
  <button data-tab="dashboard" class="active">Dashboard</button>
  <button data-tab="auth">Auth</button>
  <button data-tab="ghost">Ghost</button>
</nav>
<main>
  <section id="pane-dashboard" class="pane active">
    <div class="pad">
      <h2>Beatrix Suite</h2>
      <p class="sub">One window. Pick a tool from the tabs above — it opens right here, no new tabs.</p>
      <div class="card">
        <b>Tools</b>
        <ul style="margin:8px 0 0; padding-left:18px; color:var(--muted);">
          <li><b>Auth</b> — import cookies / tokens / HAR, manage AI keys and the ghost2 model.</li>
          <li><b>Ghost</b> — launch an autonomous GHOST v2 investigation and watch it live.</li>
        </ul>
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

// ── Ghost: launch a run, then poll its event stream inline ──
let since = 0, polling = false;
function renderEvent(ev) {
  const d = document.createElement("div");
  d.className = "ev " + ev.type;
  const tag = TAGS[ev.type] || ev.type;
  let html = `<span class="ts">${new Date(ev.ts*1000).toLocaleTimeString()}</span><span class="tag">${tag}</span>${esc(ev.text||"")}`;
  if (ev.detail) html += `<span class="detail">${esc(ev.detail)}</span>`;
  d.innerHTML = html;
  $("ghost-log").appendChild(d);
}
async function poll() {
  try {
    const r = await (await fetch("/ghost/events?since=" + since)).json();
    for (const ev of r.events) { renderEvent(ev); since = ev.seq; }
    $("ghost-log").scrollTop = $("ghost-log").scrollHeight;
    if (r.done) { polling = false; $("g-run").disabled = false; $("g-msg").textContent = "Run finished."; return; }
  } catch (e) { /* server gone — stop quietly */ }
  if (polling) setTimeout(poll, 600);
}
$("g-run").onclick = async () => {
  const target = $("g-target").value.trim();
  if (!target) { $("g-msg").textContent = "Enter a target first."; return; }
  $("g-run").disabled = true; $("g-msg").textContent = "Starting…"; $("ghost-log").innerHTML = ""; since = 0;
  try {
    const r = await (await fetch("/ghost/run", { method:"POST",
      body: JSON.stringify({ target, objective: $("g-obj").value.trim() }) })).json();
    if (!r.ok) { $("g-msg").textContent = "Error: " + (r.error || "could not start"); $("g-run").disabled = false; return; }
    $("g-msg").textContent = "Running: " + target;
    polling = true; poll();
  } catch (e) { $("g-msg").textContent = "Error: " + e; $("g-run").disabled = false; }
};
</script>
</body>
</html>"""


class SuiteServer:
    """The single central-dashboard server. One port, all tools."""

    def __init__(self, host: str = "0.0.0.0", port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None
        self.url: str = ""
        self.public_url: Optional[str] = None
        # At most one ghost run at a time in v1; its event broker lives here.
        self.ghost_broker: Optional[_Broker] = None
        self._lock = threading.Lock()

    # ── Ghost run lifecycle ──────────────────────────────────────────────
    def start_ghost_run(self, target: str, objective: str) -> Dict[str, Any]:
        """Launch a GHOST v2 investigation in a background thread.

        Returns an ack dict; run output is streamed via ``self.ghost_broker``.
        Guards the ``[agent]`` extra + missing-API-key the same way the CLI does.
        """
        target = (target or "").strip()
        if not target:
            return {"ok": False, "error": "target required"}
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
            self.ghost_broker = broker

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

    def ghost_events(self, since: int) -> Dict[str, Any]:
        b = self.ghost_broker
        return b.since(since) if b is not None else {"events": [], "done": False}

    def ghost_state(self) -> Dict[str, Any]:
        b = self.ghost_broker
        return dict(b.meta) if b is not None else {}

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
                elif path in _AUTH_GET:
                    try:
                        result = _AUTH_GET[path]()
                    except Exception as e:  # noqa: BLE001
                        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
                    self._json(result)
                elif path == "/ghost/events":
                    q = parse_qs(urlparse(self.path).query)
                    since = int((q.get("since") or ["0"])[0])
                    self._json(suite.ghost_events(since))
                elif path == "/ghost/state":
                    self._json(suite.ghost_state())
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
                    self._json(suite.start_ghost_run(
                        payload.get("target", ""), payload.get("objective", "")))
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
            import time
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
