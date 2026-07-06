"""
Live web dashboard for a GHOST v2 run (`beatrix ghost2 --web`).

Codespaces / remote containers can't pop a native window, so this starts a tiny
localhost server (stdlib ``http.server`` — no extra deps) that VS Code
port-forwards to a browser tab. The agent's hooks feed structured events into a
thread-safe ring buffer; the page polls for new events and renders them as a
live, colour-coded terminal stream so you can watch everything the agent does —
its thinking, every tool call, tool results, findings, and the final verdict.

Usage from the CLI:

    server = GhostWebServer(meta={...})
    server.start(open_browser=True)
    run_investigation(..., on_event=server.emit)
    server.finish(result)   # marks the stream complete
    server.wait()           # keep serving so the user can read the final state
"""

from __future__ import annotations

import json
import os
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GHOST v2 — live</title>
<style>
  :root {
    --bg:#0b0e14; --panel:#11151f; --border:#222a38; --fg:#c9d4e5; --muted:#6b7787;
    --cyan:#3fd0d6; --yellow:#e5c07b; --green:#5fd479; --red:#ff6b6b; --violet:#b98cff; --blue:#5aa9ff;
  }
  @media (prefers-color-scheme: light) {
    :root { --bg:#f7f9fc; --panel:#fff; --border:#dce3ec; --fg:#1f2733; --muted:#6b7787;
      --cyan:#0b8a90; --yellow:#8a6d1a; --green:#1a7f37; --red:#c0392b; --violet:#7a3ff2; --blue:#0969da; }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
    font:14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  header { position:sticky; top:0; background:var(--panel); border-bottom:1px solid var(--border);
    padding:12px 18px; display:flex; flex-wrap:wrap; gap:8px 20px; align-items:center; z-index:5; }
  header .t { font-weight:700; font-size:15px; }
  header .t .g { color:var(--red); }
  header .kv { color:var(--muted); font-size:12px; }
  header .kv b { color:var(--fg); font-weight:600; }
  .dot { width:9px; height:9px; border-radius:50%; display:inline-block; margin-right:6px; }
  .dot.run { background:var(--green); box-shadow:0 0 0 0 var(--green); animation:p 1.4s infinite; }
  .dot.done { background:var(--muted); }
  @keyframes p { 0%{box-shadow:0 0 0 0 rgba(95,212,121,.5)} 70%{box-shadow:0 0 0 7px rgba(95,212,121,0)} 100%{box-shadow:0 0 0 0 rgba(95,212,121,0)} }
  #log { padding:14px 18px 60px; }
  .ev { padding:3px 0; white-space:pre-wrap; word-break:break-word; }
  .ev .ts { color:var(--muted); margin-right:10px; font-size:12px; }
  .ev .tag { font-weight:700; margin-right:8px; }
  .ev.thinking .tag { color:var(--violet); }
  .ev.system_prompt .tag { color:var(--muted); }
  .ev.prompt .tag { color:var(--cyan); }
  .ev.reasoning .tag { color:var(--violet); }
  .ev.reasoning .detail { color:var(--fg); border-color:var(--violet); }
  .ev.tool_start .tag { color:var(--yellow); }
  .ev.tool_end .tag { color:var(--blue); }
  .ev.agent_start .tag { color:var(--cyan); }
  .ev.agent_end .tag { color:var(--muted); }
  .ev.finding .tag { color:var(--red); }
  .ev.verdict .tag, .ev.done .tag { color:var(--green); }
  .ev .detail { display:block; color:var(--muted); margin:2px 0 2px 92px; padding:8px 10px;
    background:var(--panel); border:1px solid var(--border); border-radius:6px; max-height:260px; overflow:auto; }
  .bar { position:fixed; bottom:0; left:0; right:0; background:var(--panel); border-top:1px solid var(--border);
    padding:7px 18px; color:var(--muted); font-size:12px; display:flex; gap:18px; }
  .bar b { color:var(--fg); }
  .paused { color:var(--yellow); cursor:pointer; }
  .btn { margin-left:auto; font:inherit; font-size:12px; color:var(--fg); background:var(--bg);
    border:1px solid var(--border); border-radius:6px; padding:5px 11px; cursor:pointer; }
  .btn:hover { border-color:var(--cyan); color:var(--cyan); }
  .btn:active { transform:translateY(1px); }
</style>
</head>
<body>
<header>
  <span class="t">👻 <span class="g">GHOST v2</span> — live</span>
  <span class="kv">target <b id="m-target">—</b></span>
  <span class="kv">model <b id="m-model">—</b></span>
  <span class="kv">auth <b id="m-auth">—</b></span>
  <span class="kv"><span id="dot" class="dot run"></span><b id="m-status">running</b></span>
  <button id="save" class="btn" title="Save this run as a standalone HTML file">💾 Save HTML</button>
</header>
<div id="log"></div>
<div class="bar">
  <span>events <b id="c-count">0</b></span>
  <span>tools <b id="c-tools">0</b></span>
  <span>elapsed <b id="c-elapsed">0s</b></span>
  <span id="autoscroll" class="paused" title="click to toggle">⤓ autoscroll: on</span>
</div>
<script>
const TAGS = { thinking:"🧠 thinking", system_prompt:"📋 system", prompt:"📤 prompt",
  reasoning:"💭 reasoning", tool_start:"🔧 tool", tool_end:"↳ result",
  agent_start:"▶ agent", agent_end:"■ agent", finding:"⚑ finding", verdict:"✔ verdict", done:"● done" };
const esc = s => String(s).replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
let since = 0, tools = 0, autoscroll = true, started = null, done = false;
const log = document.getElementById("log");

document.getElementById("autoscroll").onclick = () => {
  autoscroll = !autoscroll;
  document.getElementById("autoscroll").textContent = "⤓ autoscroll: " + (autoscroll ? "on" : "off");
};

// Save the current dashboard (all streamed events + metadata, fully styled)
// as a standalone HTML file for the record. The saved copy is static — the
// live-polling script and interactive controls are stripped so it renders
// stand-alone with no server.
function saveHtml() {
  const clone = document.documentElement.cloneNode(true);
  clone.querySelectorAll("script").forEach(s => s.remove());
  const rm = clone.querySelector("#save"); if (rm) rm.remove();
  const as = clone.querySelector("#autoscroll"); if (as) as.remove();
  const dot = clone.querySelector("#dot"); if (dot) dot.className = "dot done";
  const st = clone.querySelector("#m-status");
  if (st) st.textContent = (done ? "finished" : "in progress") + " · saved " + new Date().toLocaleString();
  const html = "<!doctype html>\n" + clone.outerHTML;
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  const target = (document.getElementById("m-target").textContent || "target").replace(/[^a-z0-9.\-]+/gi, "_");
  const ts = new Date().toISOString().replace(/[:]/g, "-").replace("T", "_").slice(0, 19);
  a.href = url;
  a.download = "ghost2-" + target + "-" + ts + ".html";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
document.getElementById("save").onclick = saveHtml;

async function loadMeta() {
  const m = await (await fetch("/state")).json();
  document.getElementById("m-target").textContent = m.target || "—";
  document.getElementById("m-model").textContent = m.model || "—";
  document.getElementById("m-auth").textContent = m.auth || "none";
  started = m.started;
}
function render(ev) {
  const d = document.createElement("div");
  d.className = "ev " + ev.type;
  const tag = TAGS[ev.type] || ev.type;
  let html = `<span class="ts">${new Date(ev.ts*1000).toLocaleTimeString()}</span><span class="tag">${tag}</span>${esc(ev.text||"")}`;
  if (ev.detail) html += `<span class="detail">${esc(ev.detail)}</span>`;
  d.innerHTML = html;
  log.appendChild(d);
  if (ev.type === "tool_start") { tools++; document.getElementById("c-tools").textContent = tools; }
}
async function poll() {
  try {
    const r = await (await fetch("/events?since=" + since)).json();
    for (const ev of r.events) { render(ev); since = ev.seq; }
    document.getElementById("c-count").textContent = since;
    if (r.events.length && autoscroll) window.scrollTo(0, document.body.scrollHeight);
    if (r.done && !done) {
      done = true;
      document.getElementById("dot").className = "dot done";
      document.getElementById("m-status").textContent = "finished";
    }
  } catch (e) { /* server gone — stop politely */ }
  if (started) document.getElementById("c-elapsed").textContent =
    Math.round(Date.now()/1000 - started) + "s";
  setTimeout(poll, done ? 2000 : 600);
}
loadMeta().then(poll);
</script>
</body>
</html>"""


class _Broker:
    """Thread-safe event ring buffer shared between the run and HTTP handlers."""

    def __init__(self, meta: Dict[str, Any], maxlen: int = 5000):
        self._lock = threading.Lock()
        self._events: List[Dict[str, Any]] = []
        self._seq = 0
        self._maxlen = maxlen
        self._done = False
        self.meta = dict(meta)
        self.meta.setdefault("started", time.time())

    def emit(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self._seq += 1
            rec = {
                "seq": self._seq,
                "ts": time.time(),
                "type": event.get("type", "log"),
                "text": event.get("text", ""),
                "detail": event.get("detail", ""),
            }
            self._events.append(rec)
            if len(self._events) > self._maxlen:
                self._events = self._events[-self._maxlen:]

    def since(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            evs = [e for e in self._events if e["seq"] > seq]
            return {"events": evs, "done": self._done}

    def finish(self) -> None:
        with self._lock:
            self._done = True


class GhostWebServer:
    """Serves the live dashboard for one GHOST v2 run.

    Binds ``0.0.0.0`` by default, not ``127.0.0.1`` — Codespaces' port-forwarding
    tunnel can't reach a loopback-only listener (it connects from outside the
    process's own network namespace), which silently surfaces as a 404 from
    the tunnel relay with no indication the bind address was the problem. The
    printed/opened "local" URL still shows 127.0.0.1 for a clean local link.
    """

    def __init__(self, meta: Optional[Dict[str, Any]] = None,
                 host: str = "0.0.0.0", port: int = 8799):
        self.broker = _Broker(meta or {})
        self.host = host
        self.port = port
        self._httpd: Optional[ThreadingHTTPServer] = None
        self.url: Optional[str] = None
        self.public_url: Optional[str] = None

    # The hooks call this for every agent event.
    def emit(self, event: Dict[str, Any]) -> None:
        self.broker.emit(event)

    def finish(self, result: Optional[Dict[str, Any]] = None) -> None:
        if result:
            verdict = result.get("verdict") or ("findings recorded"
                      if result.get("findings") else "no findings")
            self.broker.emit({"type": "verdict", "text": str(verdict),
                              "detail": result.get("summary", "")})
        self.broker.finish()

    def start(self, open_browser: bool = True) -> str:
        broker = self.broker

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, code, body, ctype):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urlparse(self.path).path
                if path in ("/", "/index.html"):
                    self._send(200, _PAGE.encode(), "text/html; charset=utf-8")
                elif path == "/state":
                    self._send(200, json.dumps(broker.meta).encode(), "application/json")
                elif path == "/events":
                    q = parse_qs(urlparse(self.path).query)
                    since = int((q.get("since") or ["0"])[0])
                    self._send(200, json.dumps(broker.since(since)).encode(), "application/json")
                else:
                    self._send(404, b"not found", "text/plain")

        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port), _H)
        except OSError:
            # Port busy (e.g. a previous dashboard or a concurrent scan) — since
            # the dashboard is automatic, fall back to an ephemeral free port
            # rather than failing the run.
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

    def wait(self) -> None:
        """Block until Ctrl-C so the user can keep reading after the run ends."""
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
