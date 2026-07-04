"""
Browser-based auth setup for Beatrix (`beatrix auth gui`).

Codespaces / remote containers have no display, so a native desktop window
(Tkinter/Qt) can't render. Instead we start a tiny localhost web server on the
stdlib ``http.server`` — no extra dependencies — and let VS Code / Codespaces
port-forwarding surface it as a browser tab. The page lets you:

  * drag-and-drop a ``.har`` file,
  * paste a Cookie header / token / extra headers,
  * pick an IDOR user slot,

then saves through the *same* helpers the `beatrix auth import` command uses
(`_import_from_har`, `save_session`, `_save_idor_slot`), so the on-disk format
and everything downstream is identical to the CLI path.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


# ── HTML page ────────────────────────────────────────────────────────────────
# Self-contained: inline CSS + JS, theme-aware, no external requests.
_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Beatrix Auth</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --fg: #e6edf3;
    --muted: #8b949e; --accent: #2f81f7; --accent-fg: #fff;
    --ok: #3fb950; --err: #f85149; --drop: #1f6feb22;
  }
  @media (prefers-color-scheme: light) {
    :root {
      --bg: #f6f8fa; --panel: #fff; --border: #d0d7de; --fg: #1f2328;
      --muted: #656d76; --accent: #0969da; --accent-fg: #fff;
      --ok: #1a7f37; --err: #cf222e; --drop: #0969da11;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    padding: 32px 16px;
  }
  .wrap { max-width: 720px; margin: 0 auto; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .sub { color: var(--muted); margin: 0 0 24px; }
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px; margin-bottom: 18px;
  }
  label { display: block; font-weight: 600; margin-bottom: 6px; }
  .hint { color: var(--muted); font-weight: 400; font-size: 13px; }
  input[type=text], textarea {
    width: 100%; background: var(--bg); color: var(--fg);
    border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px;
    font: inherit; font-size: 14px;
  }
  textarea { resize: vertical; min-height: 84px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  input:focus, textarea:focus { outline: 2px solid var(--accent); border-color: var(--accent); }
  .row { margin-bottom: 16px; }
  .row:last-child { margin-bottom: 0; }
  #drop {
    border: 2px dashed var(--border); border-radius: 10px; padding: 28px 16px;
    text-align: center; color: var(--muted); cursor: pointer; transition: .15s;
  }
  #drop.over { border-color: var(--accent); background: var(--drop); color: var(--fg); }
  #drop b { color: var(--fg); }
  #harName { margin-top: 10px; font-size: 13px; color: var(--ok); font-weight: 600; }
  .seg { display: inline-flex; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  .seg button {
    background: var(--panel); color: var(--fg); border: 0; padding: 8px 16px;
    cursor: pointer; font: inherit; border-right: 1px solid var(--border);
  }
  .seg button:last-child { border-right: 0; }
  .seg button.on { background: var(--accent); color: var(--accent-fg); }
  .save {
    background: var(--accent); color: var(--accent-fg); border: 0; border-radius: 8px;
    padding: 12px 24px; font: inherit; font-weight: 600; cursor: pointer; width: 100%;
  }
  .save:disabled { opacity: .5; cursor: not-allowed; }
  #msg { margin-top: 14px; padding: 12px 14px; border-radius: 8px; display: none; font-size: 14px; }
  #msg.ok, #keyMsg.ok { display: block; background: var(--ok)22; border: 1px solid var(--ok); }
  #msg.err, #keyMsg.err { display: block; background: var(--err)22; border: 1px solid var(--err); }
  #msg pre { margin: 8px 0 0; white-space: pre-wrap; font-size: 13px; color: var(--muted); }
  #keyMsg { margin-top: 12px; padding: 10px 12px; border-radius: 8px; display: none; font-size: 14px; }
  .keyrow { margin-bottom: 14px; }
  .keyrow .cur { font-size: 12px; color: var(--muted); margin-left: 8px; font-family: ui-monospace, monospace; }
  .keyrow .cur.set { color: var(--ok); }
  .item {
    display: flex; align-items: center; justify-content: space-between; gap: 12px;
    padding: 12px 0; border-bottom: 1px solid var(--border);
  }
  .item:last-child { border-bottom: 0; }
  .item .meta { font-size: 13px; color: var(--muted); }
  .item .name { color: var(--fg); font-weight: 600; font-size: 15px; }
  .clr {
    background: transparent; color: var(--err); border: 1px solid var(--err);
    border-radius: 7px; padding: 6px 14px; cursor: pointer; font: inherit; font-size: 13px; white-space: nowrap;
  }
  .clr:hover { background: var(--err); color: #fff; }
  .empty { color: var(--muted); font-size: 14px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>🔐 Beatrix Auth</h1>
  <p class="sub">Set up scan credentials without touching a YAML file. Saved to <code>~/.beatrix</code>.</p>

  <div class="card">
    <div class="row">
      <label for="target">Target <span class="hint">— domain or URL you'll scan</span></label>
      <input type="text" id="target" placeholder="example.com" autocomplete="off" autofocus>
    </div>
    <div class="row">
      <label>IDOR user slot <span class="hint">— optional, for access-control testing with two accounts</span></label>
      <div class="seg" id="slot">
        <button data-slot="" class="on">None</button>
        <button data-slot="user1">user1</button>
        <button data-slot="user2">user2</button>
      </div>
    </div>
  </div>

  <div class="card">
    <label>1 · Drop a HAR file <span class="hint">— export from your browser's Network tab after logging in</span></label>
    <div id="drop">
      <b>Drag &amp; drop</b> a <code>.har</code> here, or click to browse.
      <div id="harName"></div>
    </div>
    <input type="file" id="harFile" accept=".har,application/json" style="display:none">
  </div>

  <div class="card">
    <label>2 · …or paste credentials directly <span class="hint">— use any combination below</span></label>
    <div class="row">
      <label for="cookies" style="font-weight:500">Cookie header</label>
      <textarea id="cookies" placeholder="session=abc123; csrf_token=xyz789"></textarea>
    </div>
    <div class="row">
      <label for="token" style="font-weight:500">Bearer token</label>
      <input type="text" id="token" placeholder="eyJhbGciOi... (without the 'Bearer ' prefix)" autocomplete="off">
    </div>
    <div class="row">
      <label for="headers" style="font-weight:500">Extra headers <span class="hint">— one per line, <code>Name: value</code></span></label>
      <textarea id="headers" placeholder="X-API-Key: key-123&#10;X-Tenant: acme"></textarea>
    </div>
  </div>

  <button class="save" id="save">Save credentials</button>
  <div id="msg"></div>

  <h1 style="margin-top:36px">🤖 AI provider keys</h1>
  <p class="sub">Stored in <code>~/.beatrix/.env</code> (chmod 600) and loaded automatically. Leave a field blank to keep its current value.</p>
  <div class="card">
    <div id="keyFields"></div>
    <button class="save" id="saveKeys">Save API keys</button>
    <div id="keyMsg"></div>
  </div>

  <h1 style="margin-top:36px">🗂️ Currently saved auth</h1>
  <p class="sub">Sessions and IDOR slots already on disk. Clear anything stale.</p>
  <div class="card">
    <div id="existing"><span class="hint">Loading…</span></div>
  </div>
</div>

<script>
let slot = "";
document.querySelectorAll("#slot button").forEach(b => b.onclick = () => {
  document.querySelectorAll("#slot button").forEach(x => x.classList.remove("on"));
  b.classList.add("on"); slot = b.dataset.slot;
});

const drop = document.getElementById("drop"), fileInput = document.getElementById("harFile");
let harContent = null;
drop.onclick = () => fileInput.click();
drop.ondragover = e => { e.preventDefault(); drop.classList.add("over"); };
drop.ondragleave = () => drop.classList.remove("over");
drop.ondrop = e => { e.preventDefault(); drop.classList.remove("over"); if (e.dataTransfer.files[0]) readHar(e.dataTransfer.files[0]); };
fileInput.onchange = () => { if (fileInput.files[0]) readHar(fileInput.files[0]); };
function readHar(f) {
  const r = new FileReader();
  r.onload = () => { harContent = r.result; document.getElementById("harName").textContent = "✓ " + f.name; };
  r.readAsText(f);
}

const msg = document.getElementById("msg"), save = document.getElementById("save");
save.onclick = async () => {
  const target = document.getElementById("target").value.trim();
  if (!target) { show("err", "Enter a target domain first."); return; }
  save.disabled = true; save.textContent = "Saving…";
  try {
    const res = await fetch("/api/save", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        target, slot, harContent,
        cookies: document.getElementById("cookies").value,
        token: document.getElementById("token").value.trim(),
        headers: document.getElementById("headers").value,
      }),
    });
    const data = await res.json();
    if (data.ok) {
      show("ok", data.summary, data.detail);
    } else {
      show("err", data.error || "Save failed.");
    }
  } catch (e) {
    show("err", "Request failed: " + e);
  } finally {
    save.disabled = false; save.textContent = "Save credentials";
  }
};
function show(kind, text, detail) {
  msg.className = kind;
  msg.innerHTML = text + (detail ? "<pre>" + detail.replace(/</g,"&lt;") + "</pre>" : "");
}
save.addEventListener("click", () => setTimeout(loadExisting, 300));

// ── AI provider keys ────────────────────────────────────────────────────────
const esc = s => String(s).replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
async function loadKeys() {
  const data = await (await fetch("/api/keys")).json();
  const box = document.getElementById("keyFields");
  box.innerHTML = data.keys.map(k => `
    <div class="keyrow">
      <label style="font-weight:500">${esc(k.label)}
        <span class="cur ${k.set?'set':''}">${k.set ? (k.from_env?'(from shell env) ':'') + esc(k.preview) : 'not set'}</span>
      </label>
      <input type="text" data-env="${k.env}" placeholder="${k.env}" autocomplete="off"
             style="width:100%;background:var(--bg);color:var(--fg);border:1px solid var(--border);border-radius:8px;padding:10px 12px;font:inherit;font-size:14px">
    </div>`).join("");
}
const keyMsg = document.getElementById("keyMsg"), saveKeys = document.getElementById("saveKeys");
saveKeys.onclick = async () => {
  const keys = {};
  document.querySelectorAll("#keyFields input").forEach(i => { if (i.value.trim()) keys[i.dataset.env] = i.value.trim(); });
  if (!Object.keys(keys).length) { keyMsg.className = "err"; keyMsg.textContent = "Fill in at least one key field."; return; }
  saveKeys.disabled = true; saveKeys.textContent = "Saving…";
  try {
    const data = await (await fetch("/api/keys", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({keys})})).json();
    keyMsg.className = data.ok ? "ok" : "err";
    keyMsg.textContent = data.ok ? data.summary : (data.error || "Failed.");
    if (data.ok) { document.querySelectorAll("#keyFields input").forEach(i => i.value=""); loadKeys(); }
  } finally { saveKeys.disabled = false; saveKeys.textContent = "Save API keys"; }
};

// ── Existing saved auth ─────────────────────────────────────────────────────
async function loadExisting() {
  const data = await (await fetch("/api/list")).json();
  const box = document.getElementById("existing");
  const parts = [];
  if (data.sessions && data.sessions.length) {
    parts.push(data.sessions.map(s => `
      <div class="item">
        <div><div class="name">${esc(s.domain)}</div>
          <div class="meta">${s.cookies} cookies · ${s.headers} headers${s.has_token?' · token':''} · saved ${esc(s.saved_at)} (${s.age_hours}h ago)</div></div>
        <button class="clr" data-kind="session" data-id="${esc(s.domain)}">Clear</button>
      </div>`).join(""));
  }
  if (data.idor && data.idor.length) {
    parts.push(data.idor.map(i => `
      <div class="item">
        <div><div class="name">IDOR · ${esc(i.slot)}</div>
          <div class="meta">${i.cookies} cookies · ${i.headers} headers</div></div>
        <button class="clr" data-kind="idor" data-id="${esc(i.slot)}">Clear</button>
      </div>`).join(""));
  }
  box.innerHTML = parts.length ? parts.join("") : '<div class="empty">No saved sessions or IDOR slots yet.</div>';
  box.querySelectorAll(".clr").forEach(b => b.onclick = async () => {
    b.disabled = true; b.textContent = "…";
    const body = b.dataset.kind === "session" ? {kind:"session", domain:b.dataset.id} : {kind:"idor", slot:b.dataset.id};
    await fetch("/api/clear", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body)});
    loadExisting();
  });
}

loadKeys();
loadExisting();
</script>
</body>
</html>"""


def load_beatrix_env() -> None:
    """Load ~/.beatrix/.env into os.environ without overriding existing vars.

    Called once at CLI startup so AI keys saved via the GUI take effect on the
    next `beatrix` invocation. A real shell env var always wins over the file.
    """
    env_file = Path.home() / ".beatrix" / ".env"
    if not env_file.exists():
        return
    try:
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            if k and k not in os.environ:
                os.environ[k] = v.strip()
    except OSError:
        pass


def _parse_cookie_str(s: str) -> dict:
    """Parse a `k=v; k2=v2` cookie header (possibly multi-line) into a dict."""
    out: dict = {}
    for chunk in s.replace("\n", ";").split(";"):
        chunk = chunk.strip()
        if "=" in chunk:
            k, _, v = chunk.partition("=")
            k = k.strip()
            if k:
                out[k] = v.strip()
    return out


def _parse_header_lines(s: str) -> dict:
    """Parse `Name: value` lines into a headers dict."""
    out: dict = {}
    for line in s.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, _, val = line.partition(":")
        name = name.strip()
        if name:
            out[name] = val.strip()
    return out


# AI provider keys the GUI can manage. (env var, human label, is_secret).
_AI_KEYS = [
    ("ANTHROPIC_API_KEY", "Anthropic (Claude)", True),
    ("OPENAI_API_KEY", "OpenAI", True),
    ("OPENROUTER_API_KEY", "OpenRouter", True),
    ("GEMINI_API_KEY", "Google Gemini", True),
    ("GROQ_API_KEY", "Groq", True),
    ("MISTRAL_API_KEY", "Mistral", True),
    ("LLM_API_KEY", "Generic key (LiteLLM override)", True),
    ("LLM_API_BASE", "Custom API base URL", False),
]
_ENV_FILE = Path.home() / ".beatrix" / ".env"


def _read_env_file() -> dict:
    """Parse ~/.beatrix/.env into a dict (KEY=value lines)."""
    out: dict = {}
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    return out


def _mask(val: str) -> str:
    """Mask a secret for display — show only the last 4 chars."""
    if not val:
        return ""
    return ("•" * max(0, len(val) - 4)) + val[-4:] if len(val) > 4 else "••••"


def _list_keys() -> dict:
    """Report which AI keys are set (masked), from the .env file or live env."""
    stored = _read_env_file()
    keys = []
    for env, label, is_secret in _AI_KEYS:
        val = stored.get(env) or os.environ.get(env) or ""
        keys.append({
            "env": env, "label": label, "secret": is_secret,
            "set": bool(val),
            "preview": (_mask(val) if is_secret else val) if val else "",
            "from_env": bool(not stored.get(env) and os.environ.get(env)),
        })
    return {"ok": True, "keys": keys, "path": str(_ENV_FILE)}


def _save_keys(payload: dict) -> dict:
    """Merge submitted AI keys into ~/.beatrix/.env (chmod 600).

    Blank values are ignored (leave existing untouched); the literal string
    "__CLEAR__" removes a key. Never logs or echoes the values back.
    """
    valid = {env for env, _, _ in _AI_KEYS}
    incoming = payload.get("keys") or {}
    stored = _read_env_file()

    changed = []
    for env, val in incoming.items():
        if env not in valid:
            continue
        if val == "__CLEAR__":
            if env in stored:
                del stored[env]
                changed.append(f"cleared {env}")
        elif val:  # non-empty → set; empty → leave as-is
            stored[env] = val
            changed.append(f"set {env}")

    _ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Beatrix AI provider keys — loaded automatically by the CLI.",
             "# Managed by `beatrix auth` GUI. Keep this file private."]
    lines += [f"{k}={v}" for k, v in stored.items()]
    _ENV_FILE.write_text("\n".join(lines) + "\n")
    try:
        os.chmod(_ENV_FILE, 0o600)
    except OSError:
        pass

    # Reflect immediately into this process too.
    for env, val in incoming.items():
        if env not in valid:
            continue
        if val == "__CLEAR__":
            os.environ.pop(env, None)
        elif val:
            os.environ[env] = val

    if not changed:
        return {"ok": True, "summary": "No changes — leave a field blank to keep its value."}
    return {"ok": True, "summary": f"✓ Saved to {_ENV_FILE} ({', '.join(changed)})."}


def _list_auth() -> dict:
    """Return the currently-saved auth: per-domain sessions + populated IDOR slots."""
    from beatrix.core.auto_login import list_sessions

    sessions = [
        {
            "domain": s["domain"],
            "saved_at": s.get("saved_at", ""),
            "age_hours": s.get("age_hours", 0),
            "cookies": s.get("cookies", 0),
            "headers": s.get("headers", 0),
            "has_token": s.get("has_token", False),
        }
        for s in list_sessions()
    ]

    idor = []
    auth_yaml = Path.home() / ".beatrix" / "auth.yaml"
    if auth_yaml.exists():
        try:
            import yaml
            data = yaml.safe_load(auth_yaml.read_text()) or {}
            for slot, cfg in (data.get("idor") or {}).items():
                if not cfg:  # empty placeholder — nothing to clear
                    continue
                idor.append({
                    "slot": slot,
                    "cookies": len((cfg or {}).get("cookies") or {}),
                    "headers": len((cfg or {}).get("headers") or {}),
                })
        except Exception:
            pass

    return {"ok": True, "sessions": sessions, "idor": idor}


def _clear_auth(payload: dict) -> dict:
    """Delete a saved session or an IDOR slot."""
    kind = payload.get("kind")

    if kind == "session":
        from beatrix.core.auto_login import clear_session
        domain = (payload.get("domain") or "").strip()
        if not domain:
            return {"ok": False, "error": "No domain given."}
        removed = clear_session(domain)
        return {"ok": True, "message": f"Cleared session for {domain}." if removed
                else f"No saved session for {domain}."}

    if kind == "idor":
        slot = (payload.get("slot") or "").strip()
        auth_yaml = Path.home() / ".beatrix" / "auth.yaml"
        if not auth_yaml.exists():
            return {"ok": True, "message": "No auth.yaml to clear."}
        try:
            import yaml
            data = yaml.safe_load(auth_yaml.read_text()) or {}
            idor = data.get("idor") or {}
            if slot in idor:
                idor[slot] = None  # keep the placeholder, drop the credentials
                data["idor"] = idor
                auth_yaml.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
                return {"ok": True, "message": f"Cleared IDOR slot {slot}."}
            return {"ok": True, "message": f"IDOR slot {slot} was already empty."}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": f"Could not update auth.yaml: {e}"}

    return {"ok": False, "error": f"Unknown clear kind: {kind!r}"}


def _build_and_save(payload: dict) -> dict:
    """Turn a GUI payload into a LoginResult and persist it via the CLI helpers.

    Reuses `beatrix.cli.main`'s import/save functions so the on-disk result is
    byte-for-byte what `beatrix auth import` produces. Returns a JSON-able dict.
    """
    # Imported lazily to avoid a circular import at module load (main imports us).
    from beatrix.core.auto_login import LoginResult, save_session
    from beatrix.cli import main as _main

    target = (payload.get("target") or "").strip()
    if not target:
        return {"ok": False, "error": "No target provided."}

    slot = (payload.get("slot") or "").strip()
    cookies: dict = {}
    headers: dict = {}
    token = (payload.get("token") or "").strip() or None

    # 1) HAR (if any) seeds the session via the shared parser.
    har = payload.get("harContent")
    if har:
        tmp = Path(tempfile.mkstemp(suffix=".har")[1])
        try:
            tmp.write_text(har, encoding="utf-8")
            har_result = _main._import_from_har(target, tmp)
        finally:
            tmp.unlink(missing_ok=True)
        if har_result is not None:
            cookies.update(har_result.cookies or {})
            headers.update(har_result.headers or {})
            token = token or har_result.token

    # 2) Pasted values merge on top (explicit entry wins).
    cookies.update(_parse_cookie_str(payload.get("cookies") or ""))
    headers.update(_parse_header_lines(payload.get("headers") or ""))

    if not cookies and not headers and not token:
        return {"ok": False, "error": "Nothing to save — add a HAR, cookies, a token, or headers."}

    parsed = urlparse(target if "://" in target else f"https://{target}")
    domain = parsed.netloc or target

    result = LoginResult(
        success=True,
        cookies=cookies,
        headers=headers,
        token=token,
        method_used="gui_import",
        login_url=target,
        message=f"Saved via GUI: {len(cookies)} cookies, {len(headers)} headers",
    )

    path = save_session(domain, result)
    if slot in ("user1", "user2"):
        _main._save_idor_slot(target, slot, result)

    detail_lines = [f"domain: {domain}", f"cookies: {len(cookies)}"]
    if cookies:
        detail_lines.append("cookie names: " + ", ".join(list(cookies)[:8]))
    if headers:
        detail_lines.append("headers: " + ", ".join(headers))
    if token:
        detail_lines.append(f"bearer token: {token[:36]}…")
    if slot:
        detail_lines.append(f"IDOR slot: idor.{slot} (~/.beatrix/auth.yaml)")
    detail_lines.append(f"session file: {path}")

    return {
        "ok": True,
        "summary": f"✓ Saved credentials for {domain}. Run: beatrix hunt {domain}",
        "detail": "\n".join(detail_lines),
    }


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence default stderr logging
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, _PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif self.path in ("/api/list", "/api/keys"):
            try:
                result = _list_auth() if self.path == "/api/list" else _list_keys()
            except Exception as e:  # noqa: BLE001
                result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            self._send(200, json.dumps(result).encode("utf-8"), "application/json")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        routes = {"/api/save": _build_and_save, "/api/clear": _clear_auth,
                  "/api/keys": _save_keys}
        handler = routes.get(self.path)
        if handler is None:
            self._send(404, b"not found", "text/plain")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")
            result = handler(payload)
        except Exception as e:  # noqa: BLE001 — report any failure back to the page
            result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        self._send(200, json.dumps(result).encode("utf-8"), "application/json")


def serve_auth_gui(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True):
    """Start the auth GUI server and block until Ctrl-C.

    Returns nothing; prints connection info. In Codespaces the forwarded URL is
    derived from the standard env vars so the user can click straight through.
    """
    httpd = ThreadingHTTPServer((host, port), _Handler)
    actual_port = httpd.server_address[1]
    local_url = f"http://{host}:{actual_port}/"

    # Codespaces exposes forwarded ports at <name>-<port>.<forwarding-domain>.
    codespace = os.environ.get("CODESPACE_NAME")
    fwd_domain = os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN")
    public_url = (
        f"https://{codespace}-{actual_port}.{fwd_domain}/"
        if codespace and fwd_domain else None
    )

    print("\n  Beatrix Auth GUI is running.\n")
    print(f"    Local:      {local_url}")
    if public_url:
        print(f"    Codespaces: {public_url}")
        print("    (VS Code should pop a 'Open in Browser' toast for the forwarded port.)")
    print("\n  Press Ctrl-C to stop.\n")

    if open_browser:
        # In Codespaces $BROWSER points at VS Code's helper, which opens the
        # forwarded URL in the real browser. Run in a thread so it can't block.
        threading.Thread(target=lambda: webbrowser.open(local_url), daemon=True).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Auth GUI stopped.\n")
    finally:
        httpd.server_close()
