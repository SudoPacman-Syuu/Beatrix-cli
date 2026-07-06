"""
GHOST v2 (agent) unit tests.

Covers the M1 pieces that don't need a live LLM or network:
  * config resolution + the legacy model shim (issue #8 migration),
  * function-tool schema generation (native tool-calling replaces the old
    ``<tool_call>`` regex, so every tool must expose a valid JSON schema),
  * the finish_scan lifecycle tool and the loop-stop behavior built from it.

These require the ``[agent]`` extra (openai-agents); skipped cleanly if absent.
"""

from __future__ import annotations

import json
import os

import pytest

pytest.importorskip("agents", reason="GHOST v2 needs the [agent] extra")

from beatrix.ai.ghost2 import GhostV2Config
from beatrix.ai.ghost2.config import _normalise_model
from beatrix.ai.ghost2.core.stop import ROOT_STOP_TOOLS, root_stop_behavior
from beatrix.ai.ghost2.tools import collect_tools
from beatrix.ai.ghost2.tools.lifecycle_tools import FINISH_SCAN, finish_scan


# ── Config: legacy model shim ────────────────────────────────────────────
@pytest.mark.parametrize(
    "ai, expected",
    [
        # Legacy bare Bedrock id gets the us.anthropic inference profile prefix.
        ({"provider": "bedrock", "model": "claude-sonnet-4-20250514"},
         "bedrock/us.anthropic.claude-sonnet-4-20250514"),
        # Already an inference-profile id — only the provider prefix is added.
        ({"provider": "bedrock", "model": "us.anthropic.claude-sonnet-4-20250514-v1:0"},
         "bedrock/us.anthropic.claude-sonnet-4-20250514-v1:0"),
        ({"provider": "anthropic", "model": "claude-3-7-sonnet-latest"},
         "anthropic/claude-3-7-sonnet-latest"),
        ({"provider": "openai", "model": "gpt-4o"}, "openai/gpt-4o"),
        # Already a LiteLLM identifier — passed through verbatim (OpenRouter, #8).
        ({"model": "openrouter/anthropic/claude-3.7-sonnet"},
         "openrouter/anthropic/claude-3.7-sonnet"),
        # Empty block => no model.
        ({}, None),
    ],
)
def test_normalise_model(ai, expected):
    assert _normalise_model(ai) == expected


def test_config_load_precedence(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("ai:\n  provider: anthropic\n  model: claude-3-7-sonnet-latest\n")
    monkeypatch.delenv("BEATRIX_LLM", raising=False)

    # config.yaml wins when no CLI/env override.
    cfg = GhostV2Config.load(config_path=cfg_file)
    assert cfg.model == "anthropic/claude-3-7-sonnet-latest"

    # explicit CLI model overrides config.yaml.
    cfg = GhostV2Config.load(model="openai/gpt-4o", config_path=cfg_file)
    assert cfg.model == "openai/gpt-4o"

    # BEATRIX_LLM env overrides config.yaml (but not the CLI arg).
    monkeypatch.setenv("BEATRIX_LLM", "gemini/gemini-2.0-pro")
    cfg = GhostV2Config.load(config_path=cfg_file)
    assert cfg.model == "gemini/gemini-2.0-pro"


def test_config_key_requirements(monkeypatch):
    for var in ("LLM_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)

    # Bedrock authenticates via IAM — keyless, no missing-key message.
    bedrock = GhostV2Config(model="bedrock/us.anthropic.claude-sonnet-4-20250514-v1:0")
    assert bedrock.requires_api_key() is False
    assert bedrock.missing_key_message() is None

    # OpenAI needs a key; message names both LLM_API_KEY and the native var.
    openai = GhostV2Config(model="openai/gpt-4o")
    assert openai.requires_api_key() is True
    msg = openai.missing_key_message()
    assert msg and "LLM_API_KEY" in msg and "OPENAI_API_KEY" in msg


def test_config_provider_property():
    assert GhostV2Config(model="openrouter/anthropic/claude-3.7-sonnet").provider == "openrouter"
    assert GhostV2Config(model="bare-model-no-prefix").provider == ""


def test_max_turns_uncapped_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("BEATRIX_MAX_TURNS", raising=False)
    missing = tmp_path / "none.yaml"

    # Default: no turn cap — the agent runs until finish_scan (None => SDK
    # treats it as unlimited).
    assert GhostV2Config.load(config_path=missing).max_turns is None

    # A positive value re-imposes a cap; <=0 means uncapped.
    assert GhostV2Config.load(max_turns=50, config_path=missing).max_turns == 50
    assert GhostV2Config.load(max_turns=0, config_path=missing).max_turns is None

    # Env and yaml resolve too, CLI arg wins.
    monkeypatch.setenv("BEATRIX_MAX_TURNS", "123")
    assert GhostV2Config.load(config_path=missing).max_turns == 123
    assert GhostV2Config.load(max_turns=10, config_path=missing).max_turns == 10


# ── Tools: native schema generation ──────────────────────────────────────
def test_collect_tools_has_expected_set():
    tools = collect_tools("root")
    names = {t.name for t in tools}
    expected = {
        "http_request", "run_scanner", "inject", "encode_payload",
        "compare_responses", "record_finding", "think", "add_note",
        "add_todo", "complete_todo", "list_todos", "finish_scan",
    }
    assert expected <= names


def test_every_tool_exposes_valid_schema():
    for tool in collect_tools("root"):
        schema = tool.params_json_schema
        assert isinstance(schema, dict)
        assert schema.get("type") == "object"
        assert "properties" in schema
        assert tool.name and tool.description  # native tool-calling needs both


# ── Lifecycle + stop behavior ────────────────────────────────────────────
def test_finish_scan_tool_name_matches_constant():
    assert finish_scan.name == FINISH_SCAN == "finish_scan"


def test_root_stop_behavior_targets_finish_scan():
    assert ROOT_STOP_TOOLS == ["finish_scan"]
    behavior = root_stop_behavior()
    # StopAtTools is a TypedDict: {"stop_at_tool_names": [...]}
    assert behavior["stop_at_tool_names"] == ["finish_scan"]


def test_http_error_is_described_not_blank():
    # httpx network errors often stringify to '' — the tool must still tell the
    # agent what went wrong instead of surfacing a blank "an error occurred".
    import httpx
    from beatrix.ai.ghost2.tools.http_tools import _describe_http_error

    msg = _describe_http_error("http://x.invalid/", httpx.ConnectTimeout(""))
    assert "http://x.invalid/" in msg
    assert "ConnectTimeout" in msg
    assert "unreachable" in msg.lower()
    assert msg.strip()  # never blank


def test_finish_scan_requires_summary_arg():
    # The model must pass a summary; StopAtTools then makes it final_output.
    schema = finish_scan.params_json_schema
    assert "summary" in schema["properties"]
    assert "summary" in schema.get("required", [])


# ── M2: runtime layer + host-exec guard ──────────────────────────────────
import asyncio  # noqa: E402

from beatrix.ai.ghost2.runtime import HostExecDenied, HostRuntime, make_runtime  # noqa: E402


def test_host_runtime_refuses_exec_by_default():
    rt = HostRuntime(allow_exec=False)
    assert rt.allows_exec is False
    with pytest.raises(HostExecDenied):
        asyncio.run(rt.exec("echo hi"))
    with pytest.raises(HostExecDenied):
        asyncio.run(rt.python("print(1)"))


def test_host_runtime_runs_when_allowed():
    rt = HostRuntime(allow_exec=True)
    r = asyncio.run(rt.exec("echo hello-ghost"))
    assert r.ok and "hello-ghost" in r.stdout
    r2 = asyncio.run(rt.python("print(6*7)"))
    assert r2.ok and "42" in r2.stdout


def test_host_runtime_exec_timeout():
    rt = HostRuntime(allow_exec=True)
    r = asyncio.run(rt.exec("sleep 5", timeout=1))
    assert r.timed_out and not r.ok


def test_host_runtime_file_roundtrip():
    rt = HostRuntime(allow_exec=False)  # file I/O is not gated
    asyncio.run(rt.write_file("sub/note.txt", "payload"))
    assert asyncio.run(rt.read_file("sub/note.txt")) == "payload"


def test_make_runtime_host_mode_is_deterministic():
    # Explicit host mode never uses Docker, regardless of daemon availability.
    cfg = GhostV2Config(model="openai/gpt-4o", sandbox="host", allow_host_exec=False)
    rt = make_runtime(cfg)
    assert rt.name == "host" and rt.allows_exec is False

    cfg2 = GhostV2Config(model="openai/gpt-4o", sandbox="host", allow_host_exec=True)
    rt2 = make_runtime(cfg2)
    assert rt2.name == "host" and rt2.allows_exec is True


def test_exec_tools_offered_only_when_exec_allowed():
    from beatrix.ai.ghost2.tools import collect_tools

    no_exec = {t.name for t in collect_tools("root", allow_exec=False)}
    with_exec = {t.name for t in collect_tools("root", allow_exec=True)}
    assert "shell" not in no_exec and "python_exec" not in no_exec
    assert {"shell", "python_exec"} <= with_exec


def test_config_allow_host_exec_from_yaml(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("ai:\n  model: openai/gpt-4o\n  allow_host_exec: true\n")
    cfg = GhostV2Config.load(config_path=cfg_file)
    assert cfg.allow_host_exec is True
    # CLI flag stays authoritative when passed.
    cfg2 = GhostV2Config.load(config_path=cfg_file, allow_host_exec=False)
    assert cfg2.allow_host_exec is False


# ── M2: Docker sandbox runtime (skipped when no daemon) ──────────────────
from beatrix.ai.ghost2.runtime.dispatch import _docker_available  # noqa: E402

_DOCKER = _docker_available()
_needs_docker = pytest.mark.skipif(not _DOCKER, reason="no reachable Docker daemon")
_SANDBOX_IMAGE = "python:3.11-slim"


@_needs_docker
def test_docker_runtime_exec_and_python():
    from beatrix.ai.ghost2.runtime.sandbox import DockerRuntime

    async def run():
        rt = DockerRuntime(image=_SANDBOX_IMAGE)
        try:
            assert rt.name == "docker" and rt.allows_exec is True
            r = await rt.exec("echo sandboxed && id -u")
            assert r.ok and "sandboxed" in r.stdout
            # runs as the host uid (non-root by construction here)
            assert str(os.getuid()) in r.stdout
            p = await rt.python("print(2**10)")
            assert p.ok and "1024" in p.stdout
        finally:
            await rt.aclose()

    asyncio.run(run())


@_needs_docker
def test_docker_runtime_file_roundtrip_visible_in_container():
    from beatrix.ai.ghost2.runtime.sandbox import DockerRuntime, WORKDIR

    async def run():
        rt = DockerRuntime(image=_SANDBOX_IMAGE)
        try:
            await rt.write_file("nested/dir/note.txt", "artifact")
            # host read-back
            assert await rt.read_file("nested/dir/note.txt") == "artifact"
            # container can actually see it through the bind mount
            seen = await rt.exec(f"cat {WORKDIR}/nested/dir/note.txt")
            assert seen.ok and seen.stdout.strip() == "artifact"
        finally:
            await rt.aclose()

    asyncio.run(run())


@_needs_docker
def test_docker_runtime_timeout():
    from beatrix.ai.ghost2.runtime.sandbox import DockerRuntime

    async def run():
        rt = DockerRuntime(image=_SANDBOX_IMAGE)
        try:
            r = await rt.exec("sleep 5", timeout=1)
            assert r.timed_out and not r.ok
        finally:
            await rt.aclose()

    asyncio.run(run())


@_needs_docker
def test_make_runtime_auto_selects_docker_when_available():
    cfg = GhostV2Config(model="openai/gpt-4o", sandbox="auto", sandbox_image=_SANDBOX_IMAGE)
    rt = make_runtime(cfg)
    try:
        assert rt.name == "docker" and rt.allows_exec is True
    finally:
        asyncio.run(rt.aclose())


# ── M3: agent graph — role scoping, subagents, spawn guards, OOB ─────────
from agents.tool_context import ToolContext  # noqa: E402

from beatrix.ai.ghost2.agents.factory import build_root_agent, build_subagent  # noqa: E402
from beatrix.ai.ghost2.core.session import GhostSession, Scope  # noqa: E402


def _toolctx(session, name="t"):
    return ToolContext(context=session, tool_name=name, tool_call_id="1", tool_arguments="{}")


def test_role_tool_scoping():
    root = {t.name for t in collect_tools("root")}
    recon = {t.name for t in collect_tools("recon")}
    exploit = {t.name for t in collect_tools("exploitation")}
    valid = {t.name for t in collect_tools("validation")}

    # Only the root orchestrates + ends the whole run.
    assert "spawn_agent" in root and "finish_scan" in root
    assert "agent_finish" not in root
    # Subagents end their own loop, never spawn or finish the run.
    for s in (recon, exploit, valid):
        assert "agent_finish" in s
        assert "spawn_agent" not in s and "finish_scan" not in s
    # Recon maps surface (no exploitation/finding tools); exploitation has them.
    assert "record_finding" not in recon and "inject" not in recon
    assert {"inject", "oob_register", "record_finding"} <= exploit
    # Validation is proof-focused: OOB + diff + record, no scanner/inject.
    assert {"oob_register", "compare_responses", "record_finding"} <= valid
    assert "run_scanner" not in valid


def test_exec_tools_gated_by_role_and_capability():
    # Exec tools only for exec-capable roles, and only when allow_exec.
    assert {"shell", "python_exec"} <= {t.name for t in collect_tools("exploitation", allow_exec=True)}
    assert "shell" not in {t.name for t in collect_tools("exploitation", allow_exec=False)}
    assert "shell" not in {t.name for t in collect_tools("recon", allow_exec=True)}
    assert "shell" not in {t.name for t in collect_tools("validation", allow_exec=True)}


def test_build_subagents_and_stop_behavior():
    cfg = GhostV2Config(model="openrouter/x/y", api_key="k")
    scope = Scope(target="http://x")
    for role in ("recon", "exploitation", "validation"):
        a = build_subagent(role, scope, cfg)
        assert a.name == f"GHOST.{role}"
        assert a.tool_use_behavior["stop_at_tool_names"] == ["agent_finish"]
    # Root stops on finish_scan and can delegate.
    root = build_root_agent(scope, cfg)
    assert root.tool_use_behavior["stop_at_tool_names"] == ["finish_scan"]
    assert any(t.name == "spawn_agent" for t in root.tools)


def test_build_subagent_rejects_unknown_role():
    with pytest.raises(ValueError):
        build_subagent("banana", Scope(target="http://x"),
                       GhostV2Config(model="openrouter/x/y", api_key="k"))


def test_spawn_agent_guards():
    from beatrix.ai.ghost2.tools.graph_tools import spawn_agent

    async def run():
        s = GhostSession(Scope(target="http://x"))  # no cfg attached
        r = await spawn_agent.on_invoke_tool(_toolctx(s), '{"role":"recon","task":"go"}')
        assert "config is unavailable" in r
        s.cfg = GhostV2Config(model="openrouter/x/y", api_key="k")
        r2 = await spawn_agent.on_invoke_tool(_toolctx(s), '{"role":"bogus","task":"go"}')
        assert "Unknown role" in r2

    asyncio.run(run())


def test_oob_tools_without_server_degrade():
    from beatrix.ai.ghost2.tools.oob_tools import oob_poll, oob_register

    async def run():
        s = GhostSession(Scope(target="http://x"))  # no pocserver
        reg = await oob_register.on_invoke_tool(_toolctx(s), '{"vuln_type":"ssrf"}')
        assert "unavailable" in reg.lower()
        poll = await oob_poll.on_invoke_tool(_toolctx(s), '{"id":"abc"}')
        assert "unavailable" in poll.lower()

    asyncio.run(run())


def test_oob_callback_flow_is_ground_truth():
    import httpx

    from beatrix.ai.ghost2.tools.oob_tools import oob_poll, oob_register
    from beatrix.core.poc_server import PoCServer

    async def run():
        s = GhostSession(Scope(target="http://example.com"))
        s.pocserver = PoCServer()
        await s.pocserver.start()
        try:
            reg = await oob_register.on_invoke_tool(_toolctx(s), '{"vuln_type":"ssrf"}')
            uid = reg.split("id=", 1)[1].split("\n", 1)[0]
            url = next(l for l in reg.splitlines() if l.startswith("callback_url=")).split("=", 1)[1]

            before = await oob_poll.on_invoke_tool(_toolctx(s), '{"id":"%s"}' % uid)
            assert "No callback" in before

            async with httpx.AsyncClient() as c:  # simulate the target calling back
                await c.get(url)

            after = await oob_poll.on_invoke_tool(_toolctx(s), '{"id":"%s"}' % uid)
            assert "CALLBACK RECEIVED" in after
        finally:
            await s.pocserver.stop()

    asyncio.run(run())


# ── M4: Strix-parity gaps — budget breaker, parallel spawn, SARIF, KB ────
from types import SimpleNamespace  # noqa: E402


# ---- Config: spend guardrails + sandbox egress policy ----
def test_config_budget_and_sandbox_network(tmp_path, monkeypatch):
    for v in ("BEATRIX_MAX_BUDGET_USD", "BEATRIX_MAX_LLM_CALLS", "BEATRIX_SANDBOX_NETWORK"):
        monkeypatch.delenv(v, raising=False)
    missing = tmp_path / "none.yaml"

    # Defaults: unlimited spend, open egress.
    cfg = GhostV2Config.load(config_path=missing)
    assert cfg.max_budget_usd is None and cfg.max_llm_calls is None
    assert cfg.sandbox_network == "open"

    # config.yaml supplies all three.
    f = tmp_path / "c.yaml"
    f.write_text(
        "ai:\n  model: openai/gpt-4o\n  max_budget_usd: 2.5\n"
        "  max_llm_calls: 20\n  sandbox_network: none\n"
    )
    cfg = GhostV2Config.load(config_path=f)
    assert cfg.max_budget_usd == 2.5 and cfg.max_llm_calls == 20
    assert cfg.sandbox_network == "none"

    # Env overrides config.yaml.
    monkeypatch.setenv("BEATRIX_MAX_BUDGET_USD", "1")
    monkeypatch.setenv("BEATRIX_MAX_LLM_CALLS", "5")
    monkeypatch.setenv("BEATRIX_SANDBOX_NETWORK", "none")
    cfg = GhostV2Config.load(config_path=missing)
    assert cfg.max_budget_usd == 1.0 and cfg.max_llm_calls == 5
    assert cfg.sandbox_network == "none"

    # Invalid / non-positive values fall back to the safe defaults.
    monkeypatch.setenv("BEATRIX_MAX_BUDGET_USD", "-3")
    monkeypatch.setenv("BEATRIX_MAX_LLM_CALLS", "abc")
    monkeypatch.setenv("BEATRIX_SANDBOX_NETWORK", "banana")
    cfg = GhostV2Config.load(config_path=missing)
    assert cfg.max_budget_usd is None and cfg.max_llm_calls is None
    assert cfg.sandbox_network == "open"


# ---- Budget circuit breaker in GhostHooks ----
def _fake_llm_response(inp: int, out: int):
    return SimpleNamespace(usage=SimpleNamespace(input_tokens=inp, output_tokens=out))


def test_ghost_hooks_meters_usage():
    from beatrix.ai.ghost2.core.hooks import GhostHooks

    h = GhostHooks(model="openrouter/free/model")
    asyncio.run(h.on_llm_end(None, None, _fake_llm_response(10, 5)))
    asyncio.run(h.on_llm_end(None, None, _fake_llm_response(3, 2)))
    s = h.usage_summary()
    assert s["llm_calls"] == 2
    assert s["input_tokens"] == 13 and s["output_tokens"] == 7
    assert s["total_tokens"] == 20


def test_ghost_hooks_call_count_breaker():
    from beatrix.ai.ghost2.core.hooks import BudgetExceededError, GhostHooks

    h = GhostHooks(model="x", max_llm_calls=2)
    asyncio.run(h.on_llm_end(None, None, _fake_llm_response(1, 1)))  # call 1: ok
    with pytest.raises(BudgetExceededError):
        asyncio.run(h.on_llm_end(None, None, _fake_llm_response(1, 1)))  # call 2: stop
    assert h.llm_calls == 2


def test_ghost_hooks_cost_breaker(monkeypatch):
    import beatrix.ai.ghost2.core.hooks as hk

    monkeypatch.setattr(hk, "_estimate_cost", lambda m, i, o: 1.0)
    h = hk.GhostHooks(model="x", max_budget_usd=1.5)
    asyncio.run(h.on_llm_end(None, None, _fake_llm_response(1, 1)))  # cost 1.0 < 1.5
    with pytest.raises(hk.BudgetExceededError):
        asyncio.run(h.on_llm_end(None, None, _fake_llm_response(1, 1)))  # cost 2.0 >= 1.5


def test_estimate_cost_is_offline_safe():
    from beatrix.ai.ghost2.core.hooks import _estimate_cost

    assert _estimate_cost(None, 10, 10) == 0.0
    assert _estimate_cost("totally/made-up-model-xyz", 10, 10) == 0.0
    assert _estimate_cost("openai/gpt-4o", 0, 0) == 0.0  # no tokens => no cost


# ---- Parallel spawn (spawn_agents) ----
def test_spawn_agents_registered_with_valid_schema():
    names = {t.name for t in collect_tools("root")}
    assert "spawn_agents" in names and "spawn_agent" in names
    # subagents can neither spawn nor fan out
    for role in ("recon", "exploitation", "validation"):
        rnames = {t.name for t in collect_tools(role)}
        assert "spawn_agents" not in rnames and "spawn_agent" not in rnames


def test_spawn_agents_input_guards():
    from beatrix.ai.ghost2.tools.graph_tools import spawn_agents

    async def run():
        s = GhostSession(Scope(target="http://x"))
        s.cfg = GhostV2Config(model="openrouter/x/y", api_key="k")
        # length mismatch
        r = await spawn_agents.on_invoke_tool(
            _toolctx(s), '{"roles":["recon"],"tasks":["a","b"]}'
        )
        assert "same length" in r
        # over the parallel cap
        big = '{"roles":%s,"tasks":%s}' % (
            json.dumps(["recon"] * 6), json.dumps(["t"] * 6)
        )
        r2 = await spawn_agents.on_invoke_tool(_toolctx(s), big)
        assert "cap is" in r2

    asyncio.run(run())


def test_spawn_agents_runs_branches_concurrently(monkeypatch):
    from beatrix.ai.ghost2.tools.graph_tools import spawn_agents

    async def fake_run(agent, task, **kwargs):
        return SimpleNamespace(final_output=f"did:{task}")

    monkeypatch.setattr("agents.Runner.run", fake_run)

    async def run():
        s = GhostSession(Scope(target="http://x"))
        s.cfg = GhostV2Config(model="openrouter/x/y", api_key="k")
        r = await spawn_agents.on_invoke_tool(
            _toolctx(s),
            '{"roles":["recon","exploitation"],"tasks":["mapA","hitB"]}',
        )
        assert "did:mapA" in r and "did:hitB" in r

    asyncio.run(run())


def test_spawn_agent_propagates_budget_stop(monkeypatch):
    # A budget breaker raised inside a subagent must NOT be swallowed by the
    # spawn tool — it has to propagate so the whole run tears down.
    from beatrix.ai.ghost2.core.hooks import BudgetExceededError
    from beatrix.ai.ghost2.tools.graph_tools import spawn_agent, spawn_agents

    async def boom(agent, task, **kwargs):
        raise BudgetExceededError("over budget")

    monkeypatch.setattr("agents.Runner.run", boom)

    async def run():
        s = GhostSession(Scope(target="http://x"))
        s.cfg = GhostV2Config(model="openrouter/x/y", api_key="k")
        with pytest.raises(BudgetExceededError):
            await spawn_agent.on_invoke_tool(_toolctx(s), '{"role":"recon","task":"go"}')
        with pytest.raises(BudgetExceededError):
            await spawn_agents.on_invoke_tool(
                _toolctx(s), '{"roles":["recon"],"tasks":["go"]}'
            )

    asyncio.run(run())


def test_spawn_agent_reports_ordinary_subagent_failure(monkeypatch):
    # A normal exception inside a subagent is reported back as a string, not raised.
    from beatrix.ai.ghost2.tools.graph_tools import spawn_agent

    async def fail(agent, task, **kwargs):
        raise ValueError("boom")

    monkeypatch.setattr("agents.Runner.run", fail)

    async def run():
        s = GhostSession(Scope(target="http://x"))
        s.cfg = GhostV2Config(model="openrouter/x/y", api_key="k")
        r = await spawn_agent.on_invoke_tool(_toolctx(s), '{"role":"recon","task":"go"}')
        assert "recon subagent failed" in r and "ValueError" in r

    asyncio.run(run())


# ---- SARIF export ----
def test_build_sarif_shape_and_severity_mapping():
    from beatrix.ai.ghost2.report.sarif import build_sarif
    from beatrix.core.types import Finding, Severity

    f_crit = Finding(title="SQLi", severity=Severity.CRITICAL, cwe_id=89,
                     url="https://t/api?id=1", description="injectable id param")
    f_low = Finding(title="SQLi variant", severity=Severity.LOW, cwe_id="CWE-89",
                    url="https://t/x")
    doc = build_sarif([f_crit, f_low], target="https://t")

    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert len(run["results"]) == 2
    # Both normalise to CWE-89 => one deduped rule.
    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 1 and rules[0]["id"] == "CWE-89"
    # Severity collapses: critical->error, low->note.
    assert run["results"][0]["level"] == "error"
    assert run["results"][1]["level"] == "note"
    # GitHub code-scanning ranking property is present.
    assert rules[0]["properties"]["security-severity"] == "9.5"
    # Every result carries a location anchor (URL-based, DAST).
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_write_sarif_roundtrip(tmp_path):
    from beatrix.ai.ghost2.report.sarif import write_sarif
    from beatrix.core.types import Finding, Severity

    p = tmp_path / "findings.sarif"
    write_sarif(p, [Finding(title="XSS", severity=Severity.MEDIUM, cwe_id=79,
                            url="https://t/s")], target="https://t")
    doc = json.loads(p.read_text())
    assert doc["runs"][0]["results"][0]["level"] == "warning"  # medium


def test_build_sarif_handles_no_findings():
    from beatrix.ai.ghost2.report.sarif import build_sarif

    doc = build_sarif([], target="https://t")
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


# ---- Knowledge base: tooling/recon category expansion ----
def test_kb_resolves_new_tooling_categories():
    from beatrix.ai.ghost2.knowledge.index import get_kb

    kb = get_kb()
    assert kb.resolve("nuclei") == "nuclei"
    assert kb.resolve("reconnaissance") == "recon"
    assert kb.resolve("ffuf") == "fuzzing"
    assert kb.resolve("sqlmap") == "sqlmap"
    # The vuln rubric for sqli is still distinct from the sqlmap tooling doc.
    assert kb.resolve("sqli") == "sqli"


def test_kb_load_skill_returns_tooling_content():
    from beatrix.ai.ghost2.knowledge.index import get_kb

    kb = get_kb()
    w = kb.load_skill("nuclei")
    assert w is not None and "false positive" in w.text.lower()
    assert kb.load_skill("recon") is not None
