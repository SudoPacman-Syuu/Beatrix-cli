"""
Tests for per-host parallel nuclei scanning (issue #9).

The nuclei wrapper used to pack every subdomain into one process sharing a
single global ``-rate-limit`` — slow for large scopes, and 429-prone if the
rate was raised. ``_run_nuclei_parallel`` now partitions targets by host and
runs several single-host nuclei processes concurrently under a semaphore.

These tests exercise the orchestration (grouping, parallelism resolution,
concurrent merge, CPU bounding, failure isolation, cancellation) with a mocked
``_run_nuclei`` so no real nuclei binary or network is needed.
"""

from __future__ import annotations

import asyncio

import pytest

from beatrix.scanners.nuclei import (
    _DEFAULT_MAX_PARALLEL_HOSTS,
    _MIN_HOST_CONCURRENCY,
    _PARALLEL_CONCURRENCY_BUDGET,
    NucleiScanner,
)


# ── host key extraction ──────────────────────────────────────────────────
def test_host_of_handles_url_hostport_and_bare():
    assert NucleiScanner._host_of("https://a.example.com/path?q=1") == "a.example.com"
    assert NucleiScanner._host_of("http://B.Example.com") == "b.example.com"
    assert NucleiScanner._host_of("redis.example.com:6379") == "redis.example.com"
    assert NucleiScanner._host_of("bare.example.com/some/path") == "bare.example.com"
    assert NucleiScanner._host_of("") == "_unknown"


def test_group_targets_by_host():
    n = NucleiScanner()
    groups = n._group_targets_by_host([
        "https://a.example.com/1",
        "https://a.example.com/2",
        "https://b.example.com/x",
        "c.example.com:6379",
        "http://c.example.com/y",
    ])
    assert set(groups) == {"a.example.com", "b.example.com", "c.example.com"}
    assert groups["a.example.com"] == ["https://a.example.com/1", "https://a.example.com/2"]
    assert len(groups["c.example.com"]) == 2


# ── parallelism resolution ───────────────────────────────────────────────
def test_resolve_parallelism_respects_config_override():
    n = NucleiScanner({"nuclei_max_parallel_hosts": 3})
    assert n._resolve_parallelism(10) == 3      # ceiling
    assert n._resolve_parallelism(2) == 2       # never more than #hosts


def test_resolve_parallelism_never_exceeds_hosts_or_ceiling():
    n = NucleiScanner()
    assert n._resolve_parallelism(1) == 1
    # Derived default is bounded by the hard ceiling regardless of CPU count.
    assert n._resolve_parallelism(1000) <= _DEFAULT_MAX_PARALLEL_HOSTS


def test_resolve_parallelism_bad_config_falls_back():
    n = NucleiScanner({"nuclei_max_parallel_hosts": "not-a-number"})
    assert n._resolve_parallelism(10) == _DEFAULT_MAX_PARALLEL_HOSTS


# ── orchestration (mocked _run_nuclei) ───────────────────────────────────
class _Finding:
    def __init__(self, host, i):
        self.host, self.i = host, i


def _install_fake_run(scanner, *, per_host=2, delay=0.01, fail_hosts=()):
    """Replace _run_nuclei with an async-gen that records concurrency/peaks."""
    state = {"running": 0, "peak": 0, "concurrency_seen": set(), "hosts": []}

    async def fake_run(host_targets, tags="", cmd_extra=None, *, concurrency=None):
        host = NucleiScanner._host_of(host_targets[0])
        state["hosts"].append(host)
        state["concurrency_seen"].add(concurrency)
        state["running"] += 1
        state["peak"] = max(state["peak"], state["running"])
        try:
            if host in fail_hosts:
                raise RuntimeError(f"boom on {host}")
            for i in range(per_host):
                await asyncio.sleep(delay)
                yield _Finding(host, i)
        finally:
            state["running"] -= 1

    scanner._run_nuclei = fake_run  # instance attribute shadows the method
    return state


def _targets(n_hosts):
    return [f"https://h{k}.example.com/p" for k in range(n_hosts)]


def test_parallel_merges_all_findings_and_caps_concurrency():
    scanner = NucleiScanner({"nuclei_max_parallel_hosts": 2})
    state = _install_fake_run(scanner, per_host=2)

    async def run():
        return [f async for f in scanner._run_nuclei_parallel(_targets(5))]

    findings = asyncio.run(run())
    assert len(findings) == 10          # 5 hosts × 2 findings each
    assert state["peak"] <= 2           # semaphore honored — CPU bounded
    # Per-process concurrency scaled to the budget, not left at the default.
    assert state["concurrency_seen"] == {max(_MIN_HOST_CONCURRENCY,
                                             _PARALLEL_CONCURRENCY_BUDGET // 2)}


def test_single_host_uses_direct_path():
    scanner = NucleiScanner()
    state = _install_fake_run(scanner, per_host=3)

    async def run():
        return [f async for f in scanner._run_nuclei_parallel(
            ["https://only.example.com/a", "https://only.example.com/b"]
        )]

    findings = asyncio.run(run())
    assert len(findings) == 3
    # Direct fallback => _run_nuclei called once with no concurrency override.
    assert state["concurrency_seen"] == {None}
    assert state["hosts"] == ["only.example.com"]


def test_one_host_failure_does_not_sink_others():
    scanner = NucleiScanner({"nuclei_max_parallel_hosts": 3})
    _install_fake_run(scanner, per_host=2, fail_hosts={"h1.example.com"})

    async def run():
        return [f async for f in scanner._run_nuclei_parallel(_targets(3))]

    findings = asyncio.run(run())
    # h1 raised; h0 and h2 still complete (2 each).
    assert len(findings) == 4
    assert {f.host for f in findings} == {"h0.example.com", "h2.example.com"}


def test_early_break_cancels_outstanding_workers():
    scanner = NucleiScanner({"nuclei_max_parallel_hosts": 4})
    state = _install_fake_run(scanner, per_host=50, delay=0.02)

    async def run():
        gen = scanner._run_nuclei_parallel(_targets(4))
        collected = []
        async for f in gen:
            collected.append(f)
            if len(collected) == 2:
                break  # consumer stops early
        # Closing the generator runs its finally: cancel outstanding workers.
        await gen.aclose()
        await asyncio.sleep(0.05)  # let cancellations propagate
        return collected

    collected = asyncio.run(run())
    assert len(collected) == 2
    # All workers wound down after the generator closed — none left running.
    assert state["running"] == 0
