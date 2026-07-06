"""
Regression tests for two scanner false-positive bugs found validating a live
scan of harmonic.ai (a Cloudflare/Webflow site):

1. param_miner flagged all ~500 probed parameters as HIGH "cache poisoning"
   because it compared the ``Age`` response header by equality — and ``Age``
   (seconds-in-cache) increments on essentially every request to a CDN origin.
2. The auth rate-limit test reported "missing rate limiting" against an
   endpoint that answered every request with 405 Method Not Allowed — i.e. the
   auth handler never ran, so the test proved nothing.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from beatrix.scanners.auth import AuthScanner
from beatrix.scanners.param_miner import ParamMiner


# ── param_miner: Age-header drift must not be a signal ───────────────────
def _fp(**over):
    """A baseline-ish response fingerprint; override individual fields."""
    fp = {
        "status": 200,
        "length": 346156,
        "content_type": "text/html; charset=utf-8",
        "headers_set": frozenset({"server", "age", "cf-cache-status", "content-type"}),
        "body_hash": "constanthash",
        "cache_control": "",
        "vary": "accept-encoding",
        "x_cache": "",
        "age": "357826",
        "etag": "",
        "set_cookie_names": frozenset({"_cfuvid"}),
        "body_prefix": "<!DOCTYPE html>...",
    }
    fp.update(over)
    return fp


def _calibrated(pm, baseline, second):
    """Attach the volatile-key set _get_baseline would compute."""
    baseline = dict(baseline)
    baseline["_volatile"] = frozenset(pm._responses_differ(baseline, second).keys())
    return baseline


def test_age_header_drift_is_not_a_diff():
    pm = ParamMiner()
    baseline = _calibrated(pm, _fp(age="357826"), _fp(age="357826"))
    # Later probe: only Age moved (as it does on every CDN request).
    diffs = pm._responses_differ(baseline, _fp(age="357999"))
    assert diffs == {}, f"Age drift still produces a false positive: {diffs}"


def test_age_not_in_cache_poison_classification():
    # Even if a stray cache_age key were ever produced, it must not classify
    # as CACHE_POISON on its own.
    pm = ParamMiner()
    from beatrix.scanners.param_miner import ParamType
    assert pm._classify_param("x", {"cache_age": ("1", "2")}, "https://h") != ParamType.CACHE_POISON


def test_real_cache_key_change_still_detected():
    pm = ParamMiner()
    from beatrix.scanners.param_miner import ParamType
    baseline = _calibrated(pm, _fp(), _fp())
    # A param that genuinely alters the Vary header = real cache-poisoning lead.
    diffs = pm._responses_differ(baseline, _fp(vary="accept-encoding, x-lang"))
    assert "cache_vary" in diffs
    assert pm._classify_param("lang", diffs, "https://h") == ParamType.CACHE_POISON


def test_autocalibration_suppresses_body_nonce():
    pm = ParamMiner()
    # Two identical requests already differ in body hash (per-response nonce).
    baseline = _calibrated(pm, _fp(body_hash="nonceA"), _fp(body_hash="nonceB"))
    assert "body_hash" in baseline["_volatile"]
    diffs = pm._responses_differ(baseline, _fp(body_hash="nonceC"))
    assert diffs == {}, f"body nonce leaked through as a diff: {diffs}"


def test_genuine_body_change_still_detected():
    pm = ParamMiner()
    # Stable baseline (no volatility) — a real body change must surface.
    baseline = _calibrated(pm, _fp(), _fp())
    diffs = pm._responses_differ(baseline, _fp(body_hash="totallydifferent",
                                               body_prefix="<html>new</html>"))
    assert "body_hash" in diffs


# ── auth: rate-limit test must ignore non-processing status codes ────────
def _rate_scanner(status_codes):
    scanner = AuthScanner()
    scanner.client = object()  # bypass the "no client" early return
    seq = iter(status_codes)

    async def fake_post(url, **kwargs):
        return SimpleNamespace(status_code=next(seq))

    scanner.post = fake_post
    return scanner


def test_all_405_is_not_missing_rate_limiting():
    # harmonic.ai/login answered every POST with 405 — handler never ran.
    scanner = _rate_scanner([405] * 20)
    findings = asyncio.run(scanner.test_rate_limiting("https://harmonic.ai/login"))
    assert findings == [], "405-only endpoint wrongly flagged as missing rate limiting"


def test_all_404_is_not_missing_rate_limiting():
    scanner = _rate_scanner([404] * 20)
    findings = asyncio.run(scanner.test_rate_limiting("https://h/login"))
    assert findings == []


def test_processed_unthrottled_endpoint_is_flagged():
    # 200 = login handler ran and did NOT throttle across 20 rapid tries.
    scanner = _rate_scanner([200] * 20)
    findings = asyncio.run(scanner.test_rate_limiting("https://h/login"))
    assert len(findings) == 1
    assert "Rate Limiting" in findings[0].title


def test_throttled_endpoint_is_not_flagged():
    # First few processed, then 429s kick in — rate limiting present.
    scanner = _rate_scanner([200, 200, 200] + [429] * 17)
    findings = asyncio.run(scanner.test_rate_limiting("https://h/login"))
    assert findings == []


def test_mixed_405_and_redirect_is_not_flagged():
    scanner = _rate_scanner([405, 301] * 10)
    findings = asyncio.run(scanner.test_rate_limiting("https://h/login"))
    assert findings == []
