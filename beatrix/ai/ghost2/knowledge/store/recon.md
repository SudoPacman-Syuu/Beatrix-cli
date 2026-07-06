# Reconnaissance & attack-surface mapping

Recon decides where every later test goes. The goal is not a big list of URLs —
it is an accurate map of *inputs* (params, headers, cookies, body fields, upload
points) and *trust boundaries* (auth transitions, server-to-server calls,
third-party integrations) ranked by how much damage a flaw there would do.

## What real recon produces
- **The input inventory.** Every parameter, header, and body field the app
  reads, with the endpoint and method that consume it. Injection/IDOR/SSRF all
  need a specific sink; "the site is a Next.js app" is not a sink.
- **The auth model.** How a session is established, what a token looks like,
  which endpoints are gated (401/403) vs public, and where privilege boundaries
  sit (user → admin, tenant A → tenant B). Gated endpoints that exist and return
  distinct errors are high-value — they are real functionality, just protected.
- **Server-side fetch points.** Anywhere the app takes a URL/host/file path and
  acts on it (webhooks, "import from URL", image proxies, PDF/XML processors) —
  the SSRF/XXE surface.
- **Version/framework facts that change the test**, not trophy banners. "It's
  WordPress" changes which CVEs apply; "server: cloudflare" does not.

## Method
1. Crawl to enumerate endpoints and JS bundles; pull API routes, hardcoded
   hosts, and feature flags out of the JS.
2. Fingerprint the stack only as far as it changes your plan (framework, CMS,
   proxy/CDN, language) — then confirm the fingerprint before trusting a
   version-specific CVE template. Many DAST false positives are a template that
   fired on a 200 without confirming the product is even present.
3. Probe likely-gated API paths (`/api/admin/*`, `/api/payments`, `/actuator`,
   `/.git/`, `/graphql`) and record status + error body. Distinguish "exists but
   protected" (401/403 with a real error) from "not found" (the app's 404).
4. Map auth transitions and note where to attempt IDOR, privilege escalation,
   and token manipulation later.

## Common false positives to reject
- Fingerprint-only "findings" (server header, CDN detected, cache detected)
  with no downstream impact.
- CVE-template hits against a product the target does not actually run — always
  confirm the plugin/app is present (a real path, a version string) before
  treating a version-based template as a finding.
- A 200 on an injected marketing/CMS route mistaken for a vulnerable handler.
