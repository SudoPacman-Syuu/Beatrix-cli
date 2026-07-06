# Driving and triaging nuclei

Nuclei runs a huge library of community templates; it is excellent for breadth
but its raw output is a *lead list*, not a findings list. Every hit needs
confirmation before it is recorded — especially CVE templates, which are the
biggest source of false positives.

## Running it well
- Scope templates to the fingerprint. If recon shows the target is not
  WordPress, do not report a `wp-plugin` template hit — confirm the product is
  actually present first (a real plugin path, a version string, an admin route).
- Prefer OOB/`oast` templates for blind classes (SSRF, RCE, XXE): a real
  out-of-band callback is ground truth. A template that only matched an HTTP 200
  or a reflected string is weak on its own.
- Use severity/tags to prioritise, not to conclude. `[high]` from nuclei means
  "worth checking now," not "confirmed."

## Triage checklist (before recording)
1. **Does the product even exist here?** For any CVE/plugin template, verify the
   affected software is installed and at a vulnerable version. A template that
   fires on the generic 200 homepage is a false positive.
2. **Did the matcher prove impact or just a fingerprint?** Re-read what the
   template actually matched. "Status 200 + word in body" is a fingerprint;
   an OOB interaction or extracted secret is impact.
3. **Reproduce independently.** Replay the request yourself (http_request /
   curl). If replaying the PoC just returns the normal app response, it did not
   confirm anything.
4. **For SSRF/RCE templates, require the callback.** If the template claims OOB
   but your interaction server logged nothing, it is unconfirmed.

## Worked example (false positive)
A "Paytm Payment Gateway <= 2.7.0 SSRF" template fires with HTTP 200 on
`/?paytm_action=curltest&url=<oast>`. Before recording: the target is not
WordPress (`/wp-login.php`, `/wp-content/` both 404), no `paytm-payments` plugin
exists, replaying the URL just returns the normal homepage, and the interaction
server logged no callback. Verdict: false positive — the template matched a bare
200, not an SSRF. Drop it.
