#!/usr/bin/env bash
# Set GitHub repo description and topics for SEO
set -euo pipefail

REPO="SudoPacman-Syuu/Beatrix-cli"

echo "[1/3] Setting description..."
gh api "repos/$REPO" -X PATCH \
  -f description="The Black Mamba — Bug bounty hunting CLI framework. 38+ scanner modules, OWASP Top 10 coverage, Kill Chain methodology, AI-assisted pentesting, and HackerOne integration. Install globally and hunt from anywhere." \
  --silent

echo "[2/3] Setting topics..."
gh api "repos/$REPO/topics" -X PUT \
  --input - <<'EOF'
{
  "names": [
    "bug-bounty",
    "security",
    "penetration-testing",
    "vulnerability-scanner",
    "owasp",
    "cli",
    "python",
    "pentesting",
    "hacking-tool",
    "cybersecurity",
    "ethical-hacking",
    "hackerone",
    "web-security",
    "infosec",
    "recon",
    "xss",
    "sqli",
    "ssrf",
    "security-tools",
    "bug-bounty-tools"
  ]
}
EOF

echo "[3/3] Setting homepage URL..."
gh api "repos/$REPO" -X PATCH \
  -f homepage="https://github.com/SudoPacman-Syuu/Beatrix-cli#readme" \
  --silent

echo ""
echo "Done! Verify at: https://github.com/$REPO"
