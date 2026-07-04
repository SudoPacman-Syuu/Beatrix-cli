# GHOST v2 sandbox image.
#
# The container GHOST v2 runs shell/python_exec/external tools inside (see
# beatrix/ai/ghost2/runtime/sandbox.py::DockerRuntime). It bundles Beatrix plus
# the same external arsenal install.sh provisions, so run_external_tool and
# shell have the real binaries available without touching the host.
#
# Build:   docker build -f docker/ghost-sandbox.Dockerfile -t beatrix/ghost-sandbox:latest .
#   (or:   beatrix ghost2 --build-sandbox)
# Use:     ai.sandbox_image: beatrix/ghost-sandbox:latest   (config.yaml)
#
# The DockerRuntime also works with a plain python:3.11-slim image (its default);
# this image just adds the external tooling. Keep the tool list in sync with the
# GO_TOOLS map and apt block in install.sh.

FROM python:3.11-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    GOPATH=/opt/go \
    PATH=/opt/go/bin:/usr/local/go/bin:/usr/local/bin:$PATH

# ── System deps: build tools, nmap, sqlmap, git, and Chromium shared libs
#    (nuclei headless / Playwright need these) ────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl git build-essential \
        nmap sqlmap \
        libatk1.0-0 libatk-bridge2.0-0 libcups2 libgbm1 \
        libgtk-3-0 libnss3 libxcomposite1 libxdamage1 \
        libxfixes3 libxrandr2 libpango-1.0-0 libdrm2 \
        libxshmfence1 libxkbcommon0 libasound2 \
    && rm -rf /var/lib/apt/lists/*

# ── Go toolchain + the ProjectDiscovery / recon arsenal (matches install.sh) ─
ARG GO_VERSION=1.22.5
RUN curl -sSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
      | tar -C /usr/local -xz
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install -v github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install -v github.com/ffuf/ffuf/v2@latest \
 && go install -v github.com/hahwul/dalfox/v2@latest \
 && go install -v github.com/lc/gau/v2/cmd/gau@latest \
 && go install -v github.com/jaeles-project/gospider@latest \
 && go install -v github.com/hakluke/hakrawler@latest \
 && rm -rf /root/.cache/go-build

# ── Beatrix + the agent extra, installed into the image ──────────────────
WORKDIR /opt/beatrix
COPY pyproject.toml README.md ./
COPY beatrix ./beatrix
RUN pip install ".[agent]"

# Playwright browser (Beatrix's browser transport / auto_login use chromium)
RUN python -m playwright install chromium || true

# ── Nuclei templates (best-effort; scans still run without a fresh set) ───
RUN nuclei -update-templates >/dev/null 2>&1 || true

# Default work dir is bind-mounted by DockerRuntime at run time.
WORKDIR /work
CMD ["sleep", "infinity"]
