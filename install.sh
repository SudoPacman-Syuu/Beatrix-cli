#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  BEATRIX CLI — The Black Mamba
#  One-command installer for Linux systems
#
#  Usage:
#    git clone https://github.com/SudoPacman-Syuu/Beatrix-cli.git && cd Beatrix-cli && ./install.sh
#
#  Or:
#    curl -sSL https://raw.githubusercontent.com/SudoPacman-Syuu/Beatrix-cli/main/install.sh | bash
#
#  "Those of you lucky enough to have your lives, take them with you."
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

MIN_PYTHON="3.11"
INSTALL_DIR="${BEATRIX_INSTALL_DIR:-/usr/local/bin}"
VENV_DIR="${BEATRIX_VENV:-$HOME/.beatrix}"

# ── Banner ───────────────────────────────────────────────────

banner() {
    echo -e "${YELLOW}"
    cat <<'EOF'
    ____             __       _     
   / __ )___  ____ _/ /______(_)  __
  / __  / _ \/ __ `/ __/ ___/ / |/_/
 / /_/ /  __/ /_/ / /_/ /  / />  <  
/_____/\___/\__,_/\__/_/  /_/_/|_|  
EOF
    echo -e "${RESET}"
    echo -e "${DIM}The Black Mamba — Installer${RESET}"
    echo ""
}

# ── Helpers ──────────────────────────────────────────────────

info()    { echo -e "  ${CYAN}▸${RESET} $1"; }
success() { echo -e "  ${GREEN}✓${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET} $1"; }
fail()    { echo -e "  ${RED}✗${RESET} $1"; exit 1; }

command_exists() { command -v "$1" &>/dev/null; }

version_gte() {
    # Returns 0 if $1 >= $2 (semver-ish comparison)
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# ── Checks ───────────────────────────────────────────────────

check_python() {
    local py=""

    # Dynamically discover all python3.X binaries on PATH (future-proof)
    local candidates=()
    for p in $(compgen -c python3. 2>/dev/null | sort -t. -k2 -rn | uniq); do
        # Only match python3.NN patterns (not python3.11-config etc.)
        if [[ "$p" =~ ^python3\.[0-9]+$ ]]; then
            candidates+=("$p")
        fi
    done
    # Always include generic python3 as fallback
    candidates+=("python3")

    for candidate in "${candidates[@]}"; do
        if command_exists "$candidate"; then
            local ver
            ver="$($candidate --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)"
            if version_gte "$ver" "$MIN_PYTHON"; then
                py="$candidate"
                break
            fi
        fi
    done

    if [[ -z "$py" ]]; then
        fail "Python >= $MIN_PYTHON is required. Install it first:
         ${DIM}sudo apt install python3  # Debian/Ubuntu
         sudo dnf install python3   # Fedora
         sudo pacman -S python      # Arch${RESET}"
    fi

    PYTHON="$py"
    PYTHON_VERSION="$($PYTHON --version 2>&1)"
    success "Found $PYTHON_VERSION"
}

check_pip() {
    # pip is only needed as a fallback. With uv/venv, the venv has its own pip.
    if $PYTHON -m pip --version &>/dev/null; then
        success "pip available"
    elif $PYTHON -m ensurepip --upgrade 2>/dev/null; then
        success "pip installed via ensurepip"
    else
        warn "pip not available (not critical — uv/venv installs don't need system pip)"
    fi
}

# ── Install Methods ──────────────────────────────────────────
# Order of preference: uv → venv → pipx → pip --user
# System-level pip install removed — it conflicts with PEP 668
# (externally managed environments) on modern distros.

# ── Preferred: uv-based install (fastest, most reliable) ──

install_with_uv() {
    info "Installing with uv (fast Python package manager)..."

    if ! command_exists uv; then
        info "Installing uv..."
        curl -LsSf https://astral.sh/uv/install.sh 2>/dev/null | sh 2>/dev/null || \
            { warn "Could not install uv, falling back to venv"; return 1; }
        export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    fi

    if ! command_exists uv; then
        warn "uv not found after install, falling back to venv"
        return 1
    fi

    # Create/recreate venv
    if [[ -d "$VENV_DIR" ]]; then
        rm -rf "$VENV_DIR"
    fi

    uv venv "$VENV_DIR" --python "$PYTHON" || { warn "uv venv creation failed"; return 1; }
    uv pip install --python "$VENV_DIR/bin/python" ".[extended]" 2>/dev/null || \
        uv pip install --python "$VENV_DIR/bin/python" . || \
        { warn "uv install failed, falling back to venv"; return 1; }

    # Install a sudo-compatible wrapper script (not a symlink)
    _install_wrapper "$VENV_DIR"

    success "Installed to $VENV_DIR with wrapper at $INSTALL_DIR/beatrix (via uv)"
    return 0
}

# ── Reliable fallback: venv (always works, fully isolated) ──

install_with_venv() {
    info "Installing into isolated venv at $VENV_DIR..."

    # Create/recreate venv
    if [[ -d "$VENV_DIR" ]]; then
        info "Removing existing venv at $VENV_DIR"
        rm -rf "$VENV_DIR"
    fi

    $PYTHON -m venv "$VENV_DIR" || fail "Failed to create venv. Install python3-venv:
         ${DIM}sudo apt install python3-venv  # Debian/Ubuntu
         sudo dnf install python3-libs   # Fedora${RESET}"

    # Upgrade pip inside the venv
    "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel &>/dev/null

    # Install Beatrix with extended deps where possible
    "$VENV_DIR/bin/pip" install ".[extended]" 2>/dev/null || \
        "$VENV_DIR/bin/pip" install . || \
        fail "Failed to install Beatrix into venv"

    # Install a sudo-compatible wrapper script (not a symlink)
    _install_wrapper "$VENV_DIR"

    success "Installed to $VENV_DIR with wrapper at $INSTALL_DIR/beatrix"
    return 0
}

# ── Alternative: pipx install ──

install_with_pipx() {
    info "Installing with pipx (isolated environment)..."

    if ! command_exists pipx; then
        info "Installing pipx first..."
        $PYTHON -m pip install --user --break-system-packages pipx 2>/dev/null || \
            $PYTHON -m pip install --user pipx 2>/dev/null || \
            sudo $PYTHON -m pip install --break-system-packages pipx 2>/dev/null || \
            sudo $PYTHON -m pip install pipx 2>/dev/null || \
            { warn "Could not install pipx"; return 1; }
        $PYTHON -m pipx ensurepath 2>/dev/null || true
    fi

    pipx install --force ".[extended]" || pipx install --force . || return 1
    success "Installed via pipx"
    return 0
}

# ── Last resort: pip --user ──

install_with_pip_user() {
    info "Installing with pip (user-level)..."
    $PYTHON -m pip install --user --break-system-packages ".[extended]" 2>/dev/null || \
        $PYTHON -m pip install --user --break-system-packages . 2>/dev/null || \
        $PYTHON -m pip install --user . 2>/dev/null || \
        { warn "pip user install failed"; return 1; }

    # Ensure ~/.local/bin is on PATH
    local user_bin="$HOME/.local/bin"
    if [[ ":$PATH:" != *":$user_bin:"* ]]; then
        warn "$user_bin is not on your PATH"
        _add_to_path "$user_bin"
    fi

    # Install sudo-compatible wrapper (user-level needs PYTHONPATH)
    _install_wrapper_user

    success "Installed via pip (user) with sudo wrapper at $INSTALL_DIR/beatrix"
    return 0
}

# ── Wrapper script (sudo-compatible) ─────────────────────────
# Instead of a symlink to the venv entrypoint (which breaks under
# sudo because root has a different PATH/home), we install a small
# shell wrapper that hardcodes the absolute path to the venv Python.
# This means `sudo beatrix` works out of the box — critical for
# nmap SYN scans, scapy probes, and other root-requiring operations.

# Write one wrapper file: _put_wrapper <path> <content>
_put_wrapper() {
    local wrapper="$1"; local content="$2"
    if [[ -w "$INSTALL_DIR" ]]; then
        echo "$content" > "$wrapper"
        chmod +x "$wrapper"
    else
        echo "$content" | sudo tee "$wrapper" > /dev/null
        sudo chmod +x "$wrapper"
    fi
}

_install_wrapper() {
    local venv="$1"
    local venv_python="$venv/bin/python"

    # Resolve the absolute path (handle ~ and relative paths)
    venv_python="$(cd "$(dirname "$venv_python")" && pwd)/$(basename "$venv_python")"

    local header="#!/usr/bin/env bash
# BEATRIX CLI wrapper — auto-generated by install.sh
# Uses the venv Python so 'sudo beatrix' works without reinstalling.

# Preserve invoking user's HOME so ~/.beatrix config is found under sudo
if [ -n \"\$SUDO_USER\" ]; then
    export HOME=\$(getent passwd \"\$SUDO_USER\" | cut -d: -f6)
fi
"

    # `beatrix` -> the Click CLI; `beatrix-suite` -> the central dashboard.
    _put_wrapper "$INSTALL_DIR/beatrix" \
        "$header
exec \"$venv_python\" -W ignore::RuntimeWarning -m beatrix.cli.main \"\$@\"
"
    _put_wrapper "$INSTALL_DIR/beatrix-suite" \
        "$header
exec \"$venv_python\" -W ignore::RuntimeWarning -m beatrix.cli.main suite \"\$@\"
"
}

# ── Wrapper for pip --user / editable installs (no venv) ─────
# When installed with pip --user or pip -e, root can't find the
# package because user site-packages aren't on root's sys.path.
# This wrapper sets PYTHONPATH to include both the project dir
# and the user's site-packages so all dependencies resolve.

_install_wrapper_user() {
    local py_exe
    py_exe="$(command -v $PYTHON)"
    py_exe="$(readlink -f "$py_exe")"

    # Detect user site-packages and project root
    local user_site
    user_site="$($PYTHON -c 'import site; print(site.getusersitepackages())')"
    local project_dir
    project_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

    local header="#!/usr/bin/env bash
# BEATRIX CLI wrapper — sudo-compatible (user-level install)
# Sets PYTHONPATH so root's Python finds beatrix + dependencies.
# Auto-generated by install.sh. Regenerate with: ./install.sh

# Preserve invoking user's HOME so ~/.beatrix config is found under sudo
if [ -n \"\$SUDO_USER\" ]; then
    export HOME=\$(getent passwd \"\$SUDO_USER\" | cut -d: -f6)
fi

export PYTHONPATH=\"$project_dir:$user_site\${PYTHONPATH:+:\$PYTHONPATH}\"
"

    _put_wrapper "$INSTALL_DIR/beatrix" \
        "$header
exec \"$py_exe\" -W ignore::RuntimeWarning -m beatrix.cli.main \"\$@\"
"
    _put_wrapper "$INSTALL_DIR/beatrix-suite" \
        "$header
exec \"$py_exe\" -W ignore::RuntimeWarning -m beatrix.cli.main suite \"\$@\"
"
}

# ── PATH helper ──────────────────────────────────────────────

_add_to_path() {
    local dir="$1"
    local shell_rc=""

    if [[ -f "$HOME/.zshrc" ]]; then
        shell_rc="$HOME/.zshrc"
    elif [[ -f "$HOME/.bashrc" ]]; then
        shell_rc="$HOME/.bashrc"
    elif [[ -f "$HOME/.profile" ]]; then
        shell_rc="$HOME/.profile"
    fi

    if [[ -n "$shell_rc" ]]; then
        if ! grep -q "$dir" "$shell_rc" 2>/dev/null; then
            echo "" >> "$shell_rc"
            echo "# Beatrix CLI" >> "$shell_rc"
            echo "export PATH=\"$dir:\$PATH\"" >> "$shell_rc"
            info "Added $dir to PATH in $shell_rc"
            info "Run: ${BOLD}source $shell_rc${RESET} or restart your terminal"
        fi
    fi
}

# ── Package Manager Detection ────────────────────────────────

detect_pkg_manager() {
    if command_exists apt-get; then
        PKG_MGR="apt"
    elif command_exists dnf; then
        PKG_MGR="dnf"
    elif command_exists pacman; then
        PKG_MGR="pacman"
    elif command_exists apk; then
        PKG_MGR="apk"
    else
        PKG_MGR="unknown"
    fi
}

pkg_install() {
    local pkg="$1"
    case "$PKG_MGR" in
        apt)    sudo apt-get install -y -qq "$pkg" 2>/dev/null ;;
        dnf)    sudo dnf install -y -q "$pkg" 2>/dev/null ;;
        pacman) sudo pacman -S --noconfirm --needed "$pkg" 2>/dev/null ;;
        apk)    sudo apk add --quiet "$pkg" 2>/dev/null ;;
        *)      return 1 ;;
    esac
}

# ── Go Toolchain ─────────────────────────────────────────────

ensure_go() {
    if command_exists go; then
        success "Go already installed ($(go version | grep -oP 'go\d+\.\d+\.\d+'))"
        return 0
    fi

    info "Installing Go toolchain..."
    local GO_VERSION
    GO_VERSION=$(curl -sSL "https://go.dev/VERSION?m=text" 2>/dev/null | head -1 | sed 's/^go//' | tr -d '[:space:]')
    [[ -z "$GO_VERSION" || ! "$GO_VERSION" =~ ^[0-9]+\.[0-9] ]] && GO_VERSION="1.22.5"
    local ARCH
    case "$(uname -m)" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l)  ARCH="armv6l" ;;
        *)       ARCH="amd64" ;;
    esac
    local GO_TAR="go${GO_VERSION}.linux-${ARCH}.tar.gz"

    curl -sSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}" || { warn "Failed to download Go"; return 1; }
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}" || { warn "Failed to extract Go"; return 1; }
    rm -f "/tmp/${GO_TAR}"

    export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
    _add_to_path "/usr/local/go/bin"
    _add_to_path "$HOME/go/bin"

    if command_exists go; then
        success "Go installed ($(go version | grep -oP 'go\d+\.\d+\.\d+'))"
        return 0
    else
        warn "Go installation failed"
        return 1
    fi
}

go_install_tool() {
    local name="$1"
    local pkg="$2"
    if command_exists "$name"; then
        success "$name (already installed)"
        return 0
    fi
    info "Installing $name..."
    go install -v "$pkg" &>/dev/null && success "$name" || { warn "Failed to install $name"; return 1; }
}

# ── External Tools Installer ─────────────────────────────────

install_external_tools() {
    # Temporarily disable exit-on-error (tool installs may fail gracefully)
    set +e

    echo ""
    echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════╗${RESET}"
    echo -e "${YELLOW}${BOLD}║       ⚔️  ARMING THE ARSENAL  ⚔️         ║${RESET}"
    echo -e "${YELLOW}${BOLD}╚══════════════════════════════════════════╝${RESET}"
    echo ""

    local installed=0
    local failed=0
    local skipped=0
    local total=21

    detect_pkg_manager
    info "Detected package manager: ${BOLD}${PKG_MGR}${RESET}"

    # ── 1. System packages (apt/dnf/pacman) ──────────────
    echo ""
    echo -e "${BOLD}[1/6] System packages...${RESET}"

    if [[ "$PKG_MGR" == "apt" ]]; then
        sudo apt-get update -qq 2>/dev/null
    fi

    declare -A SYS_PKGS
    case "$PKG_MGR" in
        apt)
            SYS_PKGS=(
                [nmap]="nmap"
                [sqlmap]="sqlmap"
                [adb]="android-tools-adb"
            )
            ;;
        dnf)
            SYS_PKGS=(
                [nmap]="nmap"
                [sqlmap]="sqlmap"
                [adb]="android-tools"
            )
            ;;
        pacman)
            SYS_PKGS=(
                [nmap]="nmap"
                [sqlmap]="sqlmap"
                [adb]="android-tools"
            )
            ;;
        *)
            SYS_PKGS=()
            ;;
    esac

    for tool in nmap sqlmap adb; do
        if command_exists "$tool"; then
            success "$tool (already installed)"
            ((skipped++))
        elif [[ -n "${SYS_PKGS[$tool]+x}" ]]; then
            info "Installing $tool..."
            if pkg_install "${SYS_PKGS[$tool]}"; then
                success "$tool"
                ((installed++))
            else
                warn "Failed to install $tool"
                ((failed++))
            fi
        else
            warn "Cannot auto-install $tool on this system"
            ((failed++))
        fi
    done

    # ── whatweb: install from source to avoid Ruby load path issues ──
    # Apt-installed whatweb breaks under RVM/rbenv because /usr/bin/whatweb
    # requires whatweb.rb at the system Ruby vendor path, which RVM's Ruby
    # doesn't include in its load path. Source install is self-contained.
    local WHATWEB_SRC="$HOME/.local/share/whatweb"
    local WHATWEB_BIN="$HOME/.local/bin/whatweb"
    if [[ -x "$WHATWEB_SRC/whatweb" ]] && "$WHATWEB_SRC/whatweb" --version &>/dev/null 2>&1; then
        success "whatweb (already installed from source)"
        ((skipped++))
    elif command_exists whatweb && whatweb --version &>/dev/null 2>&1; then
        success "whatweb (already installed)"
        ((skipped++))
    else
        info "Installing whatweb (from source)..."
        if ! command_exists ruby; then
            warn "whatweb requires ruby — install ruby first"
            ((failed++))
        elif ! command_exists git; then
            warn "whatweb source install requires git"
            ((failed++))
        else
            rm -rf "$WHATWEB_SRC"
            if git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git "$WHATWEB_SRC" &>/dev/null; then
                chmod +x "$WHATWEB_SRC/whatweb"
                mkdir -p "$HOME/.local/bin"
                ln -sf "$WHATWEB_SRC/whatweb" "$WHATWEB_BIN"
                # Install required gems into whatever Ruby is active (RVM-aware)
                command_exists gem && gem install addressable --quiet &>/dev/null || true
                if "$WHATWEB_SRC/whatweb" --version &>/dev/null 2>&1; then
                    success "whatweb (from source)"
                    ((installed++))
                else
                    warn "whatweb cloned but smoke test failed — run 'gem install addressable' if missing"
                    ((failed++))
                fi
            else
                warn "Failed to clone WhatWeb repository"
                ((failed++))
            fi
        fi
    fi

    # ── 2. Go-based tools ────────────────────────────────
    echo ""
    echo -e "${BOLD}[2/6] Go-based security tools...${RESET}"

    if ensure_go; then
        export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
        export GOPATH="${GOPATH:-$HOME/go}"
        export GOBIN="$GOPATH/bin"
        mkdir -p "$GOBIN"

        declare -A GO_TOOLS=(
            [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
            [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            [ffuf]="github.com/ffuf/ffuf/v2@latest"
            [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
            [gospider]="github.com/jaeles-project/gospider@latest"
            [hakrawler]="github.com/hakluke/hakrawler@latest"
            [gau]="github.com/lc/gau/v2/cmd/gau@latest"
            [dalfox]="github.com/hahwul/dalfox/v2@latest"
            [amass]="github.com/owasp-amass/amass/v4/...@master"
        )

        for tool in nuclei httpx subfinder ffuf katana gospider hakrawler gau dalfox amass; do
            # httpx: the Python httpx pip package installs a CLI shim that
            # shadows ProjectDiscovery's Go httpx. Detect this by checking
            # if the found binary is a compiled Go executable vs a Python script.
            if [[ "$tool" == "httpx" ]] && command_exists httpx; then
                if file "$(command -v httpx)" 2>/dev/null | grep -qi "python\|script\|text"; then
                    info "Found Python httpx shim — installing Go httpx (ProjectDiscovery)..."
                    go install -v "${GO_TOOLS[httpx]}" &>/dev/null && \
                        { success "httpx"; ((installed++)); } || \
                        { warn "Failed to install httpx"; ((failed++)); }
                else
                    success "$tool (already installed)"
                    ((skipped++))
                fi
                continue
            fi

            if command_exists "$tool"; then
                success "$tool (already installed)"
                ((skipped++))
            else
                info "Installing $tool..."
                if go install -v "${GO_TOOLS[$tool]}" &>/dev/null; then
                    success "$tool"
                    ((installed++))
                else
                    warn "Failed to install $tool"
                    ((failed++))
                fi
            fi
        done

        _add_to_path "$GOBIN"

        # ── Initialize Go tool configs as current user ────────────
        # When Beatrix runs via sudo, Go tools (subfinder, amass, nuclei)
        # create their config dirs in ~/.config/ as root, making them
        # unreadable on subsequent runs. Pre-create them here as the
        # current (non-root) user so they already exist with correct
        # ownership before sudo ever invokes them.
        echo ""
        info "Initializing Go tool configurations..."
        if command_exists subfinder; then
            subfinder -h &>/dev/null || true
            success "subfinder config initialized"
        fi
        if command_exists amass; then
            amass -h &>/dev/null || true
            success "amass config initialized"
        fi

        # ── Download nuclei templates ─────────────────────────────
        # Nuclei needs ~18,000 YAML templates to scan. Without them,
        # the first scan triggers a 500MB+ download mid-hunt.
        # Run as the real user (not root) so templates land in the
        # correct home directory with proper ownership.
        if command_exists nuclei; then
            info "Downloading nuclei templates (one-time, ~500MB)..."
            if [[ -n "${SUDO_USER:-}" && "$EUID" -eq 0 ]]; then
                sudo -u "$SUDO_USER" nuclei -update-templates &>/dev/null && \
                    success "nuclei templates downloaded (as $SUDO_USER)" || \
                    warn "Failed to download nuclei templates (run 'nuclei -update-templates' manually)"
            else
                nuclei -update-templates &>/dev/null && \
                    success "nuclei templates downloaded" || \
                    warn "Failed to download nuclei templates (run 'nuclei -update-templates' manually)"
            fi
        fi

        # ── Chromium system deps for nuclei headless mode ─────────
        # Nuclei's headless mode (go-rod) downloads its own Chrome
        # binary but requires system shared libraries. Without these,
        # headless scans crash with "libatk-1.0.so.0: cannot open".
        if [[ "$PKG_MGR" == "apt" ]]; then
            info "Installing chromium system dependencies for headless mode..."
            sudo apt-get install -y -qq \
                libatk1.0-0 libatk-bridge2.0-0 libcups2 libgbm1 \
                libgtk-3-0 libnss3 libxcomposite1 libxdamage1 \
                libxfixes3 libxrandr2 libpango-1.0-0 libdrm2 \
                libxshmfence1 libxkbcommon0 libasound2 2>/dev/null && \
                success "chromium system dependencies" || \
                warn "Failed to install some chromium deps — headless mode may not work"
        fi
    else
        warn "Skipping Go tools (Go not available)"
        ((failed+=10))
    fi

    # ── 3. Python tools ──────────────────────────────────
    echo ""
    echo -e "${BOLD}[3/6] Python security tools...${RESET}"

    # Use the venv pip if available (avoids PEP 668 / --break-system-packages issues)
    local PIP_CMD="$PYTHON -m pip install --user"
    if [[ -x "$VENV_DIR/bin/pip" ]]; then
        PIP_CMD="$VENV_DIR/bin/pip install"
    fi

    for tool in mitmproxy commix; do
        if command_exists "$tool"; then
            success "$tool (already installed)"
            ((skipped++))
        else
            info "Installing $tool..."
            if $PIP_CMD "$tool" &>/dev/null; then
                success "$tool"
                ((installed++))
            else
                warn "Failed to install $tool"
                ((failed++))
            fi
        fi
    done

    # jwt_tool
    if command_exists jwt_tool || command_exists jwt_tool.py; then
        success "jwt_tool (already installed)"
        ((skipped++))
    else
        info "Installing jwt_tool..."
        local JWT_DIR="$HOME/.local/share/jwt_tool"
        mkdir -p "$JWT_DIR"
        if curl -sSL "https://raw.githubusercontent.com/ticarpi/jwt_tool/master/jwt_tool.py" -o "$JWT_DIR/jwt_tool.py" && \
           chmod +x "$JWT_DIR/jwt_tool.py" && \
           $PIP_CMD termcolor cprint pycryptodomex requests &>/dev/null; then
            mkdir -p "$HOME/.local/bin"
            local JWT_PYTHON="$PYTHON"
            [[ -x "$VENV_DIR/bin/python" ]] && JWT_PYTHON="$VENV_DIR/bin/python"
            cat > "$HOME/.local/bin/jwt_tool" <<WRAPPER
#!/usr/bin/env bash
exec $JWT_PYTHON "$JWT_DIR/jwt_tool.py" "\$@"
WRAPPER
            chmod +x "$HOME/.local/bin/jwt_tool"
            success "jwt_tool"
            ((installed++))
        else
            warn "Failed to install jwt_tool"
            ((failed++))
        fi
    fi

    # dirsearch
    if command_exists dirsearch; then
        success "dirsearch (already installed)"
        ((skipped++))
    else
        info "Installing dirsearch..."
        if $PIP_CMD dirsearch &>/dev/null; then
            success "dirsearch"
            ((installed++))
        else
            warn "Failed to install dirsearch"
            ((failed++))
        fi
    fi

    # ── 4. Playwright (browser automation) ───────────────
    echo ""
    echo -e "${BOLD}[4/6] Playwright (browser automation)...${RESET}"

    local PW_PYTHON="$PYTHON"
    [[ -x "$VENV_DIR/bin/python" ]] && PW_PYTHON="$VENV_DIR/bin/python"

    # playwright is a core pip dependency (already installed with Beatrix).
    # Here we ensure the Chromium browser binary is downloaded and on PATH.
    if $PW_PYTHON -c 'import playwright' &>/dev/null; then
        info "Installing Chromium browser for playwright..."

        # When running as root (sudo bash install.sh), Playwright downloads Chromium
        # to $HOME/.cache/ms-playwright. Under sudo, HOME=/root — but beatrix runs
        # as the invoking user, so we must override HOME so Chromium lands in the
        # real user's cache directory. The --with-deps apt step still runs as root.
        local _pw_home="$HOME"
        if [[ -n "${SUDO_USER:-}" && "$EUID" -eq 0 ]]; then
            _pw_home=$(getent passwd "$SUDO_USER" | cut -d: -f6 2>/dev/null || echo "$HOME")
            info "  Using HOME=$_pw_home for Chromium download (SUDO_USER=$SUDO_USER)"
        fi

        local _pw_install_ok=false
        local _pw_err
        _pw_err=$(HOME="$_pw_home" $PW_PYTHON -m playwright install chromium --with-deps 2>&1) && \
            _pw_install_ok=true

        if [[ "$_pw_install_ok" == "false" ]]; then
            # --with-deps may fail if apt is unavailable; retry without it
            _pw_err=$(HOME="$_pw_home" $PW_PYTHON -m playwright install chromium 2>&1) && \
                _pw_install_ok=true
        fi

        if [[ "$_pw_install_ok" == "true" ]]; then
            # Verify Chromium was actually downloaded (not just "already installed")
            local _chromium_ok=false
            for _cache in "$_pw_home/.cache/ms-playwright" "$HOME/.cache/ms-playwright"; do
                if ls "$_cache"/chromium-* &>/dev/null 2>&1 || ls "$_cache"/chromium_headless_shell-* &>/dev/null 2>&1; then
                    _chromium_ok=true
                    break
                fi
            done

            # Symlink playwright CLI so it's usable directly from the terminal
            mkdir -p "$HOME/.local/bin"
            if [[ -x "$VENV_DIR/bin/playwright" ]]; then
                ln -sf "$VENV_DIR/bin/playwright" "$HOME/.local/bin/playwright" 2>/dev/null || true
            fi

            if [[ "$_chromium_ok" == "true" ]]; then
                success "playwright + Chromium"
                ((installed++))
            else
                warn "playwright installed but Chromium binary not found — try: $PW_PYTHON -m playwright install chromium"
                ((failed++))
            fi
        else
            warn "playwright Chromium install failed:"
            warn "  $_pw_err"
            warn "  Fix: run '$PW_PYTHON -m playwright install chromium --with-deps'"
            ((failed++))
        fi
    else
        warn "playwright Python package not found — reinstall Beatrix first"
        ((failed++))
    fi

    # ── 5. webanalyze (Go-based Wappalyzer) ──────────────
    echo ""
    echo -e "${BOLD}[5/6] webanalyze (tech fingerprinting)...${RESET}"

    if command_exists webanalyze; then
        success "webanalyze (already installed)"
        ((skipped++))
    else
        info "Installing webanalyze..."
        if go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest &>/dev/null; then
            success "webanalyze"
            ((installed++))
        else
            warn "Failed to install webanalyze"
            ((failed++))
        fi
    fi

    # Download technologies.json (required at runtime — webanalyze errors without it).
    # Always refresh so the fingerprint database stays current across reinstalls.
    local WEBANALYZE_DATA="$HOME/.local/share/webanalyze"
    local WEBANALYZE_DB="$WEBANALYZE_DATA/technologies.json"
    mkdir -p "$WEBANALYZE_DATA"
    info "Fetching webanalyze technology database..."
    if curl -sSL "https://raw.githubusercontent.com/rverton/webanalyze/master/technologies.json" \
            -o "$WEBANALYZE_DB" 2>/dev/null && [[ -s "$WEBANALYZE_DB" ]]; then
        success "webanalyze technologies database"
    else
        # Fall back to copying from the Go module cache if curl failed
        local cached_db
        cached_db=$(find "${GOPATH:-$HOME/go}/pkg/mod" -name "technologies.json" \
                        -path "*/webanalyze*" 2>/dev/null | head -1)
        if [[ -n "$cached_db" ]]; then
            cp "$cached_db" "$WEBANALYZE_DB"
            success "webanalyze technologies database (from module cache)"
        else
            warn "Could not fetch webanalyze technologies database — run 'webanalyze -update' after install"
        fi
    fi

    # ── 6. Metasploit Framework ──────────────────────────
    echo ""
    echo -e "${BOLD}[6/6] Metasploit Framework...${RESET}"

    if command_exists msfconsole; then
        success "metasploit (already installed)"
        ((skipped++))
    else
        info "Installing Metasploit Framework (this may take a few minutes)..."
        if curl -sSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall 2>/dev/null && \
           chmod +x /tmp/msfinstall && \
           sudo /tmp/msfinstall &>/dev/null; then
            rm -f /tmp/msfinstall
            success "metasploit"
            ((installed++))
        else
            rm -f /tmp/msfinstall
            warn "Failed to install metasploit (try manually: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod +x msfinstall && sudo ./msfinstall)"
            ((failed++))
        fi
    fi

    # ── Summary ──────────────────────────────────────────
    echo ""
    echo -e "${BOLD}Arsenal Summary:${RESET}"
    echo -e "  ${GREEN}✓ Installed:${RESET}  $installed"
    echo -e "  ${CYAN}○ Skipped:${RESET}   $skipped (already present)"
    if [[ $failed -gt 0 ]]; then
        echo -e "  ${RED}✗ Failed:${RESET}    $failed"
    fi

    local ready=$((installed + skipped))
    echo ""
    echo -e "  ${BOLD}${ready}/${total} tools armed.${RESET}"

    if [[ $failed -gt 0 ]]; then
        echo ""
        echo -e "  ${DIM}Run ${BOLD}beatrix setup${DIM} anytime to retry failed installations.${RESET}"
    fi

    # Re-enable strict mode
    set -euo pipefail
}

# ── Optional Tools (check only) ──────────────────────────────

check_optional_tools() {
    echo ""
    echo -e "${BOLD}External tools status:${RESET}"

    local tools=("nuclei" "httpx" "subfinder" "ffuf" "katana" "sqlmap" "nmap" "adb" "mitmproxy" "playwright" "amass" "whatweb" "webanalyze" "gospider" "hakrawler" "gau" "dirsearch" "dalfox" "commix" "jwt_tool" "msfconsole")
    local found=0
    local total=${#tools[@]}

    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            success "$tool"
            found=$((found + 1))
        else
            echo -e "  ${DIM}○ $tool (not installed)${RESET}"
        fi
    done

    echo ""
    echo -e "  ${found}/${total} tools available."
}

# ── Python Dependency Verification & Repair ──────────────────

# All core Python packages required by Beatrix (from pyproject.toml + extended)
CORE_PYTHON_DEPS=(
    # CLI
    "click>=8.1.0"
    "rich>=13.0.0"
    # HTTP
    "httpx>=0.25.0"
    "aiohttp>=3.9.0"
    "requests>=2.31.0"
    "urllib3>=2.0.0"
    # Config
    "pyyaml>=6.0"
    # AI (ghost.py uses raw httpx/boto3)
    "boto3>=1.34.0"
    # Security / Scanning
    "PyJWT>=2.8.0"
    "dnspython>=2.4.0"
    "python-nmap>=0.7.1"
    "paramiko>=3.4.0"
    "scapy>=2.5.0"
    "playwright>=1.40.0"
    # Extended (full scanning support)
    "mitmproxy>=10.0.0"
    "cloudscraper>=1.2.71"
    "networkx>=3.2.0"
    "matplotlib>=3.8.0"
)

# Map package install names to their Python import names for verification
declare -A IMPORT_MAP=(
    [click]="click"
    [rich]="rich"
    [httpx]="httpx"
    [aiohttp]="aiohttp"
    [requests]="requests"
    [urllib3]="urllib3"
    [pyyaml]="yaml"
    [boto3]="boto3"
    [PyJWT]="jwt"
    [dnspython]="dns"
    [python-nmap]="nmap"
    [paramiko]="paramiko"
    [scapy]="scapy"
    [playwright]="playwright"
    [mitmproxy]="mitmproxy"
    [cloudscraper]="cloudscraper"
    [networkx]="networkx"
    [matplotlib]="matplotlib"
)

verify_python_deps() {
    local missing=()
    local ok=0
    local total=${#IMPORT_MAP[@]}

    # Use the venv's Python if available, otherwise fall back to system
    local verify_python="$PYTHON"
    local verify_pip="$PYTHON -m pip"
    if [[ -x "$VENV_DIR/bin/python" ]]; then
        verify_python="$VENV_DIR/bin/python"
        verify_pip="$VENV_DIR/bin/pip"
    fi

    for pkg in "${!IMPORT_MAP[@]}"; do
        local mod="${IMPORT_MAP[$pkg]}"
        if $verify_python -c "import ${mod}" &>/dev/null; then
            ((ok++)) || true
        else
            missing+=("$pkg")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        success "All $total Python dependencies verified"
        return 0
    fi

    warn "${#missing[@]} Python dependencies missing: ${missing[*]}"
    info "Installing missing dependencies..."

    local repaired=0
    for pkg in "${missing[@]}"; do
        # Find the versioned spec from CORE_PYTHON_DEPS
        local spec="$pkg"
        for dep in "${CORE_PYTHON_DEPS[@]}"; do
            if [[ "$dep" == "$pkg"* ]]; then
                spec="$dep"
                break
            fi
        done

        info "  Installing $spec..."
        if $verify_pip install "$spec" &>/dev/null 2>&1; then
            success "  $pkg"
            ((repaired++)) || true
        else
            warn "  Failed to install $pkg"
        fi
    done

    if [[ $repaired -eq ${#missing[@]} ]]; then
        success "All missing dependencies repaired ($repaired installed)"
    else
        warn "Some dependencies could not be installed. Run: $verify_python -m pip install \".[extended]\""
    fi
}

# ── Main ─────────────────────────────────────────────────────

main() {
    banner

    # If we're being piped from curl, clone the repo first
    if [[ ! -f "pyproject.toml" ]]; then
        info "Cloning Beatrix CLI..."
        if command_exists git; then
            git clone https://github.com/SudoPacman-Syuu/Beatrix-cli.git /tmp/beatrix_cli_install
            cd /tmp/beatrix_cli_install
        else
            fail "git is required. Install it: ${DIM}sudo apt install git${RESET}"
        fi
    fi

    echo -e "${BOLD}Checking requirements...${RESET}"
    check_python
    check_pip

    echo ""
    echo -e "${BOLD}Installing Beatrix CLI...${RESET}"

    # Try install methods in order of preference:
    #   1. uv (fastest, most reliable, auto-manages venv)
    #   2. venv (always works, fully isolated from system Python)
    #   3. pipx (isolated but requires pipx)
    #   4. pip --user (last resort)
    install_with_uv || \
    install_with_venv || \
    install_with_pipx || \
    install_with_pip_user || \
    fail "All install methods failed. Please install manually:\n  ${DIM}python3 -m venv ~/.beatrix && ~/.beatrix/bin/pip install .${RESET}"

    # ── Verify & repair Python dependencies ──────────────
    echo ""
    echo -e "${BOLD}Verifying Python dependencies...${RESET}"
    verify_python_deps

    # Verify installation
    echo ""
    echo -e "${BOLD}Verifying CLI...${RESET}"

    # Need to refresh PATH for current session
    export PATH="$HOME/.local/bin:$PATH"

    if command_exists beatrix; then
        local installed_ver
        installed_ver="$(beatrix --version 2>&1)"
        success "beatrix is on your PATH"
        success "$installed_ver"
    else
        warn "beatrix was installed but is not on your PATH yet"
        info "Try: ${BOLD}source ~/.bashrc${RESET} or restart your terminal"
    fi

    check_optional_tools

    echo ""
    echo -e "${BOLD}Installing external tools (the full arsenal)...${RESET}"
    install_external_tools

    echo ""
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
    echo -e "${GREEN}${BOLD}  Installation complete!${RESET}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════${RESET}"
    echo ""
    echo -e "  ${BOLD}Quick start:${RESET}"
    echo -e "    ${CYAN}beatrix${RESET}                          Show commands"
    echo -e "    ${CYAN}beatrix hunt example.com${RESET}         Scan a target"
    echo -e "    ${CYAN}beatrix help hunt${RESET}                Detailed help"
    echo -e "    ${CYAN}beatrix arsenal${RESET}                  View all modules"
    echo ""
    echo -e "  ${DIM}\"Revenge is a dish best served with a working PoC.\"${RESET}"
    echo ""

    # Cleanup if we cloned to /tmp
    if [[ "$(pwd)" == /tmp/beatrix_cli_install* ]]; then
        cd ~
        rm -rf /tmp/beatrix_cli_install
    fi
}

main "$@"
