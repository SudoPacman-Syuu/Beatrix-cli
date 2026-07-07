#!/usr/bin/env bash
# BEATRIX CLI — Uninstaller
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

INSTALL_DIR="${BEATRIX_INSTALL_DIR:-/usr/local/bin}"
VENV_DIR="${BEATRIX_VENV:-$HOME/.beatrix}"

echo ""
echo -e "${BOLD}Uninstalling Beatrix CLI...${RESET}"
echo ""

# pipx
if command -v pipx &>/dev/null; then
    pipx uninstall beatrix-cli 2>/dev/null && \
        echo -e "  ${GREEN}✓${RESET} Removed pipx install" || true
fi

# pip user
python3 -m pip uninstall -y beatrix-cli 2>/dev/null && \
    echo -e "  ${GREEN}✓${RESET} Removed pip user install" || true

# pip system
sudo python3 -m pip uninstall -y beatrix-cli 2>/dev/null && \
    echo -e "  ${GREEN}✓${RESET} Removed pip system install" || true

# Config (ask first — before removing the venv directory)
if [[ -f "$VENV_DIR/config.yaml" ]]; then
    echo ""
    read -rp "  Remove config ($VENV_DIR/config.yaml)? [y/N] " answer
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        # Preserve config — move it temporarily
        _beatrix_cfg_backup=$(mktemp)
        cp "$VENV_DIR/config.yaml" "$_beatrix_cfg_backup"
    fi
fi

# venv
if [[ -d "$VENV_DIR" ]]; then
    rm -rf "$VENV_DIR"
    echo -e "  ${GREEN}✓${RESET} Removed $VENV_DIR venv"
fi

# Restore config if user chose to keep it
if [[ -n "${_beatrix_cfg_backup:-}" ]]; then
    mkdir -p "$VENV_DIR"
    mv "$_beatrix_cfg_backup" "$VENV_DIR/config.yaml"
    echo -e "  ${GREEN}✓${RESET} Config preserved"
fi

# Wrapper scripts (beatrix + beatrix-suite)
for _bin in beatrix beatrix-suite; do
    if [[ -f "$INSTALL_DIR/$_bin" ]] || [[ -L "$INSTALL_DIR/$_bin" ]]; then
        sudo rm -f "$INSTALL_DIR/$_bin"
        echo -e "  ${GREEN}✓${RESET} Removed $INSTALL_DIR/$_bin"
    fi
done

echo ""
echo -e "${GREEN}${BOLD}Beatrix CLI has been uninstalled.${RESET}"
echo -e "${DIM}\"You and I have unfinished business.\"${RESET}"
echo ""
