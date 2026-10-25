#!/bin/bash
# launch-panel.sh — one-click launcher for the DMA MCP control panel.
# Used by the desktop entry (~/Desktop/DMA-MCP-Panel.desktop); also fine
# to run directly. The panel needs elevated access to the memory window;
# this script handles elevation so the flow is: open, click Start link,
# pick the process, Expose. Nothing else.
#
# Fresh-restart behavior: if the target host rebooted under a stale mount
# (window serves zeros), the panel's Start link restarts it automatically.

PANEL="$(cd "$(dirname "$(readlink -f '$0')")" && pwd)/panel.py"

if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    exec sudo -n -E python3 "$PANEL"
fi
# no passwordless sudo: graphical prompt instead
if command -v pkexec >/dev/null 2>&1; then
    exec pkexec env DISPLAY="${DISPLAY:-:0}" \
         XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
         PYTHONUNBUFFERED=1 python3 "$PANEL"
fi
echo "need either passwordless sudo or pkexec to run the panel" >&2
exit 1
