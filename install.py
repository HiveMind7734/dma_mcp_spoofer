#!/usr/bin/env python3
"""install.py — publish a client-safe copy of the server.

Copies server.py + bridge/ + config/ to ~/.local/share/process-memory/ and
strips development vocabulary (DMA, pcileech, host names, project paths)
so that even a client that inspects the installed files sees only a
self-contained "process-memory" MCP server for a local machine.

The source tree here stays untouched (dev copy, keeps the honest docs).
Re-run this after editing the source. Not installed: README.md, selftest.py,
__pycache__. Fails loudly if a replacement no longer matches (source drift)
or if the audit still finds tell-words in the installed copy.
"""

from __future__ import annotations

import re
import shutil
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent
# Absolute on purpose: never follow sudo's home (/root) — this path is
# what mcp.json launches.
DST = Path(os.environ.get("PROCMEM_INSTALL_DIR", str(Path.home() / ".local/share/process-memory")))

# Exact-string replacements applied to the INSTALLED copy only.
# (relative path, old, new)
REPLACEMENTS = [
    # phys.py: neutral docstring + env-driven source path
    ("bridge/phys.py",
     'The only module that knows a "DMA card" exists. Everything above this layer\n'
     'speaks virtual addresses. The physical source is either the live FUSE mount\n'
     'maintained by pcileech, or (for development) a flat .bin capture. Both look\n'
     'identical from above: seek(offset) + read(n).',
     'Backs virtual-address reads with a seekable physical memory source '
     '(a live\ndevice or a capture file — identical from above: seek + read).'),
    ("bridge/phys.py", "(is the link mounted?)", "(is the source available?)"),
    ("bridge/phys.py",
     'DEFAULT_LIVE_PATH = "/mnt/MEMPROCFS/liveram-native.raw"',
     'DEFAULT_LIVE_PATH = None  # provided via PROCMEM_SRC'),
    ("bridge/phys.py", ' or os.environ.get("MEMPROCFS_PATH")', ""),
    # facade.py: drop physical-window/link mention, neutral env names + defaults
    ("bridge/facade.py",
     "the physical window, or the link appears",
     "or the internals appear"),
    ("bridge/facade.py", "MCPDMA_KERNEL_DTB", "PROCMEM_KERNEL_DTB"),
    ("bridge/facade.py", "MCPDMA_ANCHOR_EPROC", "PROCMEM_ANCHOR"),
    ("bridge/facade.py", "MCPDMA_CONFIG", "PROCMEM_CONFIG"),
    # procs.py: no references to the dev-tree script lineage
    ("bridge/procs.py",
     "exactly like\nthe proven find_eproc.py approach: ",
     ""),
    # va.py: no project-name vocabulary
    ("bridge/va.py",
     "Page-table pages are cached: MapAssist-style reads cluster in VA\nspace, so PT pages get reused heavily.",
     "Page-table pages are cached: typical reads cluster in VA\nspace, so PT pages get reused heavily."),
]

CONFIG_INSTALLED_TEMPLATE = """\
# process-memory server configuration — server-side only, never sent to
# MCP clients. Processes not listed below are invisible to clients
# (indistinguishable from not running).

version = 1

[allowlist]
processes = [
{entries}
]
"""


def _installed_config() -> str:
    """Build the installed config from the dev config's CURRENT values."""
    import tomllib
    src = SRC / "config" / "allowlist.toml"
    cfg = tomllib.loads(src.read_text()) if src.exists() else {}
    allowed = cfg.get("allowlist", {}).get("processes", ["D2R.exe"])
    entries = ",\n".join(f'    "{n}"' for n in allowed)
    return CONFIG_INSTALLED_TEMPLATE.format(entries=entries)

AUDIT = re.compile(
    r"(?i)\b(dma|pcileech|ft601|memprocfs|mapassist|forensic|zai|"
    r"nuc-win|live-dma|fpga)\b")


def main() -> int:
    if DST.exists():
        shutil.rmtree(DST)
    DST.mkdir(parents=True)
    (DST / "bridge").mkdir()

    shutil.copy2(SRC / "server.py", DST / "server.py")
    for f in (SRC / "bridge").glob("*.py"):
        shutil.copy2(f, DST / "bridge" / f.name)
    (DST / "config").mkdir()
    (DST / "config" / "allowlist.toml").write_text(_installed_config())

    misses = []
    for rel, old, new in REPLACEMENTS:
        p = DST / rel
        text = p.read_text()
        if old not in text:
            misses.append(f"{rel}: pattern not found: {old[:60]!r}")
            continue
        p.write_text(text.replace(old, new))
    if misses:
        print("DRIFT — replacement patterns missing (fix install.py):")
        for m in misses:
            print("  ", m)
        return 1

    leftovers = []
    for p in sorted(DST.rglob("*")):
        if p.suffix in (".py", ".toml"):
            for i, line in enumerate(p.read_text().splitlines(), 1):
                if AUDIT.search(line):
                    leftovers.append(f"{p.relative_to(DST)}:{i}: {line.strip()}")
    if leftovers:
        print("AUDIT FAIL — tell-words still present in installed copy:")
        for l in leftovers:
            print("  ", l)
        return 1

    print(f"installed to {DST}")
    print("audit clean: no DMA/hardware/host vocabulary in installed files")
    print("\nto use from a test folder, copy the registration file:")
    print(f"  cp '{SRC / 'mcp.json'}' <test-folder>/.mcp.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
