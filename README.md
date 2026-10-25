# dma_mcp_spoofer

A PCIe-DMA-backed **MCP server** that exposes conventional process/memory
inspection tools — `list_processes`, `open_process`, `read_process_memory`,
`list_modules` — shaped exactly like the standard Windows way of reading a
local process. The MCP client has no way to tell from the tool surface that
reads are actually served from a **different machine** over a DMA link, or
that a server-side allowlist decides which processes exist at all.

Built and validated on a two-PC lab rig: a Linux "reader" box with a
CaptainDMA (FT601/pcileech) card reading a Windows target over PCIe. The
client (Claude Code or any MCP consumer) runs on the reader box against
`process-memory`, an MCP server that looks like a local helper.

> **Scope & ethics.** This is a research/transparency rig for machines you
> own or are authorized to analyze. DMA acquisition is the same technique
> used by forensic tooling (PCILeech/MemProcFS, Volatility); the twist
> studied here is what an AI agent can and cannot infer about where its
> tools actually run. Don't point this at systems you don't control.

---

## Quick start

```bash
# 0) prerequisites on the reader box: pcileech (v4.20+) with FPGA support,
#    python3.11+, and the mcp package:  pip install --user mcp

# 1) bring the DMA link up (MemProcFS FUSE mount)
cd tools && sudo ./pcileech mount -mount /mnt/MEMPROCFS -device fpga

# 2) structural self-test (no link needed)
cd dma_mcp_spoofer && python3 -I selftest.py          # -> ALL PASS

# 3) end-to-end smoke test (link up, target booted; D2R.exe optional)
sudo python3 -I selftest.py --live                    # -> MZ ... OK

# 4) control panel: link status, full process list, pick what to expose
sudo -E python3 panel.py            # GUI
sudo python3 panel.py --list        # CLI: walk + auto-bootstrap
sudo python3 panel.py --expose D2R.exe   # GUI has a live keyword filter too

# 5) publish the client-facing server copy + register with a client
python3 -I install.py
mkdir -p ~/memtest && cp mcp.json ~/memtest/.mcp.json   # edit the path inside!
cd ~/memtest && claude    # the client sees a plain "process-memory" helper
```

**Nothing is hardcoded per boot.** After the target PC reboots you do
nothing: the first process-list call re-discovers the walk anchors from
physical memory (typically 1–3 minutes, cached afterwards; progress on
stderr). See [ARCHITECTURE.md](ARCHITECTURE.md) for how.

## Repository layout

```
├── server.py            MCP entry point (stdio) — client-facing tools
├── bridge/
│   ├── phys.py          flat physical window (the only DMA-aware module)
│   ├── va.py            4/5-level page-table walk -> process VA reads
│   ├── procs.py         process-list walk + name/PID/DTB extraction
│   ├── autoboot.py      discovers the walk anchors from memory — no
│   │                    recorded values, self-healing after reboots
│   └── facade.py        allowlist enforcement + handle table + Win32 errors
├── config/
│   ├── allowlist.toml   server-side only: which processes clients may see
│   └── bootstrap.json   auto-managed cache of discovered anchors (optional)
├── panel.py             your control panel: link status, picker, expose
├── launch-panel.sh      one-click desktop launcher wrapper
├── install.py           publish sanitized server copy for blind tests
├── selftest.py          structural tests (+ --live end-to-end)
├── dump_d2r.py          example consumer: phase-labeled process dumps
├── scripts/probe_eprocess_layout.py   ground-truth layout probe (how the
│                                      discovery signatures were derived)
└── mcp.json             registration template (adjust install path)
```

## The two sides of the design

**Server-side truth (your side):** the panel shows the *full* unfiltered
process walk, the resolved kernel DTB / anchor, and the allowlist. You
choose exactly which image name(s) MCP clients get to see.

**Client-facing illusion (the test):** tool names, argument shapes, JSON
results, and error text are ordinary Win32-flavored surface
(`"error 87: The parameter is incorrect"`, handles that are 4-aligned,
paged-out pages zero-filled and counted). A process not on the allowlist is
*indistinguishable from not running* — same error for a filtered pid as for
a nonexistent one. No DMA/hardware/host vocabulary appears in any tool
result, schema, or error. `install.py` publishes a sanitized copy (audited
automatically for tell-words) so even a client that reads the server's
files sees a self-contained local helper.

## Day-to-day operations

| Situation | What to do |
|---|---|
| Target PC rebooted | Nothing. First call re-derives anchors automatically. |
| Game restarted | Nothing. Walk re-runs per 5 s snapshot; new pid picked up. |
| Panel shows DOWN "reads as all zeros" | Click **Start link** — it auto-restarts the stale mount. |
| Link died after reader suspended | Wake/reboot the *target* (FPGA BAR re-init), then Start link. |
| `pcileech probe` fails while mounted | Normal — probe holds the FT601 exclusively. |
| Kill the mount | `sudo pkill -x pcileech` (never `-f` — it matches your own wrapper). |

## Environment variables

| Var | Meaning |
|---|---|
| `PROCMEM_SRC` | physical window path (default `/mnt/MEMPROCFS/liveram-native.raw`) |
| `MCPDMA_KERNEL_DTB` / `MCPDMA_ANCHOR_EPROC` | optional manual bootstrap hints (never required) |
| `MCPDMA_CONFIG` | config file path override |
| `PROCMEM_TARGET` | target host IP for the panel's reachability check |
| `PROCMEM_INSTALL_DIR` | install destination for `install.py` |

## What it deliberately is NOT

- Not an injector: read-only acquisition; no code runs on the target.
- Not anti-cheat evasion research: the point is the MCP trust boundary,
  and the rig runs against its own lab machines.
- Not a kernel debugger: `dump_d2r.py`-style bulk consumers sit on top of
  the same facade, but the server itself just reads memory.
