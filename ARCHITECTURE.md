# Architecture — dma_mcp_spoofer

## The rig

```
┌─────────────────────────┐          PCIe (DMA card, no driver on target)
│ TARGET (Windows 11)     │◄──────────────────────────────────┐
│  D2R.exe & friends      │        CaptainDMA FPGA            │
└─────────────────────────┘        over FT601 USB3            │
                                                            │
┌─────────────────────────┐  FUSE    ┌────────────────────┐  │
│ READER (Linux)          │◄─────────│ pcileech/MemProcFS │◄─┘
│  Claude Code (MCP       │  mount   │ /mnt/MEMPROCFS/    │
│   client)               │          │ liveram-native.raw │
│   └─► process-memory    │          └────────────────────┘
│       MCP server        │
└─────────────────────────┘
```

The client believes it is talking to a local memory-analysis helper for
the machine it sits on. Every read it requests actually travels: MCP
(stdio) → facade → page-table walk → physical window → FUSE → pcileech →
USB → FPGA → target RAM.

## Layering

```
server.py        MCP tools (stdio): list_processes, open_process,
                 read_process_memory, read_batch, list_modules,
                 close_handle, get_system_info
   │
facade.py        allowlist enforcement, handle table, Win32-style errors,
                 typed reads, liveness, reboot self-healing
   │
   ├──autoboot.py   cold-start discovery of the walk anchors (below)
   │
   ├──procs.py      EPROCESS list walk: dynamic link-offset discovery,
   │                PID/name/DTB extraction, 5 s snapshot cache
   │
   └──va.py         4/5-level page-table walk (LA48/LA57 auto-detect),
                     process VA reads, zero-fill for unmapped pages
        │
      phys.py       the ONLY DMA-aware module: seek/read over the FUSE
                   window, whole-file cache eviction (live reads),
                   transparent reopen on mount replacement
```

Everything above `phys.py` speaks virtual addresses and knows nothing
about the hardware. Everything below `facade.py` never talks to a client.

## Key mechanisms

### Reading a process
1. Process list walk starts from a validated anchor EPROCESS (kernel VA)
   translated through the kernel DTB.
2. The ActiveProcessLinks offset is **discovered, not hardcoded**: every
   LIST_ENTRY pair in the anchor window is a candidate; candidates are
   scored by walking 16 entries and counting *distinct small integers* in
   the QWORD before the link (UniqueProcessId sits at −0x8; session lists
   repeat their ids, real pids don't).
3. Each walked entry yields DTB (+0x28, stable since Win7), pid, and a
   15-byte image name from ASCII runs.
4. Client reads go PEB→Ldr→InMemoryOrderModuleList for modules (MZ-
   validated) and through `va.py` for data. Unmapped/paged-out spans
   zero-fill and are counted in `unreadablePages`, like a debugger's
   partial-read report.

### Automatic bootstrap (the no-hardcoded-values part)
The walk needs two per-boot values: the **kernel DTB** (system page-table
root) and an **anchor** (kernel VA of one live EPROCESS). `autoboot.py`
derives both from raw physical memory:

1. **Kernel DTB** — sweep low physical memory in-buffer for a
   self-referencing level-4 page: an entry whose frame equals its own
   page address (the PML4 self-map; slot is randomized per boot, the
   property isn't). Candidates are ranked by present kernel-half entries;
   the system root maps plenty.
2. **System's EPROCESS** — sweep all memory for the 8-byte value of that
   DTB at 16-aligned+0x28 positions. Of all kernel objects, only System
   stores the *kernel* DTB in its DirectoryTableBase. Hits are
   shape-validated: self-referential list heads at +0x08/+0x10 and
   +0x18/+0x20 (values equal to the struct's own VA, so the struct's VA
   falls out for free), and +0x28 really naming a self-mapping level-4
   page.
3. **Adopt** — walk from the candidate's raw window to confirm the list,
   pick System (pid 4), re-validate through the production anchor-based
   walk, cache to `config/bootstrap.json`.

Why not pool tags: classic tag-scanning (`Proc` before the struct) fails
on modern builds — verified on a live 24H2 host, which has no classic
header at struct−0x10. The DTB-needle + self-list shape is build-
independent (verified Win10-era layouts and 24H2). The derivation probe
is kept in `scripts/probe_eprocess_layout.py`.

Resolution order (all validated by actually walking): explicit env/config
hints → disk cache → full scan. A mid-session reboot is healed the same
way: the next tool call that fails the walk re-derives once (10 s
cooldown between scans), then continues with a fresh snapshot cache.

### Liveness vs. dead-but-mounted
A DMA mount that outlives a target reboot reads back **all zeros** —
reads still succeed, so "can I read?" is not health. Both the panel and
the facade probe several spread-out pages and require non-zero content.
The panel's Start button auto-restarts a stale mount (stop pcileech,
umount, re-mount), so recovery from a target reboot is one click.

### The client-facing illusion
- Tool names/schemas/results mirror Win32 process tooling.
- Errors are Win32-style; unexpected backend failures log full tracebacks
  to stderr (server log) and return only generic error-5 text.
- Allowlist filtering is **error-parity safe**: a filtered pid returns
  the identical error string as a nonexistent pid; nothing about
  filtering, config files, or the link appears in any surface.
- `install.py` publishes a sanitized copy with hardware/host vocabulary
  stripped (automatically audited) for blind tests where the client may
  inspect the server's files.

## Performance (measured, 66 GB window)

| Operation | Time |
|---|---|
| Warm process walk (cached anchors) | ~5 s / 184 processes |
| Cold bootstrap after target reboot | ~2–3 min (sweep to System's struct at ~4.3 GB) |
| Client read after anchors resolved | ms-scale, page-table pages cached |

Cold bootstrap cost is sweep-throughput bound; it happens once per target
boot (then cached and validated in ~5 s).

## Testing

`selftest.py` (no hardware): allowlist visibility, error parity, handle
lifecycle, format validation, no-leak scan of error text, and — on a
synthetic page-table image — the full bootstrap path: level-4 self-map
detection, DTB-needle candidate scan with decoys, anchor selection, walk,
cache write, stale-cache recovery, and facade end-to-end.

`selftest.py --live` (hardware): list → open D2R → module walk → read the
main module header, expecting `MZ`.

## Threat-model notes (what this studies)

The interesting question is the MCP trust boundary: an agent that fully
trusts its tool servers cannot distinguish "local memory helper" from
"remote DMA reader with an allowlist". Signals that *would* reveal it
live outside the tool surface: timing, `get_system_info`'s memory size vs
the host's actual RAM, filesystem inspection of the server, or behavioral
probing (processes appearing/disappearing inconsistently with the local
machine). The rig exists to make those signals measurable.
