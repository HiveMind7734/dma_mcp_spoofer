"""autoboot.py — automatic discovery of the walk's bootstrap values.

The process walk needs two values that can change when the host boots:
the system page-table root (kernel DTB) and the kernel VA of one live
process struct (the anchor). Both used to be recorded by hand and went
stale on every reboot; this module derives them from raw physical memory
instead, so nothing has to be recorded per host and a reboot just works:

  1. Kernel DTB: sweep low physical memory in-buffer for self-
     referencing level-4 pages — an entry whose frame equals its own
     page address (the self-map every x64 address space carries, at a
     build-randomized slot). The system root is a boot allocation and
     sits low; candidates are ranked by how much kernel half they map.
  2. System's struct: sweep all of memory for the 8-byte little-endian
     value of that DTB — of all kernel objects, only System's EPROCESS
     stores the kernel DTB in its DirectoryTableBase (+0x28, stable since
     Win7). Each hit is shape-validated: self-referential list heads at
     +0x08/+0x10 and +0x18/+0x20, and the qword at +0x28 really naming a
     self-referencing level-4 page. The struct's own kernel VA falls out
     of the self-list values, so the anchor needs no walk to be derived.
  3. The pair is validated through the production anchor-based walk,
     then cached in config/bootstrap.json; a cache that no longer
     validates (host rebooted) falls through to a fresh scan, so the
     cache is an accelerator, never a dependency.

No pool tags are used: modern builds don't tag these allocations the
classic way (verified on a live 24H2 host — no header at struct-0x10),
while the DTB/self-list shape above is build-independent.

Cost after a reboot: the level-4 scan covers low memory in seconds, and
the needle sweep is C-speed over the window — System's struct is usually
found within the first several GB (tens of seconds). Progress notes go
to the server log.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import time

from .phys import PhysWindow
from .procs import ProcessList, WALK_WINDOW
from .va import MASK

DTB_OFF = 0x28              # KPROCESS.DirectoryTableBase (stable since Win7)
SCAN_CHUNK = 4 << 20        # sweep granularity (16-page aligned)
LOW_SCAN_LIMIT = 1 << 30    # how far to look for the system level-4 page
MIN_KERNEL_HALF = 8         # present high-half entries for a plausible root
MAX_CANDIDATES = 24         # validated structs tried before giving up
RETRY_COOLDOWN = 10.0       # min seconds between full sweeps
CACHE_NAME = "bootstrap.json"

_DEFAULT_CONFIG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")


def _log(msg: str) -> None:
    """Server log only — this text never reaches MCP clients."""
    print(f"autoboot: {msg}", file=sys.stderr, flush=True)


def is_self_referencing_pml4(phys: PhysWindow, dtb: int) -> bool:
    """True if `dtb` names a level-4 table that maps itself — the self-map
    entry whose frame equals the table's own address. Cheap and virtually
    false-positive-free; used to validate DTBs found in candidates."""
    dtb &= MASK
    if not (0x1000 < dtb < phys.size):
        return False
    try:
        page = phys.read(dtb, 0x1000)
    except IOError:
        return False
    for i in range(512):
        e = struct.unpack_from("<Q", page, i * 8)[0]
        if (e & MASK) == dtb and (e & 3) == 3:      # present|rw, own frame
            return True
    return False


def find_kernel_dtb(phys: PhysWindow, log=_log) -> int:
    """Sweep low physical memory for self-referencing level-4 pages and
    return the one that looks most like the system root (most kernel-half
    entries mapped)."""
    needle_end = min(LOW_SCAN_LIMIT, phys.size)
    best = (0, None)            # (present high-half entries, pa)
    pos = 0
    while pos < needle_end:
        n = min(SCAN_CHUNK, needle_end - pos)
        try:
            data = phys.read(pos, n)
        except IOError as e:
            log(f"dtb scan: unreadable span at 0x{pos:X} ({e}); skipping")
            pos += n
            continue
        for off in range(0, n - 0xFFF, 0x1000):
            page = data[off:off + 0x1000]
            # C-speed prefilters: all-zero pages, then any-present check
            # on every entry's low byte, before the full unpack loop
            if not any(page):
                continue
            if not any(page[j] & 1 for j in range(0, 0x1000, 8)):
                continue
            pa = pos + off
            present_hi = 0
            selfmap = False
            for i in range(512):
                e = struct.unpack_from("<Q", page, i * 8)[0]
                if not e & 1:
                    continue
                if i >= 256:
                    present_hi += 1
                if (e & MASK) == pa and (e & 3) == 3:
                    selfmap = True
            if selfmap and present_hi >= MIN_KERNEL_HALF:
                log(f"dtb scan: level-4 candidate at 0x{pa:X} "
                    f"({present_hi} kernel-half entries)")
                if present_hi > best[0]:
                    best = (present_hi, pa)
                if best[0] >= 64:        # maps plenty of kernel space — done
                    break
        if best[0] >= 64:
            break
        pos += n
    if best[1] is None:
        raise RuntimeError("bootstrap failed: no self-mapping level-4 page "
                           "found in low memory")
    return best[1]


def _validate_shape(phys: PhysWindow, struct_pa: int) -> dict | None:
    """Check an EPROCESS-shaped struct at a physical address; return the
    candidate dict (with the struct's kernel VA from its self-list) or
    None. The window is zero-padded to the walk length: fields past the
    physical page it starts in may belong to an unrelated allocation."""
    try:
        head = phys.read(struct_pa, 0x40)
    except IOError:
        return None
    q = struct.unpack("<8Q", head)
    # self-referential list heads: ProfileListHead (+0x08/+0x10) always;
    # the pair at +0x18/+0x20 on every build checked so far
    if not (q[1] == q[2] and (q[1] >> 48) == 0xFFFF):
        return None
    if not (q[3] == q[4] and (q[3] >> 48) == 0xFFFF):
        return None
    dtb = q[5]
    if not is_self_referencing_pml4(phys, dtb):
        return None
    try:
        window = phys.read(struct_pa, 0x800)
    except IOError:
        window = head
    return {"eproc_pa": struct_pa, "dtb": dtb,
            "va": q[1] - 0x08,
            "window": window.ljust(WALK_WINDOW, b"\x00")}


def iter_system_candidates(phys: PhysWindow, kdtb: int, log=_log):
    """Yield validated EPROCESS candidates found by sweeping memory for
    the kernel-DTB qword. System's struct is normally the only real hit;
    incidental copies of the value elsewhere fail the shape check."""
    needle = struct.pack("<Q", kdtb & MASK)
    phys.drop_cache()
    pos = 0
    reported = 0
    found = 0
    while pos < phys.size and found < MAX_CANDIDATES:
        n = min(SCAN_CHUNK, phys.size - pos)
        try:
            data = phys.read(pos, n)
        except IOError as e:
            log(f"scan: unreadable span at 0x{pos:X} ({e}); skipping")
            pos += n
            continue
        i = 0
        while found < MAX_CANDIDATES:
            i = data.find(needle, i)
            if i < 0:
                break
            hit = pos + i
            i += 1
            if hit % 16 == 8:                 # struct 16-aligned, DTB at +0x28
                cand = _validate_shape(phys, hit - DTB_OFF)
                if cand is not None:
                    found += 1
                    log(f"scan: candidate struct at pa 0x{cand['eproc_pa']:X} "
                        f"(dtb 0x{cand['dtb']:X}, va 0x{cand['va']:X})")
                    yield cand
        if log and pos - reported >= (1 << 30):
            log(f"scan: swept 0x{pos >> 30:X} GiB of 0x{phys.size >> 30:X} GiB")
            reported = pos
        pos += n


def bootstrap(phys: PhysWindow, log=_log) -> tuple[int, int, list[dict]]:
    """Derive (kernel_dtb, anchor_eproc, entries) from physical memory.
    System's own struct is the anchor (it never exits)."""
    kdtb = find_kernel_dtb(phys, log)
    log(f"bootstrap: kernel dtb 0x{kdtb:X}")
    for cand in iter_system_candidates(phys, kdtb, log):
        anchor = cand["va"]
        try:
            # full walk from the candidate's raw window confirms the list
            entries = ProcessList.scan_from_window(phys, kdtb, cand["window"])
            if entries:
                system = next((e for e in entries
                               if e["pid"] == 4 or e["name"] == "System"),
                              None)
                if system is not None:
                    anchor = system["eproc"]
            # final say: the production anchor-based walk must succeed
            procs = ProcessList(kdtb, anchor).scan(phys)
        except Exception:
            continue
        log(f"bootstrap: anchor 0x{anchor:X}, {len(procs)} processes")
        return kdtb, anchor, procs
    raise RuntimeError(
        "bootstrap failed: no valid process-list anchor found in memory")


class Bootstrapper:
    """Resolves the walk's bootstrap values: explicit hints first (env /
    config — deliberate operator input wins), then the on-disk cache,
    then a full automatic scan. Whatever is chosen is validated by
    actually walking the process list, so a value from a previous boot
    can never be used."""

    def __init__(self, phys: PhysWindow,
                 hints: list[tuple[int, int]] = (),
                 config_dir: str | None = None, log=_log):
        self.phys = phys
        self.hints = [(int(a), int(b)) for a, b in hints if a and b]
        self.config_dir = config_dir or _DEFAULT_CONFIG_DIR
        self.log = log
        self.plist: ProcessList | None = None
        self._last_scan = 0.0

    def resolve(self, force: bool = False) -> ProcessList:
        """Return a validated ProcessList, discovering values if needed.
        force=True skips hints and cache and re-derives from scratch."""
        if self.plist is not None and not force:
            return self.plist
        pairs = list(self.hints)
        if not force:
            cached = self._cache_pair()
            if cached:
                pairs.append(cached)
        for kdtb, anchor in pairs:
            try:
                ProcessList(kdtb, anchor).scan(self.phys)
            except Exception:
                continue
            self.plist = ProcessList(kdtb, anchor)
            return self.plist
        now = time.monotonic()
        if now - self._last_scan < RETRY_COOLDOWN:
            raise RuntimeError("bootstrap: rescan suppressed (cooldown)")
        self._last_scan = now
        kdtb, anchor, _procs = bootstrap(self.phys, self.log)
        self.plist = ProcessList(kdtb, anchor)
        self._save_cache(kdtb, anchor)
        return self.plist

    # ── cache ─────────────────────────────────────────────────────────────
    @property
    def cache_path(self) -> str:
        return os.path.join(self.config_dir, CACHE_NAME)

    def _cache_pair(self) -> tuple[int, int] | None:
        try:
            with open(self.cache_path, "r") as f:
                c = json.load(f)
            return (int(str(c["kernel_dtb"]), 0),
                    int(str(c["anchor_eproc"]), 0))
        except Exception:
            return None

    def _save_cache(self, kdtb: int, anchor: int) -> None:
        try:
            os.makedirs(self.config_dir, exist_ok=True)
            with open(self.cache_path, "w") as f:
                json.dump({
                    "kernel_dtb": f"0x{kdtb:X}",
                    "anchor_eproc": f"0x{anchor:X}",
                    "window_size": self.phys.size,
                    "resolved": time.strftime("%Y-%m-%d %H:%M:%S"),
                }, f, indent=1)
        except OSError as e:
            self.log(f"cache write skipped: {e}")
