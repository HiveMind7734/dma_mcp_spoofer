"""procs.py — process discovery via kernel structure walk.

Enumerates processes by walking the OS-internal process list, exactly like
the proven find_eproc.py approach: bootstrap from a known-readable kernel
address (the "anchor"), locate the list-link offset dynamically (build-
independent), walk the circular list, and pull PID / image name / page-table
root (DTB) out of each entry. Nothing here is game-specific.
"""

from __future__ import annotations

import struct
import time

from .phys import PhysWindow
from .va import VAReader

# Windows x64: DirectoryTableBase sits at +0x28 in the process struct on
# every build from Win7 through Win11. UniqueProcessId always immediately
# precedes ActiveProcessLinks in the layout, so once the links offset is
# found dynamically, PID = QWORD at links-8.
DTB_OFF = 0x28

WALK_WINDOW = 0x1800          # bytes read per process entry
MAX_PROCS = 1024              # hard stop for the list walk
LIST_STALE_SEC = 5.0          # cache duration for the process snapshot


def _ascii_runs(buf: bytes, min_len: int = 3, max_len: int = 15) -> list[str]:
    """Printable ASCII runs that look like image file names."""
    runs = []
    cur = bytearray()
    for b in buf:
        if 32 <= b < 127 and (chr(b).isalnum() or chr(b) in ".-_ "):
            cur.append(b)
        else:
            if min_len <= len(cur) <= max_len:
                runs.append(cur.decode("ascii"))
            cur = bytearray()
    if min_len <= len(cur) <= max_len:
        runs.append(cur.decode("ascii"))
    return runs


class ProcessList:
    """Snapshot of running processes visible through the physical window."""

    WALK_WINDOW = WALK_WINDOW   # bytes read per process entry (class-visible)

    def __init__(self, kernel_dtb: int, anchor_eproc: int):
        self.kernel_dtb = kernel_dtb
        self.anchor_eproc = anchor_eproc

    def scan(self, phys: PhysWindow) -> list[dict]:
        """Walk the process list. Returns entries:
        [{eproc, pid, name, dtb}] — pid may be None if extraction failed.
        """
        k = VAReader(self.kernel_dtb, phys)
        anchor = k.read(self.anchor_eproc, WALK_WINDOW)
        return self.scan_from_window(phys, self.kernel_dtb, anchor,
                                     self_va=self.anchor_eproc)

    @staticmethod
    def scan_from_window(phys: PhysWindow, dtb: int, window: bytes,
                         self_va: int | None = None) -> list[dict]:
        """Walk the process list starting from the raw bytes of one process
        struct, using `dtb` (any address space that maps kernel space) to
        translate the list links. Used by scan() with the anchor's VA; the
        discovery pass in autoboot.py calls it with a struct found by
        physical scan, where no kernel VA is known yet (self_va=None).

        Candidate LIST_ENTRYs: both pointers kernel (0xFFFF-prefixed)
        addresses, forward link pointing outside the entry window (when
        the entry's own VA is known). Several lists chain through
        EPROCESS-shaped structs (session lists etc.); the true process
        list is the one whose preceding QWORD (UniqueProcessId sits 8
        before ActiveProcessLinks) is a small DISTINCT integer per entry
        — session ids repeat, pids don't. Score candidates on that, then
        walk the winner fully.
        """
        k = VAReader(dtb, phys)
        candidates = []
        for off in range(0x30, min(WALK_WINDOW, len(window)) - 16, 8):
            fl, bl = struct.unpack_from("<QQ", window, off)
            if (fl >> 48) == 0xFFFF and (bl >> 48) == 0xFFFF and fl != bl:
                if (self_va is None
                        or not (self_va <= fl <= self_va + WALK_WINDOW)):
                    candidates.append(off)

        best_score = (-1, -1)
        best_off = None
        for links_off in candidates:
            chain = ProcessList._walk(k, links_off, window, max_entries=16)
            pids = set()
            for _va, data in chain:
                v = struct.unpack_from("<Q", data, links_off - 8)[0]
                if 4 <= v <= 0x40000:
                    pids.add(v)
            score = (len(pids), len(chain))
            if score > best_score:
                best_score, best_off = score, links_off
            if len(pids) >= 16:
                break
        if best_off is None or best_score[0] < 4:
            raise RuntimeError("could not locate the process list in the entry")

        procs = []
        for va, data in ProcessList._walk(k, best_off, window):
            entry = ProcessList._parse_entry(va, data, best_off, phys)
            if entry is not None:
                procs.append(entry)
        return procs

    @staticmethod
    def _walk(k: VAReader, links_off: int, window: bytes,
              max_entries: int = MAX_PROCS) -> list[tuple[int, bytes]]:
        """Follow one candidate chain; returns [(eproc_va, window_bytes)].
        Starts at the entry the window's forward link points at."""
        chain: list[tuple[int, bytes]] = []
        seen: set[int] = set()
        cur = struct.unpack_from("<Q", window, links_off)[0] - links_off
        while cur not in seen and len(chain) < max_entries:
            seen.add(cur)
            try:
                data = k.read(cur, WALK_WINDOW)
            except Exception:
                break
            chain.append((cur, data))
            nxt = struct.unpack_from("<Q", data, links_off)[0]
            if (nxt >> 48) != 0xFFFF:
                break
            cur = nxt - links_off
        return chain

    @staticmethod
    def _parse_entry(va: int, data: bytes, links_off: int,
                     phys: PhysWindow) -> dict | None:
        dtb = struct.unpack_from("<Q", data, DTB_OFF)[0]
        if not (0x1000 < dtb < phys.size and dtb % 0x1000 == 0):
            return None
        pid = None
        if links_off >= 8:
            cand = struct.unpack_from("<Q", data, links_off - 8)[0]
            if 0 < cand < 0x1000000:
                pid = cand
        runs = _ascii_runs(data)
        name = ProcessList._pick_name(runs)
        if name is None:
            return None
        return {"eproc": va, "pid": pid, "name": name, "dtb": dtb}

    @staticmethod
    def _pick_name(runs: list[str]) -> str | None:
        # ImageFileName is a 15-byte ASCII field; prefer .exe images, then
        # the System idle/System processes, else the first plausible run.
        for r in runs:
            if r.lower().endswith(".exe") and 4 <= len(r) <= 15:
                return r
        for r in runs:
            if r in ("System", "Registry", "Idle", "MemCompression"):
                return r
        return runs[0] if runs else None


class ProcessCache:
    """Caches the process snapshot so tool calls don't re-walk every time."""

    def __init__(self, plist: ProcessList, phys: PhysWindow,
                 stale_sec: float = LIST_STALE_SEC):
        self.plist = plist
        self.phys = phys
        self.stale_sec = stale_sec
        self._entries: list[dict] | None = None
        self._ts: float = 0.0

    def snapshot(self, force: bool = False) -> list[dict]:
        now = time.monotonic()
        if (force or self._entries is None
                or now - self._ts > self.stale_sec):
            self._entries = self.plist.scan(self.phys)
            self._ts = now
        return self._entries

    def by_pid(self, pid: int) -> dict | None:
        for e in self.snapshot():
            if e["pid"] == pid:
                return e
        return None
