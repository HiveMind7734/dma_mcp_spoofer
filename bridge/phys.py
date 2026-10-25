"""phys.py — flat physical memory window.

The only module that knows a "DMA card" exists. Everything above this layer
speaks virtual addresses. The physical source is either the live FUSE mount
maintained by pcileech, or (for development) a flat .bin capture. Both look
identical from above: seek(offset) + read(n).
"""

from __future__ import annotations

import os
import time

DEFAULT_LIVE_PATH = "/mnt/MEMPROCFS/liveram-native.raw"

_REOPEN_COOLDOWN = 2.0


class PhysWindow:
    """Seek/read over physical memory. VA layers sit on top of this.

    Liveness: the kernel happily caches this file's pages and would replay
    stale bytes forever. Callers must invoke drop_cache() once per logical
    read operation (facade does this); after it, everything fetched is
    live. Read failures attempt one transparent reopen (rate-limited) so a
    replaced mount heals instead of serving errors forever.
    """

    def __init__(self, path: str | None = None):
        self.path = (path or os.environ.get("PROCMEM_SRC")
                     or os.environ.get("MEMPROCFS_PATH") or DEFAULT_LIVE_PATH)
        if not self.path:
            raise FileNotFoundError("memory source not configured")
        if not os.path.exists(self.path):
            raise FileNotFoundError(
                f"memory window unavailable: {self.path} "
                f"(is the link mounted?)"
            )
        self._open()
        self._last_reopen = 0.0

    def _open(self) -> None:
        self.f = open(self.path, "rb", buffering=0)
        self.f.seek(0, 2)
        self.size = self.f.tell()
        self.f.seek(0)

    def _reopen(self) -> None:
        """Re-open the path — picks up a fresh inode if the source was
        replaced (e.g. the memory window was remounted under us)."""
        self._last_reopen = time.monotonic()
        try:
            self.f.close()
        except Exception:
            pass
        if os.path.exists(self.path):
            try:
                self._open()
            except Exception:
                pass

    def drop_cache(self) -> None:
        """Drop the kernel's cached pages for the whole source. Call once
        at the start of each logical read operation — after this, every
        page fetched is live. (Range-based fadvise is NOT sufficient for
        this FUSE file; whole-file eviction is.)"""
        try:
            os.posix_fadvise(self.f.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
        except OSError:
            pass

    def read(self, pa: int, size: int) -> bytes:
        """Read [pa, pa+size) from physical memory."""
        if pa < 0:
            raise IOError(f"negative physical address 0x{pa:X}")
        if pa + size > self.size:
            raise IOError(
                f"read past end of physical memory: pa=0x{pa:X} size=0x{size:X} "
                f"max=0x{self.size:X}"
            )
        for attempt in (0, 1):
            try:
                self.f.seek(pa)
                data = self.f.read(size)
                if len(data) != size:
                    raise IOError(
                        f"short read at pa=0x{pa:X}: got {len(data)} of {size}")
                return data
            except OSError as e:
                if attempt == 0 and time.monotonic() - self._last_reopen > _REOPEN_COOLDOWN:
                    self._reopen()
                    continue
                raise IOError(f"read failed at pa=0x{pa:X}: {e}") from e
        raise IOError(f"read failed at pa=0x{pa:X}")

    def close(self) -> None:
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
