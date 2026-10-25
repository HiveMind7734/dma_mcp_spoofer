"""va.py — process virtual address reader.

Does the same 4-level (or 5-level) page walk the CPU does, on top of a
PhysWindow. One VAReader instance per process address space (keyed by its
CR3/DTB). Page-table pages are cached: MapAssist-style reads cluster in VA
space, so PT pages get reused heavily.
"""

from __future__ import annotations

import struct

from .phys import PhysWindow

MASK = 0x000FFFFFFFFFF000
P = 0x01      # present
US = 0x04     # user
PS = 0x80     # page size (huge pages in PDE/PDPTE)


class VAReader:
    """Read virtual addresses of one process (identified by its CR3)."""

    def __init__(self, cr3: int, phys: PhysWindow):
        self.cr3 = cr3 & MASK
        self.phys = phys
        self.cache: dict[int, bytes] = {}   # page-table page phys -> 4096 bytes
        self.pml5: bool | None = None       # None = untested, set on first translate

    def _entry(self, page_pa: int, idx: int) -> int:
        return struct.unpack_from("<Q", self._page(page_pa), idx * 8)[0]

    def translate(self, va: int) -> tuple[int, int]:
        """auto-detects LA57 vs LA48 on first call; returns (pa, page_size)"""
        if self.pml5 is None:
            # PML5 root: ~1-2 present entries (user/kernel halves).
            # PML4 root: many present entries. Counting discriminates.
            root = self._page(self.cr3)
            n_present = sum(
                1 for i in range(512)
                if struct.unpack_from("<Q", root, i * 8)[0] & P
            )
            self.pml5 = n_present <= 4
        return (self._translate57 if self.pml5 else self._translate48)(va)

    def _translate57(self, va: int) -> tuple[int, int]:
        e = self._entry(self.cr3, (va >> 48) & 0x1FF)
        if not e & P:
            raise ValueError(f"unmapped: PML5 for VA 0x{va:X}")
        if e & PS:
            return (e & MASK) + (va & ((1 << 48) - 1)), 1 << 48
        return self._translate48(va, _pml4=e & MASK)

    def _translate48(self, va: int, _pml4: int | None = None) -> tuple[int, int]:
        pml4e_base = _pml4 if _pml4 is not None else self.cr3
        pml4_i = (va >> 39) & 0x1FF
        pdpt_i = (va >> 30) & 0x1FF
        pd_i = (va >> 21) & 0x1FF
        pt_i = (va >> 12) & 0x1FF

        e = self._entry(pml4e_base, pml4_i)
        if not e & P:
            raise ValueError(f"unmapped: PML4[{pml4_i}] for VA 0x{va:X}")
        if e & PS:
            return (e & MASK) + (va & ((1 << 39) - 1)), 1 << 39

        e = self._entry(e & MASK, pdpt_i)
        if not e & P:
            raise ValueError(f"unmapped: PDPT[{pdpt_i}] for VA 0x{va:X}")
        if e & PS:
            return (e & MASK) + (va & ((1 << 30) - 1)), 1 << 30

        e = self._entry(e & MASK, pd_i)
        if not e & P:
            raise ValueError(f"unmapped: PD[{pd_i}] for VA 0x{va:X}")
        if e & PS:
            return (e & MASK) + (va & ((1 << 21) - 1)), 1 << 21

        e = self._entry(e & MASK, pt_i)
        if not e & P:
            raise ValueError(f"unmapped: PT[{pt_i}] for VA 0x{va:X}")
        return (e & MASK) + (va & 0xFFF), 0x1000

    def _page(self, pa: int) -> bytes:
        pg = self.cache.get(pa)
        if pg is None:
            pg = self.phys.read(pa, 0x1000)
            self.cache[pa] = pg
            if len(self.cache) > 200_000:   # bound memory; ~800MB of PT pages
                self.cache.clear()
        return pg

    def read(self, va: int, size: int) -> bytes:
        """Read size bytes at va. Unmapped/paged-out pages are zero-filled
        (memory-dump semantics), matching ReadProcessMemory on a live system
        closely enough for callers that check their inputs."""
        out = bytearray()
        remaining = size
        cur = va
        while remaining > 0:
            page_off = cur & 0xFFF
            n = min(remaining, 0x1000 - page_off)
            try:
                pa, _sz = self.translate(cur)
                out += self.phys.read(pa, n)
            except (ValueError, IOError):
                out += b"\x00" * n
            cur += n
            remaining -= n
        return bytes(out)

    def read_u16(self, va: int) -> int:
        return struct.unpack("<H", self.read(va, 2))[0]

    def read_u32(self, va: int) -> int:
        return struct.unpack("<I", self.read(va, 4))[0]

    def read_u64(self, va: int) -> int:
        return struct.unpack("<Q", self.read(va, 8))[0]
