#!/usr/bin/env python3
"""selftest.py — structural tests that don't need the physical window.

Verifies the parts that make the illusion work:
  1. allowlist filtering — non-listed images are invisible
  2. error parity — unknown pid and non-allowlisted pid return the SAME error
  3. handle lifecycle — invalid/closed handles give error 6
  4. typed reads and format validation
  5. no backend vocabulary in any client-visible error
  6. automatic bootstrap — the walk anchors are discovered from a
     synthetic memory image (self-map level-4 scan, DTB-needle struct
     scan, shape validation, list walk, caching, stale-cache recovery),
     with no recorded values anywhere

With the physical window mounted, run with --live for an end-to-end smoke
test (list_processes -> open D2R -> read module header).
"""

from __future__ import annotations

import json
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bridge.autoboot import (Bootstrapper, bootstrap, iter_system_candidates)
from bridge.facade import Facade, FacadeError
from bridge.procs import ProcessCache, ProcessList


class _FakePhys:
    size = 0x800000000  # 32GB placeholder

    def read(self, pa, size):
        return b"\x00" * size

    def close(self):
        pass


class _FakeCache(ProcessCache):
    """Injects a synthetic process table so no kernel walk is needed."""

    FAKE = [
        {"eproc": 0xFFFF000000000001, "pid": 4,    "name": "System",    "dtb": 0x1AE000},
        {"eproc": 0xFFFF000000000002, "pid": 908,  "name": "services.exe", "dtb": 0x2000000},
        {"eproc": 0xFFFF000000000003, "pid": 1234, "name": "D2R.exe",   "dtb": 0x865A6A000},
        {"eproc": 0xFFFF000000000004, "pid": 5678, "name": "explorer.exe", "dtb": 0x3000000},
    ]

    def snapshot(self, force: bool = False):
        return list(self.FAKE)

    def by_pid(self, pid):
        for e in self.FAKE:
            if e["pid"] == pid:
                return e
        return None


def make_facade() -> Facade:
    f = Facade.__new__(Facade)  # skip PhysWindow-dependent __init__
    f.allowed_names = {"d2r.exe"}
    f.phys = _FakePhys()
    f.cache = _FakeCache(None, f.phys)
    f._handles = {}
    f._next_handle = 0x1F4
    f._is_live = lambda entry: True   # liveness needs real page tables
    return f


# ── synthetic memory image (bootstrap tests) ──────────────────────────────

class _ImagePhys:
    """Sparse page-backed physical memory, zero-filled on demand."""

    def __init__(self, size: int):
        self.size = size
        self.pages: dict[int, bytearray] = {}

    def page(self, pa: int) -> bytearray:
        pg = self.pages.get(pa)
        if pg is None:
            pg = bytearray(0x1000)
            self.pages[pa] = pg
        return pg

    def drop_cache(self):
        pass

    def read(self, pa: int, size: int) -> bytes:
        if pa < 0 or pa + size > self.size:
            raise IOError(f"oob read 0x{pa:X}+0x{size:X}")
        out = bytearray(size)
        off = 0
        while off < size:
            cur = pa + off
            base = cur & ~0xFFF
            n = min(0x1000 - (cur - base), size - off)
            pg = self.pages.get(base)
            if pg is not None:
                o = cur - base
                out[off:off + n] = pg[o:o + n]
            off += n
        return bytes(out)

    def close(self):
        pass


class _Image:
    """A miniature Windows-shaped memory image: one kernel address space
    (self-referencing PML4 + kernel-half mappings) and a circular list of
    EPROCESS-shaped structs at varied offsets, plus decoys that look
    almost right. Everything the discovery pass needs, nothing else."""

    POOL_BASE = 0xFFFFA00000000000
    LINKS_OFF = 0x448
    NAME_OFF = 0x5A8

    def __init__(self):
        self.phys = _ImagePhys(0x8000000)          # 128 MB
        self._next_pa = 0x200000
        self.kdtb = self._alloc()
        struct.pack_into("<Q", self.phys.page(self.kdtb), 0x1ED * 8,
                         self.kdtb | 0x23)          # self-map entry
        self.entries: list[dict] = []
        # filler kernel mappings: a root with <=4 present entries would
        # read as 5-level paging; real kernels have many more
        for i in range(6):
            self.map(self.kdtb, 0xFFFF880000000000 + (i << 39), self._alloc())

    def _alloc(self) -> int:
        pa = self._next_pa
        self._next_pa += 0x1000
        return pa

    def map(self, kdtb: int, va: int, pa: int):
        """Install one 4K va->pa mapping, building intermediate tables."""
        e = kdtb
        for shift in (39, 30, 21):
            table = self.phys.page(e)
            idx = (va >> shift) & 0x1FF
            v = struct.unpack_from("<Q", table, idx * 8)[0]
            if not v & 1:
                nxt = self._alloc()
                struct.pack_into("<Q", table, idx * 8, nxt | 0x3)
                v = nxt | 0x3
            e = v & ~0xFFF
        table = self.phys.page(e)
        struct.pack_into("<Q", table, ((va >> 12) & 0x1FF) * 8, pa | 0x3)

    def add_process(self, name: str, pid: int, off: int = 0x0) -> dict:
        pa = self._alloc()
        va = self.POOL_BASE + len(self.entries) * 0x4000
        self.map(self.kdtb, va, pa)
        base = off                              # struct start (16-aligned)
        pg = self.phys.page(pa)
        struct.pack_into("<Q", pg, base + 0x08, va + base + 0x08)  # self-lists
        struct.pack_into("<Q", pg, base + 0x10, va + base + 0x08)
        struct.pack_into("<Q", pg, base + 0x18, va + base + 0x18)
        struct.pack_into("<Q", pg, base + 0x20, va + base + 0x18)
        struct.pack_into("<Q", pg, base + 0x28, self.kdtb)         # DTB
        struct.pack_into("<Q", pg, base + self.LINKS_OFF - 8, pid)
        nm = name.encode()
        pg[base + self.NAME_OFF:base + self.NAME_OFF + len(nm)] = nm
        entry = {"name": name, "pid": pid, "eproc": va + base,
                 "dtb": self.kdtb, "page": pa, "base": base}
        self.entries.append(entry)
        return entry

    def close_list(self):
        """Circular ActiveProcessLinks through all added processes."""
        for i, e in enumerate(self.entries):
            fl = self.entries[(i + 1) % len(self.entries)]["eproc"] + self.LINKS_OFF
            bl = self.entries[(i - 1) % len(self.entries)]["eproc"] + self.LINKS_OFF
            struct.pack_into("<QQ", self.phys.page(e["page"]),
                             e["base"] + self.LINKS_OFF, fl, bl)

    def add_decoys(self):
        # the DTB needle at a checked slot, but no EPROCESS shape -> rejected
        pg = self.phys.page(self._alloc())
        struct.pack_into("<Q", pg, 0x28, self.kdtb)
        # right shape, but +0x28 names a non-self-referencing table
        tbl = self._alloc()
        for i in range(4):
            struct.pack_into("<Q", self.phys.page(tbl), i * 8, 0x6000000 | 3)
        pg2 = self.phys.page(self._alloc())
        va2 = self.POOL_BASE + 0x40000 * 64        # 0xffff VA, unmapped is fine
        struct.pack_into("<QQ", pg2, 0x08, va2 + 0x08, va2 + 0x08)
        struct.pack_into("<QQ", pg2, 0x18, va2 + 0x18, va2 + 0x18)
        struct.pack_into("<Q", pg2, 0x28, tbl)
        # misaligned needle copy — positions not at 16k+8 are ignored
        pg3 = self.phys.page(self._alloc())
        struct.pack_into("<Q", pg3, 0x24, self.kdtb)


def build_image() -> _Image:
    img = _Image()
    for name, pid, off in [("System", 4, 0x0), ("smss.exe", 324, 0x10),
                           ("csrss.exe", 480, 0x30), ("services.exe", 620, 0x40),
                           ("explorer.exe", 2244, 0x0), ("D2R.exe", 4180, 0x10)]:
        img.add_process(name, pid, off)
    img.close_list()
    img.add_decoys()
    return img


def bootstrap_tests() -> bool:
    from bridge import autoboot
    quiet = lambda msg: None                      # noqa: E731
    img = build_image()
    ok = True

    # 6a. DTB-needle scan finds exactly the planted structs; decoys rejected
    cands = list(iter_system_candidates(img.phys, img.kdtb, log=quiet))
    ok &= check("DTB-needle scan finds the planted structs", len(cands) == 6,
                f"got {len(cands)}")

    # 6b. full derivation: System becomes the anchor, kernel DTB resolved
    kdtb, anchor, procs = bootstrap(img.phys, log=quiet)
    sys_eproc = next(e["eproc"] for e in img.entries if e["name"] == "System")
    ok &= check("bootstrap picks System as anchor", anchor == sys_eproc,
                hex(anchor))
    ok &= check("bootstrap resolves the kernel dtb", kdtb == img.kdtb, hex(kdtb))
    ok &= check("bootstrap walks every struct", len(procs) == 6, str(len(procs)))

    # 6c. Bootstrapper: cache write, stale-cache recovery, facade path
    with tempfile.TemporaryDirectory() as td:
        b = Bootstrapper(img.phys, config_dir=td, log=quiet)
        pl = b.resolve()
        ok &= check("bootstrapper resolves from scratch",
                    (pl.kernel_dtb, pl.anchor_eproc) == (kdtb, anchor))
        ok &= check("bootstrap cache written",
                    os.path.exists(os.path.join(td, autoboot.CACHE_NAME)))
        with open(os.path.join(td, autoboot.CACHE_NAME), "w") as f:
            json.dump({"kernel_dtb": "0x1AE000",
                       "anchor_eproc": "0xFFFFDEAD00000000"}, f)
        b2 = Bootstrapper(img.phys, config_dir=td, log=quiet)
        pl2 = b2.resolve()
        ok &= check("stale cache falls through to a fresh scan",
                    (pl2.kernel_dtb, pl2.anchor_eproc) == (kdtb, anchor))
        # facade end-to-end on the image: no [target] in config at all
        cfgp = os.path.join(td, "allowlist.toml")
        with open(cfgp, "w") as f:
            f.write('version = 1\n\n[allowlist]\nprocesses = ["D2R.exe"]\n')
        fac = Facade(img.phys, config_path=cfgp)
        fac._is_live = lambda entry: True
        listed = fac.list_processes()
        ok &= check("facade lists D2R via auto-bootstrap",
                    listed == [{"pid": 4180, "name": "D2R.exe"}], str(listed))

    return ok


def check(label: str, cond: bool, detail: str = "") -> bool:
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {label}" + (f"  ({detail})" if detail and not cond else ""))
    return cond


def live() -> int:
    """End-to-end: list -> open -> module header read. Needs the window up."""
    from bridge import Facade, PhysWindow
    f = Facade(PhysWindow())
    procs = f.list_processes()
    print("processes:", procs)
    if not procs:
        print("no allowlisted process running (or walk failed)")
        return 1
    h = f.open_process(procs[0]["pid"])
    mods = f.list_modules(h)
    main_mod = next((m for m in mods if m["name"].lower() == procs[0]["name"].lower()),
                    mods[0])
    r = f.read_process_memory(h, main_mod["base"], 64)
    head = bytes.fromhex(r["data"])[:2]
    print(f"{main_mod['name']} @ 0x{main_mod['base']:X} header: {head!r}")
    print("OK" if head == b"MZ" else "BAD HEADER")
    return 0 if head == b"MZ" else 1


def main() -> int:
    if "--live" in sys.argv:
        return live()

    ok = True

    # 1. allowlist filtering
    f = make_facade()
    procs = f.list_processes()
    ok &= check("only allowlisted processes visible",
                [p["name"] for p in procs] == ["D2R.exe"], str(procs))
    ok &= check("listed entry has pid+name",
                procs == [{"pid": 1234, "name": "D2R.exe"}], str(procs))

    # 2. error parity: unknown pid vs non-allowlisted pid
    try:
        f.open_process(99999)
        ok &= check("unknown pid rejected", False)
    except FacadeError as e:
        ok &= check("unknown pid rejected", True)
        msg_unknown = e.message
    try:
        f.open_process(5678)  # explorer.exe — running but not allowlisted
        ok &= check("non-allowlisted pid rejected", False)
    except FacadeError as e:
        msg_blocked = e.message
    ok &= check("blocked == unknown (indistinguishable)",
                msg_unknown == msg_blocked,
                f"{msg_unknown!r} vs {msg_blocked!r}")

    # 3. handle lifecycle
    h = f.open_process(1234)
    ok &= check("open allowlisted pid returns handle", isinstance(h, int))
    ok &= check("handle is 4-aligned (win32-shaped)", h % 4 == 0, str(h))
    try:
        f.read_process_memory(h + 1, 0x140000, 16)
        ok &= check("bogus handle rejected", False)
    except FacadeError as e:
        ok &= check("bogus handle rejected", "error 6" in e.message, e.message)
    f.close_handle(h)
    try:
        f.read_process_memory(h, 0x140000, 16)
        ok &= check("closed handle rejected", False)
    except FacadeError as e:
        ok &= check("closed handle rejected", "error 6" in e.message, e.message)

    # 4. size/format validation
    try:
        h2 = f.open_process(1234)
        f.read_process_memory(h2, 0x140000, 0)
        ok &= check("zero-size read rejected", False)
    except FacadeError as e:
        ok &= check("zero-size read rejected", "error 87" in e.message, e.message)

    # 5. no-leak scan: allowlist/config words must not appear in any error
    leaks = ("allowlist", "dma", "pcileech", "memprocfs", "ft601", "toml",
             "anchor", "eprocess")
    samples = [msg_unknown, msg_blocked,
               FacadeError("x").message]
    try:
        f.list_modules(0x1F4)
    except FacadeError as e:
        samples.append(e.message)
    bad = [s for s in samples
           if any(w in s.lower() for w in leaks)]
    ok &= check("no backend vocabulary in errors", not bad, str(bad))

    # 6. automatic bootstrap on the synthetic image
    ok &= bootstrap_tests()

    print("\nALL PASS" if ok else "\nFAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
