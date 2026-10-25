#!/usr/bin/env python3
"""probe_eprocess_layout.py — learn this host's real EPROCESS layout.

Two passes over the live window (run with sudo):
  1. low-memory sweep for self-referencing PML4 pages -> kernel DTB candidates
  2. sweep for ASCII image-name strings (D2R.exe / explorer.exe / svchost.exe)
     -> for each hit, walk backwards looking for a QWORD that validates as a
     self-referencing PML4 physical address (the DTB), and dump the bytes
     around it: reveals struct start, DTB offset, name offset, pool header.
"""
import struct
import sys

sys.path.insert(0, __import__("os").path.join(
    __import__("os").path.dirname(__import__("os").path.abspath(__file__)), ".."))
from bridge import PhysWindow
from bridge.va import MASK

CHUNK = 8 << 20


def self_ref_pml4(phys, pa):
    if pa & 0xFFF or not (0x1000 < pa < phys.size):
        return None
    try:
        page = phys.read(pa, 0x1000)
    except IOError:
        return None
    hits = []
    for i in range(512):
        e = struct.unpack_from("<Q", page, i * 8)[0]
        if (e & MASK) == pa and (e & 1):
            hits.append(i)
    return hits or None


def pass1(phys):
    print("== pass 1: self-referencing PML4 pages below 256 MB ==")
    found = []
    for pa in range(0x1000, min(0x10000000, phys.size), 0x1000):
        idx = self_ref_pml4(phys, pa)
        if idx:
            found.append((pa, idx))
            if len(found) >= 12:
                break
    for pa, idx in found:
        page = phys.read(pa, 0x1000)
        n_present = sum(1 for i in range(512)
                        if struct.unpack_from("<Q", page, i * 8)[0] & 1)
        print(f"  pa=0x{pa:X} selfmap@{[hex(i) for i in idx]} "
              f"present={n_present}")
    return found


def pass2(phys):
    print("== pass 2: image-name strings -> struct layout ==")
    needles = [b"D2R.exe\x00", b"explorer.exe\x00", b"svchost.exe\x00"]
    shown = {n: 0 for n in needles}
    pos = 0
    while pos < phys.size and any(v < 6 for v in shown.values()):
        n = min(CHUNK, phys.size - pos)
        try:
            data = phys.read(pos, n)
        except IOError:
            pos += n
            continue
        for needle in needles:
            if shown[needle] >= 6:
                continue
            i = 0
            while shown[needle] < 6:
                i = data.find(needle, i)
                if i < 0:
                    break
                hit_pa = pos + i
                i += 1
                shown[needle] += 1
                examine(phys, needle, hit_pa)
        pos += n
    print("  (hit counts:", {k.decode(): v for k, v in shown.items()}, ")")


def examine(phys, needle, hit_pa):
    lo = hit_pa - 0x800
    if lo < 0:
        return
    try:
        back = phys.read(lo, hit_pa - lo)     # window before the name
    except IOError:
        return
    # every QWORD that could be the DTB (page-aligned PA, self-referencing)
    for off in range(len(back) - 8, 0x100, -8):
        v = struct.unpack_from("<Q", back, off)[0]
        if v & 0xFFF or not (0x1000 < v < phys.size):
            continue
        if not self_ref_pml4(phys, v):
            continue
        qpos = lo + off                        # PA of the DTB qword
        struct_pa = qpos - 0x28                # if DTB sits at +0x28
        name_off = hit_pa - struct_pa          # ImageFileName offset
        print(f"  [{needle.rstrip(bytes([0])).decode()} @0x{hit_pa:X}] "
              f"dtb=0x{v:X} at -0x{hit_pa - qpos:X} -> name offset "
              f"+0x{name_off:X}")
        hdr = phys.read(max(struct_pa - 0x20, 0), 0x50)
        print(f"    struct-0x20..+0x30: {hdr.hex(' ', 8)}")
        return


def main():
    with PhysWindow() as phys:
        pass1(phys)
        pass2(phys)


if __name__ == "__main__":
    main()
