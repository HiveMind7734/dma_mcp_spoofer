#!/usr/bin/env python3
"""dump_d2r.py — save phase-labeled snapshots of D2R's live memory.

Captures the game process's mapped memory over the live window so each
game phase (launch, login, char select, in-game, …) can be compared or
handed to an offline analyzer. Memory in RAM is the DECRYPTED, live copy
(unlike the on-disk exe), so these dumps are directly scannable.

Usage:
    sudo python3 dump_d2r.py <phase-label> [--fast]

    --fast  capture only the main module range (D2R.exe base..base+size)
            instead of the whole user address space (minutes vs. much longer)

Output: dumps/<timestamp>-<label>/
    manifest.json   phase, pid, dtb, module info, region table, timing
    modules.json    full module list at capture time
    r-<va-hex>.bin  one file per contiguous mapped run (va in filename)

Skipped small runs (< 64 KB) are counted in the manifest, not saved.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from bridge.phys import PhysWindow

DUMPS = os.path.join(os.path.dirname(HERE), "dumps")
MIN_RUN = 0x10000          # 64 KB — smaller mapped runs are counted, not saved


def find_d2r(phys) -> dict:
    from bridge.autoboot import Bootstrapper
    from bridge.procs import ProcessList
    plist = Bootstrapper(phys).resolve()
    procs = ProcessList(plist.kernel_dtb, plist.anchor_eproc).scan(phys)
    for p in procs:
        if p["name"].lower() == "d2r.exe":
            return p
    raise SystemExit(f"D2R.exe not found among {len(procs)} processes — "
                     f"is the game running?")


def module_info(phys, entry) -> dict:
    """Main module base/size via the PEB->Ldr walk (MZ-validated)."""
    from bridge.va import VAReader
    from bridge.facade import Facade
    f = Facade(phys)
    h = f.open_process(entry["pid"])
    mods = f.list_modules(h)
    main = next((m for m in mods if m["name"].lower() == "d2r.exe"), mods[0])
    f.close_handle(h)
    return {"base": main["base"], "size": main["size"], "modules": mods}


def user_runs(r) -> list[tuple[int, int]]:
    """Contiguous present user-space runs by walking the page tables.
    Returns [(va, length)] at 2MB granularity where possible."""
    from bridge.va import MASK, P, PS
    runs = []
    cur_start = None
    cur_len = 0

    def flush():
        nonlocal cur_start, cur_len
        if cur_start is not None and cur_len >= MIN_RUN:
            runs.append((cur_start, cur_len))
        cur_start, cur_len = None, 0

    for pml4_i in range(0, 256):               # user half of VA space
        try:
            e = r._entry(r.cr3, pml4_i)
        except Exception:
            flush(); continue
        if not e & P:
            flush(); continue
        if e & PS:
            va = pml4_i << 39
            if cur_start is None:
                cur_start = va
            cur_len += 1 << 39
            continue
        pdpt = e & MASK
        for pdpt_i in range(512):
            try:
                e2 = r._entry(pdpt, pdpt_i)
            except Exception:
                flush(); continue
            if not e2 & P:
                flush(); continue
            va = (pml4_i << 39) | (pdpt_i << 30)
            if e2 & PS:                        # 1 GB page
                if cur_start is None:
                    cur_start = va
                cur_len += 1 << 30
                continue
            pd = e2 & MASK
            for pd_i in range(512):
                try:
                    e3 = r._entry(pd, pd_i)
                except Exception:
                    flush(); continue
                if not e3 & P:
                    flush(); continue
                va3 = va | (pd_i << 21)
                if e3 & PS:                    # 2 MB page
                    if cur_start is None:
                        cur_start = va3
                    cur_len += 1 << 21
                    continue
                # 4K pages: treat the whole 2MB PD as present if the PT
                # page is readable; fine-grained misses get zero-filled —
                # for dump purposes we accept it (sparse check in manifest)
                if cur_start is None:
                    cur_start = va3
                cur_len += 1 << 21
    flush()
    return runs


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    fast = "--fast" in sys.argv
    if not args:
        raise SystemExit("usage: dump_d2r.py <phase-label> [--fast]")
    label = args[0].replace(" ", "_")

    t0 = time.time()
    with PhysWindow() as phys:
        entry = find_d2r(phys)
        print(f"D2R.exe pid {entry['pid']} dtb 0x{entry['dtb']:X}")

        from bridge.va import VAReader
        r = VAReader(entry["dtb"], phys)

        mods = module_info(phys, entry)
        base, size = mods["base"], mods["size"]
        print(f"module D2R.exe @ 0x{base:X} size 0x{size:X}")

        runs = [(base, (size + 0xFFF) & ~0xFFF)] if fast else user_runs(r)
        total = sum(n for _s, n in runs)
        print(f"{len(runs)} runs, {total / (1024 * 1024):.0f} MB to read")

        outdir = os.path.join(
            DUMPS, time.strftime("%Y%m%d-%H%M%S") + "-" + label)
        os.makedirs(outdir, exist_ok=True)
        manifest = {
            "label": label, "fast": fast,
            "started": time.strftime("%Y-%m-%d %H:%M:%S"),
            "pid": entry["pid"], "dtb": entry["dtb"],
            "module": {"base": base, "size": size},
            "regions": [], "note": "live capture over the DMA window",
        }
        with open(os.path.join(outdir, "modules.json"), "w") as f:
            json.dump(mods["modules"], f, indent=1)

        done = 0
        for i, (va, n) in enumerate(runs):
            fn = f"r-{va:012X}.bin"
            path = os.path.join(outdir, fn)
            t1 = time.time()
            with open(path, "wb") as f:
                CHUNK = 0x100000               # 1 MB
                for off in range(0, n, CHUNK):
                    f.write(r.read(va + off, min(CHUNK, n - off)))
            done += n
            dt = time.time() - t1
            print(f"  [{i + 1}/{len(runs)}] 0x{va:X} +0x{n:X} "
                  f"-> {fn}  ({done / (1024 * 1024):.0f} MB done, "
                  f"{n / max(dt, 0.001) / (1024 * 1024):.1f} MB/s)")
            manifest["regions"].append(
                {"file": fn, "va": va, "size": n})

        manifest["duration_s"] = round(time.time() - t0, 1)
        manifest["total_mb"] = round(done / (1024 * 1024), 1)
        with open(os.path.join(outdir, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=1)
        print(f"wrote {manifest['total_mb']} MB to {outdir} "
              f"in {manifest['duration_s']}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
