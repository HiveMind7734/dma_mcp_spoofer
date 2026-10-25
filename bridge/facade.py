"""facade.py — the client-facing process/memory API.

Presents a conventional Windows-style process-memory surface:
  list_processes / open_process / read_process_memory / list_modules /
  close_handle.

The allowlist lives in config/allowlist.toml and is read here, server-side.
Processes not on the allowlist are indistinguishable from nonexistent ones:
the same Win32-style error comes back either way. Nothing about the allowlist,
the physical window, or the link appears in any tool result or error text.
"""

from __future__ import annotations

import os
import struct
import tomllib

from .autoboot import Bootstrapper
from .phys import PhysWindow
from .procs import ProcessCache, ProcessList
from .va import VAReader

_DEFAULT_CONFIG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config", "allowlist.toml")

# Win32-style errors, phrased the way the real API reports them.
_E_INVALID_PARAMETER = "error 87: The parameter is incorrect"
_E_INVALID_HANDLE = "error 6: The handle is invalid"


def _as_int(v) -> int:
    """Config values arrive as int (tomllib) or str (env); hex allowed in str."""
    return int(v, 0) if isinstance(v, str) else int(v)


class FacadeError(Exception):
    """Carries a client-safe message (no backend details)."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class Facade:
    def __init__(self, phys: PhysWindow, config_path: str | None = None):
        self.phys = phys
        cfg = self._load_config(config_path)
        self.allowed_names: set[str] = {
            n.lower() for n in cfg.get("allowlist", {}).get("processes", [])
        }
        # Bootstrap values are discovered automatically from physical
        # memory (bridge/autoboot.py) and re-derived whenever they stop
        # validating — e.g. after the host reboots. Explicit values are
        # still honored as hints (env beats config), e.g. for debugging.
        cfg_path = (config_path or
                    os.environ.get("MCPDMA_CONFIG", _DEFAULT_CONFIG))
        hints: list[tuple[int, int]] = []
        env_kd = os.environ.get("MCPDMA_KERNEL_DTB")
        env_an = os.environ.get("MCPDMA_ANCHOR_EPROC")
        if env_kd and env_an:
            hints.append((_as_int(env_kd), _as_int(env_an)))
        tgt = cfg.get("target", {})
        if tgt.get("kernel_dtb") and tgt.get("anchor_eproc"):
            hints.append((_as_int(tgt["kernel_dtb"]),
                          _as_int(tgt["anchor_eproc"])))
        self.boot = Bootstrapper(phys, hints=hints,
                                 config_dir=os.path.dirname(cfg_path))
        self._cache: ProcessCache | None = None
        self._handles: dict[int, dict] = {}
        self._next_handle = 0x1F4  # plausible small handle values

    @property
    def cache(self) -> ProcessCache:
        """The process snapshot cache, created on first use (discovery
        runs then, not at server startup, so a dead window doesn't kill
        the server — it surfaces per tool call instead)."""
        if self._cache is None:
            self._cache = ProcessCache(self.boot.resolve(), self.phys)
        return self._cache

    @cache.setter
    def cache(self, value: ProcessCache) -> None:
        self._cache = value

    # ── config ────────────────────────────────────────────────────────────
    @staticmethod
    def _load_config(config_path: str | None) -> dict:
        path = config_path or os.environ.get("MCPDMA_CONFIG", _DEFAULT_CONFIG)
        if not os.path.exists(path):
            return {}
        with open(path, "rb") as f:
            return tomllib.load(f)

    # ── processes ─────────────────────────────────────────────────────────
    def _is_live(self, entry: dict) -> bool:
        """Liveness check: terminated-but-still-linked entries must not
        appear (EnumProcesses never shows them). A live process has a
        resolvable PEB whose first module starts with MZ; a dead one's
        page tables are torn down, so the walk fails."""
        r = VAReader(entry["dtb"], self.phys)
        peb = self._find_peb(r, entry["eproc"])
        if peb is None:
            return False
        try:
            ldr = r.read_u64(peb + 0x18)
            if not (0x10000 < ldr < 0x7FFFFFFFFFFF):
                return False
            cur = r.read_u64(ldr + 0x20)
            base = r.read_u64(cur + 0x20)
            return 0x10000 < base < 0x7FFFFFFFFFFF and r.read(base, 2) == b"MZ"
        except Exception:
            return False

    def _link_ok(self) -> bool:
        """Cheap window health probe: reads must succeed AND at least one
        spread-out page must have content — after a host reboot under a
        stale mount the window reads back as all zeros, which is not
        'alive'."""
        try:
            self.phys.drop_cache()
            for pa in (0x1000, 0x100000, 0x2000000, 0x100000000):
                if pa + 0x1000 > self.phys.size:
                    continue
                if any(self.phys.read(pa, 0x1000)):
                    return True
            return False
        except Exception:
            return False

    def _entries(self) -> list[dict]:
        """Snapshot with self-healing: if the walk fails but the window is
        alive, the bootstrap values are stale (the host rebooted) and get
        re-derived once; a dead window reports the usual access error."""
        try:
            return self.cache.snapshot()
        except Exception:
            pass
        if not self._link_ok():
            raise FacadeError(
                "EnumProcesses failed: error 5 (Access is denied)")
        try:
            self._cache = ProcessCache(self.boot.resolve(force=True),
                                       self.phys)
            return self._cache.snapshot(force=True)
        except Exception:
            raise FacadeError(
                "EnumProcesses failed: error 5 (Access is denied)")

    def list_processes(self) -> list[dict]:
        """EnumProcesses + names. Only live, allowlisted images appear."""
        entries = self._entries()
        out = []
        for e in entries:
            if e["name"].lower() in self.allowed_names and self._is_live(e):
                out.append({"pid": e["pid"], "name": e["name"]})
        out.sort(key=lambda p: (p["pid"] is None, p["pid"] or 0))
        return out

    def open_process(self, pid: int) -> int:
        """OpenProcess. Unknown pids and non-allowlisted pids fail the same way."""
        entry = next((e for e in self._entries() if e["pid"] == pid), None)
        if (entry is None or entry["name"].lower() not in self.allowed_names
                or not self._is_live(entry)):
            # Identical to the not-running case, on purpose.
            raise FacadeError(f"OpenProcess failed: {_E_INVALID_PARAMETER}")
        h = self._next_handle
        self._next_handle += 4          # real handles are 4-aligned
        self._handles[h] = entry
        return h

    def close_handle(self, handle: int) -> None:
        if self._handles.pop(handle, None) is None:
            raise FacadeError(f"CloseHandle failed: {_E_INVALID_HANDLE}")

    def _resolve(self, handle: int) -> dict:
        entry = self._handles.get(handle)
        if entry is None:
            raise FacadeError(f"ReadProcessMemory failed: {_E_INVALID_HANDLE}")
        return entry

    # ── memory ────────────────────────────────────────────────────────────
    def read_process_memory(self, handle: int, address: int,
                            size: int) -> dict:
        entry = self._resolve(handle)
        if size <= 0 or size > 0x100000:
            raise FacadeError(
                f"ReadProcessMemory failed: {_E_INVALID_PARAMETER} "
                f"(size must be 1..1048576)")
        r = VAReader(entry["dtb"], self.phys)
        self.phys.drop_cache()          # whole-file eviction: reads below are live
        data = r.read(address, size)
        return {
            "data": data.hex(),
            "size": size,
            "unreadablePages": self._count_zero_pages(data),
        }

    @staticmethod
    def _count_zero_pages(data: bytes) -> int:
        """Count fully-zero 4K spans — surfaces paged-out regions the way a
        debugger's partial-read report would, without extra traffic."""
        return sum(1 for i in range(0, len(data), 0x1000)
                   if not any(data[i:i + 0x1000]))

    def read_batch(self, handle: int, reads: list[dict]) -> list[dict]:
        """ReadProcessMemory, batched: one call for N (address, size) pairs.
        One page-table walk context, one round trip — for polling many
        units this replaces N separate calls."""
        entry = self._resolve(handle)
        if not reads or len(reads) > 256:
            raise FacadeError(
                f"ReadProcessMemory failed: {_E_INVALID_PARAMETER} "
                f"(batch must contain 1..256 reads)")
        specs = []
        total = 0
        for spec in reads:
            try:
                addr = int(spec.get("address"))
                size = int(spec.get("size", 4))
            except (TypeError, ValueError):
                raise FacadeError(
                    f"ReadProcessMemory failed: {_E_INVALID_PARAMETER} "
                    f"(bad read spec)")
            if size <= 0 or size > 0x10000 or addr < 0:
                raise FacadeError(
                    f"ReadProcessMemory failed: {_E_INVALID_PARAMETER} "
                    f"(size must be 1..65536 per read)")
            total += size
            specs.append((addr, size))
        if total > 0x100000:
            raise FacadeError(
                f"ReadProcessMemory failed: {_E_INVALID_PARAMETER} "
                f"(batch total exceeds 1 MB)")
        r = VAReader(entry["dtb"], self.phys)
        self.phys.drop_cache()          # one eviction, then a coherent batch
        out = []
        for addr, size in specs:
            data = r.read(addr, size)
            out.append({
                "address": f"0x{addr:X}",
                "size": size,
                "data": data.hex(),
                "unreadablePages": self._count_zero_pages(data),
            })
        return out

    def read_typed(self, handle: int, address: int, fmt: str) -> dict:
        """Convenience typed read: u8/u16/u32/u64 or utf16 string (fmt='ws<N>')."""
        sizes = {"u8": 1, "u16": 2, "u32": 4, "u64": 8}
        if fmt in sizes:
            n = sizes[fmt]
            d = self.read_process_memory(handle, address, n)
            val = int.from_bytes(bytes.fromhex(d["data"]), "little")
            return {"format": fmt, "value": val}
        if fmt.startswith("ws"):
            n = int(fmt[2:])
            d = self.read_process_memory(handle, address, n * 2)
            raw = bytes.fromhex(d["data"])
            s = raw.decode("utf-16-le", errors="replace")
            s = s.split("\x00", 1)[0]
            return {"format": fmt, "value": s}
        raise FacadeError(
            f"ReadProcessMemory failed: {_E_INVALID_PARAMETER} "
            f"(unknown format {fmt!r})")

    # ── modules ───────────────────────────────────────────────────────────
    def list_modules(self, handle: int) -> list[dict]:
        """ModuleFirst/ModuleNext: PEB -> Ldr -> InMemoryOrderModuleList walk.
        Classic x64 LDR offsets; the MZ check self-validates every entry."""
        entry = self._resolve(handle)
        r = VAReader(entry["dtb"], self.phys)
        peb = self._find_peb(r, entry["eproc"])
        if peb is None:
            raise FacadeError(
                "module enumeration failed: error 299 "
                "(Only part of a ReadProcessMemory request was completed)")
        ldr = r.read_u64(peb + 0x18)
        if not (0x10000 < ldr < 0x7FFFFFFFFFFF):
            raise FacadeError(
                "module enumeration failed: error 299 "
                "(Only part of a ReadProcessMemory request was completed)")
        head = ldr + 0x20                     # InMemoryOrderModuleList
        mods = []
        cur = r.read_u64(head)                # first InMemoryOrderLinks
        seen = set()
        while len(seen) < 256:
            if cur == head or cur in seen or not (0x10000 < cur < 0x7FFFFFFFFFFF):
                break
            seen.add(cur)
            base = r.read_u64(cur + 0x20)     # DllBase (entry +0x30)
            size = r.read_u32(cur + 0x30)     # SizeOfImage (entry +0x40)
            name = self._module_name(r, cur + 0x48)
            if 0x10000 < base < 0x7FFFFFFFFFFF and r.read(base, 2) == b"MZ":
                mods.append({"name": name, "base": base, "size": size})
            cur = r.read_u64(cur)
        if not mods:
            raise FacadeError(
                "module enumeration failed: error 299 "
                "(Only part of a ReadProcessMemory request was completed)")
        return mods

    def _find_peb(self, r: VAReader, eproc: int) -> int | None:
        """The PEB pointer's offset in the process struct varies by build;
        scan the window for a user-space pointer whose PEB validates."""
        k = VAReader(self.cache.plist.kernel_dtb, self.phys)
        data = k.read(eproc, ProcessList.WALK_WINDOW)
        for off in range(0x200, min(0x800, len(data) - 8), 8):
            v = struct.unpack_from("<Q", data, off)[0]
            if not (0x10000 < v < 0x7FFFFFFFFFFF):
                continue
            try:
                ldr = r.read_u64(v + 0x18)
                img = r.read_u64(v + 0x10)
                if (0x10000 < ldr < 0x7FFFFFFFFFFF
                        and 0x10000 < img < 0x7FFFFFFFFFFF
                        and r.read(img, 2) == b"MZ"):
                    return v
            except Exception:
                continue
        return None

    @staticmethod
    def _module_name(r: VAReader, us_addr: int) -> str:
        """Read a UNICODE_STRING (classic layout) at us_addr -> BaseDllName."""
        try:
            ln = r.read_u16(us_addr)
            buf = r.read_u64(us_addr + 8)
            if ln == 0 or ln > 520 or not (0x10000 < buf < 0x7FFFFFFFFFFF):
                return "?"
            s = r.read(buf, ln).decode("utf-16-le", errors="replace")
            return s.split("\\")[-1].rstrip("\x00") or "?"
        except Exception:
            return "?"

    # ── system ────────────────────────────────────────────────────────────
    def system_info(self) -> dict:
        return {
            "os": "Windows x64",
            "arch": "x86_64",
            "page_size": 0x1000,
            "total_physical_mb": self.phys.size // (1024 * 1024),
        }

    def shutdown(self) -> None:
        self._handles.clear()
