#!/usr/bin/env python3
"""panel.py — link & allowlist control panel (your side of the MCP server).

One window for the whole link: live status, start/stop buttons for the
memory window, a diagnostics checklist (USB side, target host, mount
process, window file), a live log of the mount process, the FULL process
list the backend can see (your God view — clients never see this), and the
allowlist picker: the process you pick is the only one MCP clients get.

Run with sudo (same as overlay.py — the memory window needs root):
    sudo -E python3 panel.py

CLI shortcuts (no GUI):
    python3 panel.py --status            # one-shot link status
    sudo python3 panel.py --list         # walk and print all processes
    sudo python3 panel.py --expose D2R.exe    # set the allowlist directly
    sudo python3 panel.py --start-link   # start the mount (foreground log)
    sudo python3 panel.py --stop-link
"""

from __future__ import annotations

import collections
import os
import queue
import subprocess
import sys
import threading
import time
import tomllib

try:
    import tkinter as tk
except ImportError:
    tk = None

HERE = os.path.dirname(os.path.abspath(__file__))
ZAI = os.path.dirname(HERE)
TOOLS = os.path.join(ZAI, "tools")
PCILEECH = os.path.join(TOOLS, "pcileech")
MOUNT_PT = "/mnt/MEMPROCFS"

SRC_CFG = os.path.join(HERE, "config", "allowlist.toml")
DST_ROOT = os.environ.get("PROCMEM_INSTALL_DIR",
                  os.path.expanduser("~/.local/share/process-memory"))
DST_CFG = os.path.join(DST_ROOT, "config", "allowlist.toml")

WINDOW = os.environ.get("PROCMEM_SRC", os.path.join(MOUNT_PT, "liveram-native.raw"))
TARGET_IP = os.environ.get("PROCMEM_TARGET", "192.168.1.100")
USB_ID = "0403:601f"

POLL_MS = 500          # UI tick
MONITOR_SEC = 2.0      # diagnostics cadence

START_CMD = ["stdbuf", "-oL", PCILEECH, "mount", "-mount", MOUNT_PT,
             "-device", "fpga"]


def _read_cfg() -> dict:
    if os.path.exists(SRC_CFG):
        with open(SRC_CFG, "rb") as f:
            return tomllib.load(f)
    return {}


# ── link status / diagnostics ──────────────────────────────────────────────

def link_status() -> tuple[str, str]:
    """(state, detail); state in {'up', 'denied', 'down'}.
    A read that merely returns bytes is NOT proof of life: after the host
    reboots under a stale mount the file serves all zeros. Real memory
    always has non-zero pages, so probe several and require content."""
    if not os.path.exists(WINDOW):
        return "down", f"not mounted: {WINDOW}"
    try:
        with open(WINDOW, "rb", buffering=0) as f:
            f.seek(0, 2)
            size = f.tell()
            probe_pages = (0x1000, 0x100000, 0x2000000, 0x100000000)
            nz = 0
            for pa in probe_pages:
                if pa + 0x1000 > size:
                    continue
                f.seek(pa)
                if any(f.read(0x1000)):
                    nz += 1
        if nz == 0:
            return "down", "window reads as all zeros — stale link; restart it"
        return "up", f"{size // (1024 * 1024)} MB window at {WINDOW}"
    except PermissionError:
        return "denied", "window exists but not readable — run with sudo"
    except OSError as e:
        return "down", f"read error: {e}"


def _target_reachable() -> bool | None:
    """TCP probe on ssh port — ICMP is firewalled on the Windows target."""
    import socket
    try:
        s = socket.create_connection((TARGET_IP, 22), timeout=2)
        s.close()
        return True
    except Exception:
        return False


def diagnostics() -> dict:
    """Checklist shown in the panel. Each value is True/False/None(unknown)."""
    d: dict = {}
    try:
        out = subprocess.run(["lsusb"], capture_output=True, text=True,
                             timeout=3).stdout
        d["ftdi"] = USB_ID in out
    except Exception:
        d["ftdi"] = None
    d["target"] = _target_reachable()
    d["pcileech"] = os.path.exists("/proc") and subprocess.run(
        ["pgrep", "-x", "pcileech"], capture_output=True).returncode == 0
    d["window"] = os.path.exists(WINDOW)
    d["link"], d["detail"] = link_status()
    return d


# ── mount control ──────────────────────────────────────────────────────────

def start_mount(log=print) -> subprocess.Popen:
    """Start the memory window. Returns the Popen handle. If a mount
    process is already running but serving a dead/stale window (host
    rebooted underneath it), it is stopped first — one click recovers."""
    link, _detail = link_status()
    if subprocess.run(["pgrep", "-x", "pcileech"],
                      capture_output=True).returncode == 0:
        if link == "up":
            log("pcileech already running — window is live; nothing to do")
            raise RuntimeError("already running")
        log("stale mount detected (host rebooted?) — restarting it")
        stop_mount()
        for _ in range(20):        # wait for the old window to disappear
            if link_status()[0] == "down" or not os.path.exists(WINDOW):
                break
            time.sleep(0.5)
        try:
            subprocess.run(["umount", MOUNT_PT], capture_output=True, timeout=10)
        except Exception:
            pass
    log(f"starting: {' '.join(START_CMD)}")
    return subprocess.Popen(START_CMD, cwd=TOOLS, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)


def stop_mount() -> bool:
    """Stop pcileech by exact name (never -f: it matches your own wrapper)."""
    r = subprocess.run(["pkill", "-x", "pcileech"], capture_output=True)
    return r.returncode == 0


# ── process walk (unfiltered) ──────────────────────────────────────────────

def scan_processes(log=print) -> list[dict]:
    """Full process list via the same auto-bootstrap the server uses
    (values discovered from memory; nothing recorded per boot)."""
    sys.path.insert(0, HERE)
    from bridge.autoboot import Bootstrapper
    from bridge.phys import PhysWindow
    from bridge.procs import ProcessList

    with PhysWindow(WINDOW) as phys:
        plist = Bootstrapper(phys, config_dir=os.path.join(HERE, "config")).resolve()
        log(f"bootstrap: kernel dtb 0x{plist.kernel_dtb:X}, "
            f"anchor 0x{plist.anchor_eproc:X}")
        procs = plist.scan(phys)
    return sorted(procs, key=lambda p: (p["pid"] is None, p["pid"] or 0))


# ── allowlist write ────────────────────────────────────────────────────────

_TEMPLATE = """\
# allowlist.toml — server-side only. NEVER exposed through MCP.
#
# processes : which images clients may see. Everything else is invisible —
#             indistinguishable from "not running" (same error 87).
#             Written by panel.py from your selection.
# Bootstrap values (kernel dtb + anchor) are discovered automatically —
# nothing recorded here; see config/bootstrap.json.

version = 1

[allowlist]
processes = [
{entries}
]
"""


def write_allowlist(names: list[str], out_paths: list[str] | None = None) -> list[str]:
    """Set the exposed-process list (bootstrap values are not recorded —
    the server derives them itself)."""
    entries = ",\n".join(f'    "{n}"' for n in names)
    body = _TEMPLATE.format(entries=entries)

    paths = out_paths
    if paths is None:
        paths = [SRC_CFG]
        if os.path.isdir(DST_ROOT):
            paths.append(DST_CFG)
    for p in paths:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(body)
        _chown_user(p)
    return paths


def _chown_user(path: str) -> None:
    """When run under sudo, keep files owned by the invoking user."""
    if os.geteuid() == 0:
        try:
            import pwd
            name = os.environ.get("SUDO_USER")
            pw = pwd.getpwnam(name) if name else None
            if pw:
                os.chown(path, pw.pw_uid, pw.pw_gid)
        except Exception:
            pass


# ── GUI ────────────────────────────────────────────────────────────────────

_COLOR = {"up": "#1a7f37", "denied": "#b58900", "down": "#c62828"}
_MARK = {True: "✓", False: "✗", None: "?"}


class Panel:
    def __init__(self, root):
        self.root = root
        self.procs: list[dict] = []
        self.view: list[dict] = []      # procs after the keyword filter
        self.q: queue.Queue = queue.Queue()
        self.log_lines: collections.deque = collections.deque(maxlen=400)
        self.mount_proc: subprocess.Popen | None = None
        self.scanning = False
        self.scanned_once = False
        self.was_up = False
        self.diag: dict = {}

        root.title("MCP DMA — link & allowlist panel")
        root.geometry("680x560")

        # status + diagnostics
        self.status = tk.Label(root, text="LINK: …", font=("sans", 16, "bold"))
        self.status.pack(pady=(8, 0))
        self.detail = tk.Label(root, text="", fg="#555")
        self.detail.pack()
        self.diagline = tk.Label(root, text="", font=("monospace", 10))
        self.diagline.pack()

        # link control
        bar = tk.Frame(root)
        bar.pack(fill="x", padx=12, pady=6)
        self.btn_start = tk.Button(bar, text="Start link", command=self.start_link)
        self.btn_start.pack(side="left")
        self.btn_stop = tk.Button(bar, text="Stop link", command=self.stop_link)
        self.btn_stop.pack(side="left", padx=6)
        self.btn_rescan = tk.Button(bar, text="Rescan processes",
                                    command=self.start_scan)
        self.btn_rescan.pack(side="left")

        # process list + live keyword filter
        filterbar = tk.Frame(root)
        filterbar.pack(fill="x", padx=12, pady=(6, 0))
        tk.Label(filterbar, text="Filter:").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.render_procs())
        self.filter_entry = tk.Entry(filterbar, textvariable=self.filter_var)
        self.filter_entry.pack(side="left", fill="x", expand=True, padx=6)
        self.filter_entry.bind("<Escape>",
                               lambda _e: self.filter_var.set(""))
        self.filter_count = tk.Label(filterbar, text="", fg="#555")
        self.filter_count.pack(side="left")

        frame = tk.Frame(root)
        frame.pack(fill="both", expand=True, padx=12)
        sb = tk.Scrollbar(frame)
        sb.pack(side="right", fill="y")
        self.lb = tk.Listbox(frame, selectmode="extended",
                             font=("monospace", 11), yscrollcommand=sb.set)
        self.lb.pack(side="left", fill="both", expand=True)
        sb.config(command=self.lb.yview)
        # open pre-filtered to whatever is currently exposed (e.g. d2r.exe)
        _allowed = _read_cfg().get("allowlist", {}).get("processes", [])
        if _allowed:
            self.filter_var.set(_allowed[0].lower())

        # allowlist row
        bottom = tk.Frame(root)
        bottom.pack(fill="x", padx=12, pady=6)
        tk.Label(bottom, text="Clients can see:").pack(side="left")
        self.allowed = tk.Label(bottom, text="…", fg="#1a7f37",
                                font=("sans", 11, "bold"))
        self.allowed.pack(side="left", padx=6)
        self.btn_expose = tk.Button(bottom, text="Expose selected",
                                    command=self.expose, state="disabled")
        self.btn_expose.pack(side="right")

        # log pane
        tk.Label(root, text="log", fg="#555").pack(anchor="w", padx=12)
        self.logw = tk.Text(root, height=8, font=("monospace", 9),
                            state="disabled", bg="#111", fg="#9e9e9e")
        self.logw.pack(fill="x", padx=12)

        self.msg = tk.Label(root, text="", fg="#555", anchor="w")
        self.msg.pack(fill="x", side="bottom", padx=12)

        self.refresh_allowed_label()
        self.log("panel ready")
        self._spawn(monitor_loop, self)
        self.tick()

    # ── helpers ────────────────────────────────────────────────────────────
    @staticmethod
    def _spawn(fn, *args):
        threading.Thread(target=fn, args=args, daemon=True).start()

    def log(self, line: str):
        self.log_lines.append(time.strftime("%H:%M:%S ") + line)

    def refresh_allowed_label(self):
        names = _read_cfg().get("allowlist", {}).get("processes", [])
        self.allowed.config(text=", ".join(names) if names else "(nothing)")

    def render_procs(self):
        """Fill the listbox from the last scan, applying the keyword
        filter (case-insensitive substring of name or pid)."""
        q = self.filter_var.get().strip().lower()
        self.view = [p for p in self.procs if not q or q in p["name"].lower()
                     or (p["pid"] is not None and q in str(p["pid"]))]
        self.lb.delete(0, "end")
        for p in self.view:
            pid = "-" if p["pid"] is None else p["pid"]
            self.lb.insert(
                "end", f"{pid:>7}  {p['name']:<24} dtb 0x{p['dtb']:X}")
        if q:
            self.filter_count.config(text=f"{len(self.view)} of "
                                          f"{len(self.procs)}")
        else:
            self.filter_count.config(text="")

    # ── link control ───────────────────────────────────────────────────────
    def start_link(self):
        try:
            self.mount_proc = start_mount(log=self.log)
        except RuntimeError:
            return
        p = self.mount_proc

        def reader():
            assert p.stdout is not None
            for line in p.stdout:
                self.log("mount: " + line.rstrip())
            rc = p.wait()
            self.log(f"mount exited with code {rc}")
        self._spawn(reader)

    def stop_link(self):
        if stop_mount():
            self.log("sent stop to pcileech")
        else:
            self.log("no pcileech process found")

    # ── scan / expose ──────────────────────────────────────────────────────
    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scanned_once = True
        self.msg.config(text="scanning — first scan after a host reboot "
                             "rediscovers anchors (a minute or two)…")

        def work():
            try:
                self.q.put(("procs", scan_processes(log=self.log)))
            except Exception as e:  # noqa: BLE001 — surface anything to the GUI
                self.q.put(("err", e))
        self._spawn(work)

    def expose(self):
        sel = self.lb.curselection()
        if not sel:
            return
        names = sorted({self.view[i]["name"] for i in sel})
        paths = write_allowlist(names)
        self.refresh_allowed_label()
        self.msg.config(text=f"allowlist -> {', '.join(names)} "
                             f"(written to {len(paths)} config copies)")

    # ── UI loop ────────────────────────────────────────────────────────────
    def tick(self):
        try:
            while True:
                kind, item = self.q.get_nowait()
                if kind == "diag":
                    self.apply_diag(item)
                elif kind == "procs":
                    self.scanning = False
                    self.procs = item
                    self.render_procs()
                    self.msg.config(text=f"{len(self.procs)} processes "
                                          f"(full list — your view)")
                elif kind == "err":
                    self.scanning = False
                    self.msg.config(text=f"scan failed: {item}")
        except queue.Empty:
            pass

        # log pane
        text = "\n".join(self.log_lines)
        self.logw.config(state="normal")
        self.logw.delete("1.0", "end")
        self.logw.insert("1.0", text)
        self.logw.see("end")
        self.logw.config(state="disabled")

        live = self.diag.get("link") == "up"
        if live and not self.was_up and not self.scanned_once:
            self.start_scan()          # auto-scan on link-up transition
        self.was_up = live
        self.btn_expose.config(
            state="normal" if (live and self.lb.size()
                               and self.lb.curselection()) else "disabled")
        self.root.after(POLL_MS, self.tick)

    def apply_diag(self, d: dict):
        self.diag = d
        self.status.config(text=f"LINK: {d['link'].upper()}", fg=_COLOR[d["link"]])
        self.detail.config(text=d["detail"])
        self.diagline.config(
            text=(f"usb-card {_MARK[d['ftdi']]}   target({TARGET_IP}) "
                  f"{_MARK[d['target']]}   pcileech {_MARK[d['pcileech']]}   "
                  f"window-file {_MARK[d['window']]}"))
        self.btn_start.config(
            state="disabled" if d["pcileech"] else "normal")
        self.btn_stop.config(
            state="normal" if d["pcileech"] else "disabled")
        self.btn_rescan.config(
            state="normal" if d["link"] == "up" else "disabled")
        if self.lb.size() and d["link"] != "up":
            self.msg.config(text="link down — list below is stale")


def monitor_loop(panel: "Panel"):
    while True:
        try:
            panel.q.put(("diag", diagnostics()))
        except Exception as e:  # noqa: BLE001 — keep the monitor alive
            panel.q.put(("err", e))
        time.sleep(MONITOR_SEC)


def main_gui():
    if tk is None:
        print("tkinter unavailable — use the CLI modes (--status/--list/…)")
        return 1
    root = tk.Tk()
    Panel(root)
    root.mainloop()
    return 0


def main() -> int:
    if "--status" in sys.argv:
        state, detail = link_status()
        print(f"LINK: {state.upper()} — {detail}")
        return 0 if state == "up" else 1
    if "--diag" in sys.argv:
        for k, v in diagnostics().items():
            print(f"{k:>8}: {v}")
        return 0
    if "--list" in sys.argv:
        for p in scan_processes():
            pid = "-" if p["pid"] is None else p["pid"]
            print(f"{pid:>7}  {p['name']:<24} dtb 0x{p['dtb']:X}")
        return 0
    if "--expose" in sys.argv:
        i = sys.argv.index("--expose")
        names = sys.argv[i + 1:]
        if not names:
            print("usage: panel.py --expose <image.exe> [more...]")
            return 2
        for p in write_allowlist(names):
            print("wrote", p)
        return 0
    if "--start-link" in sys.argv:
        p = start_mount()
        sys.exit(p.wait())
    if "--stop-link" in sys.argv:
        print("stopped" if stop_mount() else "nothing to stop")
        return 0
    return main_gui()


if __name__ == "__main__":
    sys.exit(main())
