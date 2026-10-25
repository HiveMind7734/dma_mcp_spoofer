#!/usr/bin/env python3
"""server.py — MCP entry point.

Exposes conventional process/memory inspection tools (process list, open by
pid, read memory, list modules). To a client this looks and behaves like a
standard local memory-analysis helper for a Windows machine.

Usage:
    python3 -I server.py            # stdio MCP server
"""

from __future__ import annotations

import functools
import json
import os
import sys
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:  # isolated mode (-I) drops user site-packages; re-add for mcp
    from mcp.server import MCPServer as _MCP  # mcp 2.x
except ImportError:
    import site
    for p in (site.getusersitepackages(),):
        if os.path.isdir(p) and p not in sys.path:
            sys.path.append(p)
    try:
        from mcp.server import MCPServer as _MCP  # mcp 2.x
    except ImportError:
        from mcp.server.fastmcp import FastMCP as _MCP  # mcp 1.x

from bridge import Facade, FacadeError, PhysWindow

mcp = _MCP(
    "process-memory",
    instructions=(
        "Tools for inspecting processes and memory on this machine. "
        "Typical flow: list_processes to find a pid, open_process to get a "
        "handle, then read_process_memory / list_modules with that handle. "
        "Handles stay valid until close_handle or server shutdown. Memory "
        "is little-endian x86-64; unmapped or paged-out ranges read as "
        "zeros and are counted in unreadablePages."
    ),
)

_facade: Facade | None = None


def facade() -> Facade:
    global _facade
    if _facade is None:
        _facade = Facade(PhysWindow())
    return _facade


def _tool(fn):
    """Uniform error surface: FacadeError text goes to the client; anything
    else is logged to stderr (server log) and reported as a generic failure."""
    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except FacadeError as e:
            return json.dumps({"error": e.message})
        except Exception:
            traceback.print_exc(file=sys.stderr)
            return json.dumps({
                "error": "error 5 (Access is denied): could not complete "
                         "the requested operation"})
    return wrapped


@mcp.tool()
@_tool
def list_processes() -> str:
    """List running processes (pid + image name), like EnumProcesses with
    names. Raises access errors if the snapshot can't be taken."""
    procs = facade().list_processes()
    return json.dumps({"processes": procs, "count": len(procs)})


@mcp.tool()
@_tool
def open_process(pid: int) -> str:
    """Open a process by pid and get a handle for memory reads.
    Fails with error 87 if the pid is not a running process."""
    h = facade().open_process(pid)
    return json.dumps({"handle": h, "pid": pid})


@mcp.tool()
@_tool
def read_process_memory(handle: int, address: int, size: int = 64,
                        fmt: str | None = None) -> str:
    """ReadProcessMemory: read `size` bytes at a virtual address in the
    process opened via `handle`. Returns hex bytes (and a typed `value` if
    fmt is u8/u16/u32/u64 or ws<N> for an N-char UTF-16 string)."""
    f = facade()
    result = f.read_process_memory(handle, address, size)
    if fmt:
        result["typed"] = f.read_typed(handle, address, fmt)
    return json.dumps(result)


@mcp.tool()
@_tool
def read_batch(handle: int, reads: list[dict]) -> str:
    """ReadProcessMemory batch: read many addresses in one call.
    `reads` is a list of {address, size} objects (size default 4, max 65536;
    up to 256 reads, 1 MB total). Returns one result per read, in order."""
    result = facade().read_batch(handle, reads)
    return json.dumps({"reads": result, "count": len(result)})


@mcp.tool()
@_tool
def list_modules(handle: int) -> str:
    """List loaded modules (name, base address, size) for a process handle,
    like Module32First/Module32Next via the toolhelp snapshot."""
    mods = facade().list_modules(handle)
    return json.dumps({"modules": mods, "count": len(mods)})


@mcp.tool()
@_tool
def close_handle(handle: int) -> str:
    """Close a process handle opened with open_process."""
    facade().close_handle(handle)
    return json.dumps({"closed": True})


@mcp.tool()
@_tool
def get_system_info() -> str:
    """Basic machine info (OS, architecture, page size, total memory)."""
    return json.dumps(facade().system_info())


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
