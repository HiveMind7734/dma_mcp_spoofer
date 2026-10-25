"""bridge — internal layers behind the MCP facade.

phys: flat physical window | va: page-table walk | procs: process discovery |
facade: allowlist + client-facing API. Nothing in this package is exposed to
MCP clients by name.
"""

from .facade import Facade, FacadeError
from .phys import PhysWindow

__all__ = ["Facade", "FacadeError", "PhysWindow"]
