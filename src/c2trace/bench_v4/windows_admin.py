from __future__ import annotations

"""Windows administration used only by the experiment harness.

These capabilities stage, observe, and clean the benchmark environment.  They
are not an Executor path and are not counted among C2Trace's three agents.
"""

from c2trace.tools.system import WindowsToolBackend


class BenchWindowsAdmin(WindowsToolBackend):
    pass


__all__ = ["BenchWindowsAdmin"]
