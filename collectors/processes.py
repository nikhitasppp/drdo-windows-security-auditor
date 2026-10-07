"""
Running Processes collector.

Source: Get-Process. Reading the .Path property throws for some
protected/system processes when the current user lacks access; the
PowerShell expression below catches that per-process rather than letting
one inaccessible process fail the whole query.

The "unusual path" heuristic is deliberately narrow (only the user/system
temp directories, not all of AppData) to avoid flagging the many
legitimate applications that run from AppData\\Local or \\Roaming --
broadening it would trade a low-value check for a high false-positive
rate (see FRAMEWORK.md limitations).
"""

from __future__ import annotations

import os

from collectors.base import BaseCollector, CollectorContext
from utils.helpers import as_list
from utils.powershell import run_ps_capture


class ProcessesCollector(BaseCollector):
    collector_id = "processes"

    def _collect(self, ctx: CollectorContext) -> None:
        cap = run_ps_capture(
            "Get-Process -ErrorAction Stop | Select-Object Name,Id,"
            "@{Name='Path';Expression={ try { $_.Path } catch { $null } }}"
        )
        if not cap.ok:
            reason = cap.error or "unknown error querying Get-Process"
            ctx.mark_error("running_processes", reason)
            ctx.mark_error("processes_from_unusual_paths", reason)
            return

        processes = [p for p in as_list(cap.data) if isinstance(p, dict)]
        ctx.set("running_processes", [
            {"name": p.get("Name"), "pid": p.get("Id"), "path": p.get("Path")} for p in processes
        ])

        temp_dirs = {os.environ.get("TEMP", ""), os.environ.get("TMP", "")}
        temp_dirs = {d.rstrip("\\/").lower() for d in temp_dirs if d}

        unusual = []
        for p in processes:
            path = p.get("Path")
            if not path:
                continue
            path_lower = path.lower()
            if any(path_lower.startswith(temp_dir) for temp_dir in temp_dirs):
                unusual.append({"name": p.get("Name"), "pid": p.get("Id"), "path": path})

        ctx.set("processes_from_unusual_paths", unusual)
