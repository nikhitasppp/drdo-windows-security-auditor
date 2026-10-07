"""
Browser & Internet Security collector.

Installed browsers are detected via the registry "App Paths" mechanism
(HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\<exe>), the
same lookup Windows itself uses to resolve a bare executable name -- more
reliable than guessing Program Files locations, and confirmed live to
find Microsoft Edge on this host. Version is read via PowerShell's file
VersionInfo, since Python's standard library does not expose Windows PE
version resources without a third-party dependency.

This tool is offline-only, so it cannot compare an installed version
against the latest published release -- version is reported informationally
(see FRAMEWORK.md limitations), not scored.
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils import registry
from utils.powershell import run_ps_capture

_APP_PATHS_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"

_KNOWN_BROWSERS = {
    "msedge.exe": "Microsoft Edge",
    "chrome.exe": "Google Chrome",
    "firefox.exe": "Mozilla Firefox",
    "brave.exe": "Brave",
    "opera.exe": "Opera",
}

_EDGE_SMARTSCREEN_KEY = r"SOFTWARE\Policies\Microsoft\Edge"
_PROXY_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


class BrowserCollector(BaseCollector):
    collector_id = "browser"

    def _collect(self, ctx: CollectorContext) -> None:
        installed = self._detect_installed_browsers(ctx)
        ctx.set("edge_installed", "msedge.exe" in installed)
        self._collect_edge_smartscreen(ctx)
        self._collect_proxy_override(ctx)

    def _detect_installed_browsers(self, ctx: CollectorContext) -> dict[str, str]:
        found: dict[str, str] = {}
        browsers = []
        for exe, display_name in _KNOWN_BROWSERS.items():
            result = registry.read_value("HKLM", rf"{_APP_PATHS_KEY}\{exe}", "")
            if result.error:
                continue
            if result.exists and result.value:
                found[exe] = str(result.value)
                version = self._get_file_version(str(result.value))
                browsers.append({"name": display_name, "executable": exe, "path": result.value, "version": version})
        ctx.set("installed_browsers", browsers)
        return found

    @staticmethod
    def _get_file_version(path: str) -> str | None:
        escaped = path.replace("'", "''")
        cap = run_ps_capture(f"(Get-Item -LiteralPath '{escaped}' -ErrorAction Stop).VersionInfo.ProductVersion")
        if cap.ok and cap.data:
            return str(cap.data)
        return None

    def _collect_edge_smartscreen(self, ctx: CollectorContext) -> None:
        result = registry.read_value("HKLM", _EDGE_SMARTSCREEN_KEY, "SmartScreenEnabled")
        if result.error:
            ctx.mark_error("edge_smartscreen_enabled", result.error)
        elif not result.exists:
            # No policy override present. Confirmed live, including a
            # byte-for-byte search of Edge's own Preferences JSON file,
            # that Edge does not persist this setting anywhere until it is
            # explicitly changed away from default. Microsoft documents
            # Edge SmartScreen as on by default, so absence is reported as
            # that documented default -- a policy decision based on a
            # published default, not a live-verified read, and stated as
            # such rather than treated as equivalent to a direct read.
            ctx.set("edge_smartscreen_enabled", True)
        else:
            ctx.set("edge_smartscreen_enabled", bool(result.value))

    def _collect_proxy_override(self, ctx: CollectorContext) -> None:
        result = registry.read_value("HKCU", _PROXY_SETTINGS_KEY, "ProxyEnable")
        if result.error:
            ctx.mark_error("browser_proxy_override", result.error)
        else:
            ctx.set("browser_proxy_override", bool(result.value) if result.exists else False)
