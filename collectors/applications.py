"""
Installed Applications collector.

Source: the registry Uninstall keys (HKLM native + WOW6432Node, i.e. both
64-bit and 32-bit registered applications), read directly via winreg.
Win32_Product (WMI) is deliberately NOT used: Microsoft documents that
querying it can trigger an MSI consistency-check/repair as a side effect,
which would violate this tool's read-only requirement. Subkeys without a
DisplayName value are skipped -- those are typically hotfix/component
entries, not user-facing applications.

Startup entries: the Run/RunOnce registry keys (HKLM + HKCU). This does
not include the Startup folder or scheduled tasks -- broadening this is
a reasonable future improvement, not attempted in this initial rule set.

Unwanted/risky software: a name-substring match against the already-
collected installed_applications list (no separate registry query) for
a small set of commonly-flagged tools -- unmanaged remote-access clients
(TeamViewer, AnyDesk), virtualization software (VMware, VirtualBox), and
registry/system "cleaner" utilities. Reported as INFO: presence alone
isn't a universal fail (e.g. VMware/VirtualBox are legitimate developer
tools), so this is a flagged inventory for review, not a scored check.

Installed programs (distinct from installed_applications above): the MSI
product-registration cache at HKLM\\SOFTWARE\\Classes\\Installer\\Products,
read directly via winreg. This is a lower-level, noisier list than the
Uninstall-key applications list -- it includes every individually-
registered MSI product/component (e.g. Visual Studio's granular
sub-packages), most of which never get a user-facing Uninstall entry.
Win32_Product (WMI) would return something similar but is deliberately
NOT used here either, for the same documented reason as above.

Excessive installed programs: a genuine scored PASS/FAIL
(installed_programs_count > 20 -> FAIL, per explicit instruction), not
an advisory. There is no baseline-image diff here -- "additional" is
simply the total installed-programs count, the same interpretation
already used by excessive_startup_entries above -- a true baseline
comparison would require an organization-specific reference image this
general-purpose tool doesn't have.
"""

from __future__ import annotations

from collectors.base import BaseCollector, CollectorContext
from utils import registry

_UNINSTALL_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
]

_INSTALLER_PRODUCTS_KEY = ("HKLM", r"SOFTWARE\Classes\Installer\Products")

_RUN_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

_EXCESSIVE_STARTUP_THRESHOLD = 20

# Name substrings (case-insensitive) of software commonly flagged as
# unwanted on an audited workstation: remote-access tools that bypass
# managed remote-access channels, virtualization software, and registry/
# system "cleaner" utilities. Matched against installed_applications
# (already collected) rather than re-querying the registry.
_UNWANTED_SOFTWARE_KEYWORDS = {
    "teamviewer": "Remote access",
    "anydesk": "Remote access",
    "vmware": "Virtualization",
    "virtualbox": "Virtualization",
    "registry cleaner": "Registry/system cleaner",
    "ccleaner": "Registry/system cleaner",
}


class ApplicationsCollector(BaseCollector):
    collector_id = "applications"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_installed_applications(ctx)
        self._collect_installed_programs(ctx)
        self._collect_unwanted_software(ctx)
        self._collect_startup_entries(ctx)

    def _collect_installed_applications(self, ctx: CollectorContext) -> None:
        apps = []
        errors = []

        for hive, base_key in _UNINSTALL_KEYS:
            subkeys = registry.enumerate_subkeys(hive, base_key)
            if subkeys.error:
                errors.append(subkeys.error)
                continue
            for name in subkeys.value or []:
                full_key = f"{base_key}\\{name}"
                display_name = registry.read_value(hive, full_key, "DisplayName")
                if display_name.error or not display_name.exists or not display_name.value:
                    continue
                version = registry.read_value(hive, full_key, "DisplayVersion")
                publisher = registry.read_value(hive, full_key, "Publisher")
                apps.append({
                    "name": display_name.value,
                    "version": version.value if version.exists else None,
                    "publisher": publisher.value if publisher.exists else None,
                })

        if apps:
            apps.sort(key=lambda a: (a["name"] or "").lower())
            ctx.set("installed_applications", apps)
        elif errors:
            ctx.mark_error("installed_applications", "; ".join(errors))
        else:
            ctx.set("installed_applications", [])

    def _collect_installed_programs(self, ctx: CollectorContext) -> None:
        hive, base_key = _INSTALLER_PRODUCTS_KEY
        subkeys = registry.enumerate_subkeys(hive, base_key)
        if subkeys.error:
            ctx.mark_error("installed_programs", subkeys.error)
            ctx.mark_error("installed_programs_count", subkeys.error)
            return

        programs = []
        for name in subkeys.value or []:
            full_key = f"{base_key}\\{name}"
            product_name = registry.read_value(hive, full_key, "ProductName")
            if product_name.error or not product_name.exists or not product_name.value:
                continue
            programs.append(product_name.value)

        programs.sort(key=str.lower)
        ctx.set("installed_programs", programs)
        ctx.set("installed_programs_count", len(programs))

    def _collect_unwanted_software(self, ctx: CollectorContext) -> None:
        if "installed_applications" in ctx.errors:
            ctx.mark_error("unwanted_software_detected", ctx.errors["installed_applications"])
            return

        apps = ctx.data.get("installed_applications") or []
        found = []
        for app in apps:
            name = (app.get("name") or "").lower()
            for keyword, category in _UNWANTED_SOFTWARE_KEYWORDS.items():
                if keyword in name:
                    found.append({"name": app.get("name"), "category": category})
                    break
        ctx.set("unwanted_software_detected", found)

    def _collect_startup_entries(self, ctx: CollectorContext) -> None:
        total = 0
        entries = []
        had_success = False
        errors = []

        for hive, key in _RUN_KEYS:
            values = registry.enumerate_values(hive, key)
            if values.error:
                errors.append(values.error)
                continue
            had_success = True
            for name, command in (values.value or {}).items():
                total += 1
                entries.append({"name": name, "command": command, "location": f"{hive}\\{key}"})

        if not had_success and errors:
            ctx.mark_error("excessive_startup_entries", "; ".join(errors))
            return

        ctx.set("startup_entries", entries)
        ctx.set("excessive_startup_entries", total > _EXCESSIVE_STARTUP_THRESHOLD)
