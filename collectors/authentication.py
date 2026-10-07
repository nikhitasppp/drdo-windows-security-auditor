"""
Authentication & Access Control collector.

Password/lockout policy source: `secedit /export /areas SECURITYPOLICY`,
which writes the effective local security policy to a plain-text .cfg
file (chosen over `net accounts` because it is the structured, complete
source the Local Security Policy snap-in itself reads from, covering both
password and lockout policy in one call). secedit only writes to a
temporary scratch file so this collector can parse it -- that file is
always removed afterward, and no system security policy is changed.

Confirmed live on a non-elevated Windows 11 session: `secedit /export`
exits with code 740 (ERROR_ELEVATION_REQUIRED) and writes no file when not
run as Administrator (AUTH-001..006 -> UNABLE_TO_COLLECT). Confirmed live
on an elevated session (2026-08-19) that the parse path also works end to
end: real values were recovered for every field (e.g. MinimumPasswordLength,
PasswordHistorySize both genuinely 0 on that machine), not just the
non-elevated failure path.

UAC state source: registry HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\
Policies\\System (EnableLUA, ConsentPromptBehaviorAdmin), read directly via
winreg -- no elevation required, confirmed live.

Screen lock state source: the machine-wide "Interactive logon: Machine
inactivity limit" GPO (InactivityTimeoutSecs, same policy key as UAC, also
readable without elevation) is checked first, since it forces a
password-protected lock regardless of any per-user screen saver setting.
When that policy is not configured, this falls back to the per-user
screen saver (HKCU\\Control Panel\\Desktop: ScreenSaveActive,
ScreenSaverIsSecure, ScreenSaveTimeOut) -- only counted as an effective
lock when the screen saver is both active and secure (password required
on resume); an active-but-insecure screen saver blanks the screen without
actually restricting access, so it is treated the same as no lock at all.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

from collectors.base import BaseCollector, CollectorContext
from utils import registry
from utils.helpers import safe_int
from utils.powershell import CREATE_NO_WINDOW

_POLICY_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_SCREENSAVER_KEY = r"Control Panel\Desktop"

_SECEDIT_FIELD_MAP = {
    "MinimumPasswordLength": "min_password_length",
    "PasswordComplexity": "password_complexity_enabled",
    "MaximumPasswordAge": "max_password_age_days",
    "PasswordHistorySize": "password_history_size",
    "LockoutBadCount": "lockout_threshold",
    "LockoutDuration": "lockout_duration_minutes",
}

_BOOLEAN_SECEDIT_FIELDS = {"password_complexity_enabled"}


class AuthenticationCollector(BaseCollector):
    collector_id = "authentication"

    def _collect(self, ctx: CollectorContext) -> None:
        self._collect_secedit_policy(ctx)
        self._collect_uac(ctx)
        self._collect_screen_lock(ctx)

    def _collect_secedit_policy(self, ctx: CollectorContext) -> None:
        fields = list(_SECEDIT_FIELD_MAP.values())
        fd, path = tempfile.mkstemp(suffix=".cfg", prefix="windows_auditor_secpol_")
        os.close(fd)
        try:
            proc = subprocess.run(
                ["secedit", "/export", "/cfg", path, "/areas", "SECURITYPOLICY"],
                capture_output=True, text=True, timeout=30,
                creationflags=CREATE_NO_WINDOW,
            )
            if proc.returncode != 0 or not os.path.exists(path):
                reason = (
                    "Administrator privileges required to export local security policy (secedit)"
                    if proc.returncode == 740
                    else f"secedit exited with code {proc.returncode}: {(proc.stdout or proc.stderr or '').strip()[:200]}"
                )
                for field in fields:
                    ctx.mark_error(field, reason)
                return

            parsed = self._parse_secedit_cfg(path)
            for cfg_key, field in _SECEDIT_FIELD_MAP.items():
                if cfg_key not in parsed:
                    ctx.mark_error(field, f"{cfg_key} not present in secedit export")
                    continue
                raw = parsed[cfg_key]
                if field in _BOOLEAN_SECEDIT_FIELDS:
                    ctx.set(field, raw == 1)
                else:
                    ctx.set(field, raw)
        except subprocess.TimeoutExpired:
            for field in fields:
                ctx.mark_error(field, "secedit command timed out")
        finally:
            if os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    self.logger.warning("Could not remove temporary secedit export file %s", path)

    @staticmethod
    def _parse_secedit_cfg(path: str) -> dict[str, int]:
        # secedit exports as UTF-16 with a BOM; fall back to utf-8 defensively.
        text = None
        for encoding in ("utf-16", "utf-8-sig", "utf-8"):
            try:
                with open(path, encoding=encoding) as f:
                    text = f.read()
                break
            except (UnicodeError, LookupError):
                continue
        if text is None:
            return {}

        result: dict[str, int] = {}
        for line in text.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key in _SECEDIT_FIELD_MAP:
                parsed = safe_int(value)
                if parsed is not None:
                    result[key] = parsed
        return result

    def _collect_uac(self, ctx: CollectorContext) -> None:
        enable_lua = registry.read_value("HKLM", _POLICY_KEY, "EnableLUA")
        if enable_lua.error:
            ctx.mark_error("uac_enabled", enable_lua.error)
        elif not enable_lua.exists:
            ctx.mark_error("uac_enabled", "EnableLUA registry value not found")
        else:
            ctx.set("uac_enabled", bool(enable_lua.value))

        consent_behavior = registry.read_value("HKLM", _POLICY_KEY, "ConsentPromptBehaviorAdmin")
        if consent_behavior.error:
            ctx.mark_error("uac_consent_prompt_behavior_admin", consent_behavior.error)
        elif not consent_behavior.exists:
            ctx.mark_error(
                "uac_consent_prompt_behavior_admin",
                "ConsentPromptBehaviorAdmin registry value not found",
            )
        else:
            ctx.set("uac_consent_prompt_behavior_admin", safe_int(consent_behavior.value))

    def _collect_screen_lock(self, ctx: CollectorContext) -> None:
        machine_limit = registry.read_value("HKLM", _POLICY_KEY, "InactivityTimeoutSecs")
        if machine_limit.error:
            ctx.mark_error("screen_lock_enabled", machine_limit.error)
            ctx.mark_error("screen_lock_timeout_minutes", machine_limit.error)
            return

        machine_timeout_secs = safe_int(machine_limit.value) if machine_limit.exists else None
        if machine_timeout_secs:
            ctx.set("screen_lock_enabled", True)
            ctx.set("screen_lock_timeout_minutes", max(1, round(machine_timeout_secs / 60)))
            return

        active = registry.read_value("HKCU", _SCREENSAVER_KEY, "ScreenSaveActive")
        secure = registry.read_value("HKCU", _SCREENSAVER_KEY, "ScreenSaverIsSecure")
        timeout = registry.read_value("HKCU", _SCREENSAVER_KEY, "ScreenSaveTimeOut")
        for result in (active, secure, timeout):
            if result.error:
                ctx.mark_error("screen_lock_enabled", result.error)
                ctx.mark_error("screen_lock_timeout_minutes", result.error)
                return

        screensaver_locks = (
            active.exists and str(active.value).strip() == "1"
            and secure.exists and str(secure.value).strip() == "1"
        )
        screensaver_timeout_secs = safe_int(timeout.value) if timeout.exists else None

        if screensaver_locks and screensaver_timeout_secs:
            ctx.set("screen_lock_enabled", True)
            ctx.set("screen_lock_timeout_minutes", max(1, round(screensaver_timeout_secs / 60)))
        else:
            ctx.set("screen_lock_enabled", False)
            ctx.set("screen_lock_timeout_minutes", 0)
