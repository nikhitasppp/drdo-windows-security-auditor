"""
Single choke point for invoking PowerShell.

Every collector that needs PowerShell goes through run_powershell() here so
that: invocation flags are consistent (no profile, non-interactive, no
policy prompts), output is always parsed as structured JSON rather than
scraped from formatted text, and every failure mode (missing PowerShell,
timeout, non-zero exit, malformed JSON) is turned into an explicit,
collector-friendly result instead of an exception.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any, Optional

from utils.logging_config import get_logger

logger = get_logger("powershell")

DEFAULT_TIMEOUT_SECONDS = 30.0

# Suppresses the console window Windows would otherwise pop up for this
# child process. Irrelevant (and harmless) when this app itself has a
# console (the CLI build), but essential for the windowed GUI build
# (console=False): with no parent console to attach to, every spawned
# powershell.exe would otherwise flash its own new console window.
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


@dataclass
class PowerShellResult:
    success: bool
    data: Any = None
    error: Optional[str] = None
    raw_stdout: str = ""
    raw_stderr: str = ""


def to_json_command(expression: str, depth: int = 5) -> str:
    """Wrap a PowerShell expression so its output is emitted as compact JSON."""
    return f"{expression} | ConvertTo-Json -Depth {depth} -Compress"


def run_powershell(command: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> PowerShellResult:
    """
    Run `command` in a non-interactive PowerShell host and parse stdout as
    JSON. `command` is expected to already end in a ConvertTo-Json pipe
    (see to_json_command) — this function does not append one automatically,
    since some callers intentionally return $null or a scalar.
    """
    args = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", command,
    ]

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired:
        logger.warning("PowerShell command timed out after %ss", timeout)
        return PowerShellResult(success=False, error=f"command timed out after {timeout}s")
    except FileNotFoundError:
        logger.error("powershell.exe not found on this system")
        return PowerShellResult(success=False, error="powershell.exe not found")
    except OSError as e:
        logger.error("Failed to launch PowerShell: %s", e)
        return PowerShellResult(success=False, error=str(e))

    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()

    if proc.returncode != 0:
        logger.warning("PowerShell command exited %s: %s", proc.returncode, stderr[:300])
        return PowerShellResult(
            success=False,
            error=stderr or f"powershell exited with code {proc.returncode}",
            raw_stdout=stdout,
            raw_stderr=stderr,
        )

    if not stdout:
        # Valid outcome: command legitimately produced no output (e.g. $null).
        return PowerShellResult(success=True, data=None, raw_stdout=stdout, raw_stderr=stderr)

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse PowerShell JSON output: %s", e)
        return PowerShellResult(
            success=False,
            error=f"failed to parse JSON output: {e}",
            raw_stdout=stdout,
            raw_stderr=stderr,
        )

    return PowerShellResult(success=True, data=data, raw_stdout=stdout, raw_stderr=stderr)


@dataclass
class PsCapture:
    """Outcome of a single PowerShell expression evaluated via run_ps_capture().

    ok=True  -> the expression ran without throwing; `data` holds its result
                (which may legitimately be None/empty).
    ok=False -> the expression raised a terminating error inside PowerShell
                itself (e.g. "Access denied", "Administrator privilege is
                required"); `error` holds that message. This is distinct
                from PowerShellResult.success, which only reflects whether
                the *outer* powershell.exe process launched and returned
                exit code 0 — a cmdlet can fail internally while the host
                process still exits 0, so relying on exit code alone is not
                sufficient (confirmed against Get-BitLockerVolume/Get-WinEvent
                on a non-elevated Windows 11 session).
    """

    ok: bool
    data: Any = None
    error: Optional[str] = None


def run_ps_capture(expression: str, depth: int = 5, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> PsCapture:
    """
    Evaluate a single PowerShell expression and reliably distinguish success
    from an internal (terminating) failure, regardless of the host process's
    exit code. The expression should use -ErrorAction Stop on any cmdlet
    whose failure must be caught (non-terminating errors are not caught by
    the wrapping try/catch below).
    """
    script = (
        "$__err = $null\n"
        "try {\n"
        f"  $__data = {expression}\n"
        "} catch {\n"
        "  $__err = $_.Exception.Message\n"
        "}\n"
        "[PSCustomObject]@{ ok = ($null -eq $__err); data = $__data; error = $__err } | "
        f"ConvertTo-Json -Depth {depth} -Compress"
    )

    ps_result = run_powershell(script, timeout=timeout)
    if not ps_result.success:
        return PsCapture(ok=False, error=ps_result.error)

    payload = ps_result.data
    if not isinstance(payload, dict):
        return PsCapture(ok=False, error=f"unexpected output shape: {type(payload).__name__}")

    return PsCapture(ok=bool(payload.get("ok")), data=payload.get("data"), error=payload.get("error"))
