"""
Safe, read-only Windows Registry access.

Distinguishes three outcomes for every read, which collectors must not
collapse into one another:
  - value found                              -> RegistryReadResult(exists=True, value=..., error=None)
  - key/value legitimately absent            -> RegistryReadResult(exists=False, value=None, error=None)
  - read failed for another reason           -> RegistryReadResult(exists=False, value=None, error="...")
    (permission denied, unexpected OS error)

A missing key is common and often meaningful (e.g. a policy that simply
hasn't been configured) — it is not the same as a collection failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

try:
    import winreg
except ImportError:  # pragma: no cover - only happens off-Windows
    winreg = None  # type: ignore

from utils.logging_config import get_logger

logger = get_logger("registry")

_HIVES = {}
if winreg is not None:
    _HIVES = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
        "HKCC": winreg.HKEY_CURRENT_CONFIG,
    }


@dataclass
class RegistryReadResult:
    exists: bool
    value: Any
    error: Optional[str] = None


def _resolve_hive(hive: str):
    if winreg is None:
        raise RuntimeError("winreg is only available on Windows")
    try:
        return _HIVES[hive.upper()]
    except KeyError as e:
        raise ValueError(f"Unknown registry hive: {hive}") from e


def read_value(hive: str, subkey: str, value_name: str) -> RegistryReadResult:
    """Read a single named value from subkey. See module docstring for
    the exists/error contract."""
    if winreg is None:
        return RegistryReadResult(exists=False, value=None, error="winreg unavailable on this platform")

    try:
        root = _resolve_hive(hive)
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
            value, _regtype = winreg.QueryValueEx(key, value_name)
            return RegistryReadResult(exists=True, value=value)
    except FileNotFoundError:
        return RegistryReadResult(exists=False, value=None, error=None)
    except PermissionError as e:
        logger.warning("Permission denied reading %s\\%s [%s]", hive, subkey, value_name)
        return RegistryReadResult(exists=False, value=None, error=f"permission denied: {e}")
    except OSError as e:
        logger.warning("OS error reading %s\\%s [%s]: %s", hive, subkey, value_name, e)
        return RegistryReadResult(exists=False, value=None, error=str(e))


def key_exists(hive: str, subkey: str) -> RegistryReadResult:
    """Check only for key presence (no value read). Useful for markers
    like the SecureBoot state key that only exist on UEFI systems."""
    if winreg is None:
        return RegistryReadResult(exists=False, value=None, error="winreg unavailable on this platform")

    try:
        root = _resolve_hive(hive)
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ):
            return RegistryReadResult(exists=True, value=True)
    except FileNotFoundError:
        return RegistryReadResult(exists=False, value=False, error=None)
    except PermissionError as e:
        return RegistryReadResult(exists=False, value=None, error=f"permission denied: {e}")
    except OSError as e:
        return RegistryReadResult(exists=False, value=None, error=str(e))


def enumerate_subkeys(hive: str, subkey: str) -> RegistryReadResult:
    """List immediate subkey names under subkey."""
    if winreg is None:
        return RegistryReadResult(exists=False, value=None, error="winreg unavailable on this platform")

    try:
        root = _resolve_hive(hive)
        names: list[str] = []
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
        return RegistryReadResult(exists=True, value=names)
    except FileNotFoundError:
        return RegistryReadResult(exists=False, value=None, error=None)
    except PermissionError as e:
        return RegistryReadResult(exists=False, value=None, error=f"permission denied: {e}")
    except OSError as e:
        return RegistryReadResult(exists=False, value=None, error=str(e))


def enumerate_values(hive: str, subkey: str) -> RegistryReadResult:
    """Return {value_name: value} for all values directly under subkey."""
    if winreg is None:
        return RegistryReadResult(exists=False, value=None, error="winreg unavailable on this platform")

    try:
        root = _resolve_hive(hive)
        values: dict[str, Any] = {}
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, value, _regtype = winreg.EnumValue(key, i)
                    values[name] = value
                    i += 1
                except OSError:
                    break
        return RegistryReadResult(exists=True, value=values)
    except FileNotFoundError:
        return RegistryReadResult(exists=False, value=None, error=None)
    except PermissionError as e:
        return RegistryReadResult(exists=False, value=None, error=f"permission denied: {e}")
    except OSError as e:
        return RegistryReadResult(exists=False, value=None, error=str(e))
