"""Small, shared normalization helpers used by multiple collectors."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Optional

# PowerShell 5.1's ConvertTo-Json renders System.DateTime using the legacy
# ASP.NET AJAX "/Date(ticks)/" convention (ticks = ms since Unix epoch),
# NOT an ISO-8601 string -- confirmed against Win32_OperatingSystem.LastBootUpTime
# and Get-LocalUser.LastLogon on a live Windows 11 (build 26200) host. Some CIM
# datetime properties instead arrive as {"value": "/Date(...)/", "DateTime": "<readable string>"}
# (seen on Win32_QuickFixEngineering.InstalledOn) - callers should pass the
# "DateTime" sub-field or the raw "/Date(...)/" string to this function.
_DOTNET_DATE_RE = re.compile(r"^/Date\((-?\d+)\)/$")

_DATETIME_FORMATS = (
    "%d %B %Y %H:%M:%S",       # e.g. "16 August 2026 00:00:00" (CIM .DateTime sub-field)
    "%a, %d %b %Y %H:%M:%S %Z",  # e.g. "Thu, 15 Sep 2022 19:03:43 GMT" (SecurityCenter2 AntivirusProduct.timestamp)
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
)


def parse_datetime(value: Any) -> Optional[datetime]:
    """Best-effort parse of a PowerShell/CIM-originated timestamp. Accepts
    the .NET "/Date(ms)/" form, the CIM readable-string form, or ISO-8601.
    Returns None if the value is missing or unrecognized — callers must
    treat that as "could not determine", not as a specific date."""
    if not value or not isinstance(value, str):
        return None

    m = _DOTNET_DATE_RE.match(value.strip())
    if m:
        try:
            return datetime.fromtimestamp(int(m.group(1)) / 1000.0)
        except (ValueError, OverflowError, OSError):
            return None

    for fmt in _DATETIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def days_since(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
    return (now - dt).days


def bytes_to_gb(num_bytes: Any, precision: int = 1) -> Optional[float]:
    try:
        return round(float(num_bytes) / (1024 ** 3), precision)
    except (TypeError, ValueError):
        return None


def safe_float(value: Any) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def safe_int(value: Any) -> Optional[int]:
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def as_list(value: Any) -> list:
    """PowerShell's ConvertTo-Json collapses a single-item array to a bare
    object, so a field that is normally a list may arrive as a dict or
    scalar when exactly one item is present. Normalize to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
