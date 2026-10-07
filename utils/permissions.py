"""Read-only privilege detection. Never attempts elevation or bypass."""

from __future__ import annotations

import ctypes


def is_admin() -> bool:
    """True if the current process token has administrative privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
