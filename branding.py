"""
Centralized branding/organization constants for CABS IT AUDITING TOOL.

Single source of truth for text and asset paths that would otherwise be
duplicated across gui_app.py and every reporting/*.py module. Nothing
here affects audit logic -- it's presentation metadata only.
"""

from __future__ import annotations

import sys
from pathlib import Path

APP_NAME = "CABS IT AUDITING TOOL"
ORGANIZATION = "CABS BANGALORE"
LOCATION = "NEW DELHI"
MINISTRY = "DRDO, Ministry of Defence"

NAVY_BLUE = "#001a4d"
NAVY_BLUE_RGB = (0, 26, 77)
WHITE_RGB = (255, 255, 255)

# Mirrors main.py's APP_DIR/BUNDLE_DIR frozen-aware resolution: assets
# embedded by PyInstaller live under sys._MEIPASS at runtime, not next to
# the actual .exe.
if getattr(sys, "frozen", False):
    _BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
else:
    _BUNDLE_DIR = Path(__file__).resolve().parent

_LOGO_PNG = _BUNDLE_DIR / "assets" / "drdo_logo.png"
_LOGO_ICO = _BUNDLE_DIR / "assets" / "drdo_logo.ico"


def get_logo_path() -> Path | None:
    """Path to the local DRDO logo PNG, or None if it isn't present.
    Never fetched at runtime -- offline by construction."""
    return _LOGO_PNG if _LOGO_PNG.exists() else None


def get_icon_path() -> Path | None:
    """Path to the local DRDO logo .ico (for the window/exe icon), or None."""
    return _LOGO_ICO if _LOGO_ICO.exists() else None
