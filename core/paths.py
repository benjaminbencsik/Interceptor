"""Resource path resolution that works both from source and when frozen
into a single executable by PyInstaller.

When frozen, data files (web UI, bundled extensions) are unpacked to
``sys._MEIPASS`` at runtime; from source they sit next to the package.
"""
from __future__ import annotations

import os
import sys


def base_dir() -> str:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS  # type: ignore[attr-defined]
    # project root = parent of this file's package (core/)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def web_dir() -> str:
    return os.path.join(base_dir(), "web")


def extensions_dir() -> str:
    return os.path.join(base_dir(), "extensions")
