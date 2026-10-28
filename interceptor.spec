# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Interceptor (single-file executable).

mitmproxy ships data files and relies on dynamic imports, so we collect it
whole. The web UI and bundled extensions are added as data and resolved at
runtime via core.paths (sys._MEIPASS when frozen).

Build:  pyinstaller interceptor.spec
Output: dist/Interceptor(.exe)
"""
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = [("web", "web"), ("extensions", "extensions")]
binaries = []
hiddenimports = []

# mitmproxy: grab package data + submodules + its dynamic imports
for pkg in ("mitmproxy",):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

# things pulled in dynamically that static analysis can miss
hiddenimports += collect_submodules("uvicorn")
hiddenimports += collect_submodules("mitmproxy.addons")
hiddenimports += collect_submodules("mitmproxy.proxy")
hiddenimports += collect_submodules("mitmproxy.contentviews")
hiddenimports += [
    "h2", "h11", "hpack", "hyperframe", "kaitaistruct", "zstandard",
    "brotli", "anyio", "sniffio", "httpcore", "httpx", "websockets",
    "websockets.legacy", "passlib.handlers.bcrypt",
]

a = Analysis(
    ["run.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Interceptor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
)
