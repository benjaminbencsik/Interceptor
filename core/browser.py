"""Built-in browser launcher.

Opens a Chromium instance pre-wired to route through the proxy and trust
its interception, so the tester gets Burp-style "one-click browse" with no
manual proxy or certificate setup. Uses the system Chrome/Chromium when
found, otherwise falls back to Playwright's managed Chromium.

The browser runs in a throwaway profile so it never touches the user's real
Chrome. Testers who prefer their own browser + an extension like FoxyProxy
can still just point it at the proxy port — this is only the convenience
path.
"""
from __future__ import annotations

import glob
import os
import platform
import shutil
import subprocess
import tempfile
from typing import Optional


def detect_system_chrome() -> Optional[str]:
    """Locate a system Chrome/Chromium binary, or None."""
    if os.environ.get("CHROME_PATH") and os.path.exists(os.environ["CHROME_PATH"]):
        return os.environ["CHROME_PATH"]
    system = platform.system()
    candidates: list[str] = []
    if system == "Darwin":
        candidates = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        ]
    elif system == "Windows":
        for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(env)
            if base:
                candidates.append(os.path.join(base, "Google/Chrome/Application/chrome.exe"))
                candidates.append(os.path.join(base, "Chromium/Application/chrome.exe"))
    else:  # Linux / other
        for name in ("google-chrome", "google-chrome-stable", "chromium",
                     "chromium-browser", "brave-browser"):
            p = shutil.which(name)
            if p:
                return p
        candidates = ["/opt/google/chrome/chrome", "/usr/bin/chromium"]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def detect_playwright_chromium() -> Optional[str]:
    """Find Playwright's downloaded Chromium without importing Playwright."""
    system = platform.system()
    if system == "Darwin":
        cache = os.path.expanduser("~/Library/Caches/ms-playwright")
        rel = "chrome-mac/Chromium.app/Contents/MacOS/Chromium"
    elif system == "Windows":
        cache = os.path.join(os.environ.get("LOCALAPPDATA", ""), "ms-playwright")
        rel = "chrome-win/chrome.exe"
    else:
        cache = os.path.expanduser("~/.cache/ms-playwright")
        rel = "chrome-linux/chrome"
    if os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        cache = os.environ["PLAYWRIGHT_BROWSERS_PATH"]
    matches = sorted(glob.glob(os.path.join(cache, "chromium-*", rel)))
    return matches[-1] if matches else None


def resolve_binary(engine: str = "auto") -> tuple[Optional[str], str]:
    """Return (path, engine_used). engine in {auto, system, playwright}."""
    if engine == "system":
        return detect_system_chrome(), "system"
    if engine == "playwright":
        return detect_playwright_chromium(), "playwright"
    # auto: prefer the user's own Chrome, fall back to Playwright's
    sys_chrome = detect_system_chrome()
    if sys_chrome:
        return sys_chrome, "system"
    return detect_playwright_chromium(), "playwright"


class BrowserLauncher:
    def __init__(self, proxy_host: str, proxy_port: int,
                 web_host: str, web_port: int) -> None:
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.web_host = web_host
        self.web_port = web_port
        self._proc: Optional[subprocess.Popen] = None
        self._profile: Optional[str] = None
        self._engine_used: str = ""

    def available(self) -> dict:
        sysc = detect_system_chrome()
        pw = detect_playwright_chromium()
        return {
            "system": sysc, "playwright": pw,
            "any": bool(sysc or pw),
            "running": self.is_running(),
            "engine_used": self._engine_used,
        }

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def launch(self, *, engine: str = "auto", headless: bool = False,
               start_url: str = "about:blank") -> dict:
        if self.is_running():
            return {"ok": False, "error": "browser already running",
                    "engine": self._engine_used}
        binary, used = resolve_binary(engine)
        if not binary:
            return {"ok": False, "error":
                    "no Chromium found. Install Chrome, or run "
                    "`playwright install chromium`."}
        self._profile = tempfile.mkdtemp(prefix="interceptor-profile-")
        args = [
            binary,
            f"--user-data-dir={self._profile}",
            "--no-first-run", "--no-default-browser-check",
            f"--proxy-server=http://{self.proxy_host}:{self.proxy_port}",
            # proxy loopback too, so localhost targets are interceptable
            # (Chrome bypasses loopback by default)
            "--proxy-bypass-list=<-loopback>",
            # trust the proxy's on-the-fly certs in this throwaway profile
            "--ignore-certificate-errors",
            "--test-type",  # suppress the automation infobar
            "--disable-features=TranslateUI",
        ]
        if headless:
            args += ["--headless=new", "--disable-gpu", "--no-sandbox"]
        else:
            args += ["--new-window"]
        args.append(start_url)
        try:
            self._proc = subprocess.Popen(
                args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            self._engine_used = used
            return {"ok": True, "engine": used, "binary": binary,
                    "pid": self._proc.pid, "profile": self._profile}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def close(self) -> dict:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None
        if self._profile and os.path.isdir(self._profile):
            shutil.rmtree(self._profile, ignore_errors=True)
        self._profile = None
        return {"ok": True}
