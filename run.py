#!/usr/bin/env python3
"""interceptor entrypoint — runs the intercepting proxy and the web UI/API
on a single asyncio event loop.

    python run.py --proxy-port 8080 --web-port 8000

Then set your browser's HTTP(S) proxy to 127.0.0.1:<proxy-port> and open
http://127.0.0.1:<web-port> for the UI. Install the mitmproxy CA (printed
on startup) to intercept HTTPS.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn

from core.app_state import AppState
from core import proxy as proxy_mod
from server.app import create_app

BANNER = r"""
  ___       _                           _
 |_ _|_ __ | |_ ___ _ __ ___ ___ _ __ | |_ ___  _ __
  | || '_ \| __/ _ \ '__/ __/ _ \ '_ \| __/ _ \| '__|
  | || | | | ||  __/ | | (_|  __/ |_) | || (_) | |
 |___|_| |_|\__\___|_|  \___\___| .__/ \__\___/|_|
                                |_|  intercept · repeat · intrude · scan
"""


async def amain(args) -> None:
    db = args.db
    from core.paths import extensions_dir
    state = AppState(db)
    state.ext.load_dir(extensions_dir())

    from core.browser import BrowserLauncher
    state.browser = BrowserLauncher(args.proxy_host, args.proxy_port,
                                    args.web_host, args.web_port)

    master = proxy_mod.build_master(state, args.proxy_host, args.proxy_port)

    app = create_app(state)
    config = uvicorn.Config(app, host=args.web_host, port=args.web_port,
                            log_level="warning", loop="none")
    server = uvicorn.Server(config)

    ca = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
    print(BANNER)
    print(f"  proxy   : http://{args.proxy_host}:{args.proxy_port}")
    print(f"  web UI  : http://{args.web_host}:{args.web_port}")
    print(f"  CA cert : {ca}")
    print(f"            (install it in your browser/OS to intercept HTTPS)\n")

    if getattr(sys, "frozen", False) or args.open_ui:
        async def _open_ui():
            await asyncio.sleep(1.5)
            import webbrowser
            webbrowser.open(f"http://{args.web_host}:{args.web_port}")
        asyncio.create_task(_open_ui())

    await asyncio.gather(master.run(), server.serve())


def main() -> None:
    p = argparse.ArgumentParser(description="interceptor")
    p.add_argument("--proxy-host", default="127.0.0.1")
    p.add_argument("--proxy-port", type=int, default=8080)
    p.add_argument("--web-host", default="127.0.0.1")
    p.add_argument("--web-port", type=int, default=8000)
    p.add_argument("--db", default=":memory:",
                   help="SQLite path for persistence, or :memory: (default)")
    p.add_argument("--open-ui", action="store_true",
                   help="open the web UI in your default browser on startup")
    args = p.parse_args()
    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        print("\nshutting down.")


if __name__ == "__main__":
    main()
