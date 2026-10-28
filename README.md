# Interceptor

A web application security testing toolkit: an intercepting proxy with a
repeater, intruder, a passive/active vulnerability scanner, a target site-map,
a decoder, a built-in browser, and a Python extension API — all in a local
web UI.

> **Authorized testing only.** Use it on systems you own or have written
> permission to test. It generates real attack traffic.

## Features

- **Proxy + history** — intercepting TLS proxy; every request/response captured and scope-filtered.
- **Intercept** — pause, edit, and forward or drop in-scope requests.
- **Target / site map** — scan a list of subdomains/URLs; optional in-scope crawler.
- **Repeater** — edit and resend any request.
- **Intruder** — Sniper / Battering ram / Pitchfork / Cluster bomb payload attacks.
- **Scanner** — passive checks run automatically; active checks for XSS, SQLi, path traversal, open redirect, and SSTI.
- **Decoder** — base64/url/html/hex/gzip + hashes.
- **Built-in browser** — one-click Chromium pre-wired to the proxy.
- **Extensions** — drop a `.py` file in `extensions/`.

## Run it

**Windows (recommended):** download `Interceptor.exe` from the latest
[Actions run](../../actions) (or a release) and double-click it. No install.

**From source:**

```bash
pip install -r requirements.txt
python run.py            # proxy :8080, web UI :8000
```

Open **http://127.0.0.1:8000**. Click **Open browser** to start browsing
through the proxy, or point your own browser at `127.0.0.1:8080`.

## Build the exe yourself

```bash
pip install -r requirements.txt pyinstaller
pyinstaller --clean --noconfirm interceptor.spec   # -> dist/Interceptor.exe
```

Pushing to `main` builds it automatically on a Windows runner; tag `v*` to
publish a release.
