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

## Download & run

Grab `Interceptor.exe` from the [latest release](../../releases/latest) and
double-click it. No install. It starts the proxy and opens the UI in your
browser; click **Open browser** to browse through the proxy.
