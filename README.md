# Interceptor

A Burp-Suite-style web application security testing toolkit, built on
[mitmproxy](https://mitmproxy.org/) with a FastAPI backend and a single-page
web UI. Intercepting proxy, repeater, intruder, an extensible passive/active
scanner, a target/site-map list for scanning many subdomains, a decoder, and
a Python extension API.

> **Authorized testing only.** Point this at systems you own or have explicit
> written permission to test. It generates real attack traffic.

## Features

| Tool | What it does |
|------|--------------|
| **Proxy + HTTP history** | TLS-intercepting proxy (mitmproxy core). Every request/response is captured, stored, and shown live. Scope-aware. |
| **Built-in browser** | One-click Chromium pre-wired to the proxy with HTTPS interception already trusted and an isolated profile. Uses system Chrome if present, else Playwright's Chromium. |
| **Intercept** | Pause in-scope requests, edit the raw request, forward or drop. |
| **Target / Site map** | Paste a list of subdomains/URLs, fetch them all, passively scan, and queue active audits across the whole list. Optional in-scope link crawler. |
| **Repeater** | Edit and resend any request, inspect the raw response with timing. |
| **Intruder** | Payload automation with Sniper / Battering ram / Pitchfork / Cluster bomb; results stream live. |
| **Scanner** | Passive checks run automatically on in-scope traffic; active checks (XSS, SQLi, path traversal, open redirect, SSTI) run on demand per request or across all targets. |
| **Decoder** | base64/url/html/hex/gzip encode-decode + md5/sha1/sha256/sha512. |
| **Extensions** | Drop a `.py` file in `extensions/`; implement `on_request` / `on_response` / `passive_scan`. |

## Install & run

```bash
pip install -r requirements.txt
python run.py                       # proxy :8080, web UI :8000
python run.py --proxy-port 8081 --web-port 8000 --db session.sqlite
```

Open the UI at **http://127.0.0.1:8000**.

### Windows without installing Python

Extract the archive, then **double-click `run_windows.bat`**. The first run
pulls a portable (embeddable) Python into `.\pydist`, installs the
dependencies there, and launches — nothing is installed system-wide, no
admin required. Later runs start instantly. To uninstall, delete the folder.

> The portable Python is downloaded once from python.org; the machine needs
> internet access for that first run.

### Native Windows .exe (single binary, no Python at all)

A GitHub Actions workflow builds a standalone `Interceptor.exe` on a Windows
runner — no Python, no first-run download for the end user.

1. Push this project to a GitHub repo.
2. The workflow (`.github/workflows/build-windows.yml`) runs on every push to
   `main`; download **Interceptor.exe** from the run's *Artifacts*.
3. Tag a release (`git tag v1.0.0 && git push --tags`) to also publish the exe
   on a GitHub Release.

Build it locally on Windows instead:

```powershell
pip install -r requirements.txt pyinstaller
pyinstaller --clean --noconfirm interceptor.spec
# -> dist\Interceptor.exe
```

The exe bundles the proxy, web UI, and example extensions; double-clicking it
starts everything and opens the UI in your browser. Because it's unsigned,
Windows SmartScreen may warn on first launch ("More info" -> "Run anyway") —
expected for any unsigned binary; code-signing removes it.

### Intercepting HTTPS

1. Set your browser/system HTTP(S) proxy to `127.0.0.1:8080`.
2. Install the mitmproxy CA certificate (path printed on startup, e.g.
   `~/.mitmproxy/mitmproxy-ca-cert.pem`) in your browser/OS trust store.
   Easiest: with the proxy set, browse to `http://mitm.it` and follow the
   platform instructions.
3. Traffic now appears in **Proxy → HTTP history**.

Set a **Target → Scope** (e.g. `*.example.com`) so interception and passive
scanning only touch what you're allowed to test.

### Built-in browser (no setup)

Click **🌐 Open browser** in the header. It launches Chromium already
pointed at the proxy, with the interception certificate trusted and a clean,
isolated profile — so HTTPS traffic is captured immediately with no CA
install or proxy config. It prefers your system Chrome/Chromium and falls
back to Playwright's Chromium (`pip install playwright && playwright install
chromium`). Loopback is proxied too, so you can test `localhost` apps.

Prefer your own browser and a proxy switcher like FoxyProxy? That still
works — just point it at `127.0.0.1:8080`. The built-in browser is only the
zero-setup convenience path.

## Architecture

```
run.py                 # starts proxy master + uvicorn on one asyncio loop
core/
  proxy.py             # mitmproxy addon: capture, intercept, passive scan hook
  app_state.py         # shared state wired into proxy + server
  store.py             # SQLite flows + findings
  sender.py            # outbound HTTP for repeater/intruder/scanner (httpx)
  scope.py             # include/exclude host rules
  encoder.py           # decoder transforms
  intruder.py          # attack engine (4 modes, § markers)
  extensions.py        # extension loader + hook dispatch
  targets.py           # target list + crawler
  browser.py           # built-in browser launcher (system Chrome / Playwright)
  scanner/
    base.py            # Finding, check base classes
    passive.py         # security headers, cookie flags, banner, errors, dir listing
    active.py          # XSS, SQLi, path traversal, open redirect, SSTI
    engine.py          # insertion-point enumeration, baseline diffing, dedup
server/app.py          # FastAPI REST + /ws WebSocket
web/                   # index.html + app.js + style.css
extensions/            # example_passive.py, example_header_tag.py
```

## Writing an extension

```python
# extensions/my_check.py
NAME = "My check"
DESCRIPTION = "Flags responses missing a cache-control header."

def passive_scan(ctx, flow):
    resp = flow.get("response")
    if resp and not any(k.lower() == "cache-control" for k, _ in resp["headers"]):
        ctx.finding(name="No Cache-Control", severity="info",
                    detail="Response has no Cache-Control header.", flow=flow)
    return []

def on_request(ctx, flow):
    flow["request"]["headers"].append(["X-My-Tag", "1"])  # mutate in place
```

`flow` is a dict: `flow["request"]` has `method, scheme, host, port, path,
url, headers (list of [k,v]), body, body_is_base64`; `flow["response"]` has
`status_code, headers, body, body_is_base64`.

## Extending the scanner

Add a passive check by subclassing `PassiveCheck` in `core/scanner/passive.py`
and appending to `ALL_PASSIVE`. Add an active check by subclassing
`ActiveCheck` in `core/scanner/active.py` (declare `payloads` + a `detect()`
that compares the probe response to the baseline) and appending to
`ALL_ACTIVE`. The engine handles insertion points and sending.

## Roadmap ideas

- Request/response search and match-and-replace rules
- WebSocket message interception
- Session handling / macro replay for authenticated scans
- Collaborator-style out-of-band (OAST) detection for blind injection
- Export findings to HTML/JSON/SARIF
- Persisted projects, saved Intruder attacks, and a comparer diff view
