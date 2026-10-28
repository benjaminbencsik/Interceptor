"""FastAPI backend: REST for every tool + a WebSocket for live traffic.

The web UI is served from /, the API lives under /api, and /ws streams
flow/finding/intercept/log/intruder events pushed by the event bus.
"""
from __future__ import annotations

import asyncio
import os

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from core import encoder
from core.app_state import AppState
from core.models import body_to_bytes
from core.paths import web_dir

WEB_DIR = web_dir()


# ---- request models --------------------------------------------------
class SendReq(BaseModel):
    method: str
    url: str
    headers: list[list[str]]
    body: str = ""
    body_is_base64: bool = False
    follow_redirects: bool = False
    verify: bool = False


class InterceptForward(BaseModel):
    method: str | None = None
    path: str | None = None
    headers: list[list[str]] | None = None
    body: str | None = None
    body_is_base64: bool = False
    drop: bool = False


class ScopeReq(BaseModel):
    include: list[str] = []
    exclude: list[str] = []


class AuditReq(BaseModel):
    flow_id: str
    check_ids: list[str] | None = None


class TargetsAddReq(BaseModel):
    urls: list[str]


class TargetsSeedReq(BaseModel):
    crawl: bool = False
    max_crawl: int = 50


class IntruderReq(BaseModel):
    template: str
    scheme: str
    host: str
    port: int
    attack: str = "sniper"
    payload_sets: list[list[str]]
    sniper_original: str = ""
    concurrency: int = 10


class DecodeReq(BaseModel):
    mode: str
    op: str = "decode"
    text: str


class BrowserLaunchReq(BaseModel):
    engine: str = "auto"      # auto | system | playwright
    headless: bool = False
    start_url: str = "about:blank"


def create_app(state: AppState) -> FastAPI:
    app = FastAPI(title="interceptor")

    @app.get("/")
    async def index():
        return FileResponse(os.path.join(WEB_DIR, "index.html"))

    # ---- proxy settings / history -----------------------------------
    @app.get("/api/status")
    async def status():
        return {
            "intercept": state.intercept_enabled,
            "passive_auto": state.passive_auto,
            "held": state.held_ids(),
            "scope": state.scope.rules(),
            "flows": len(state.store.list_flows(limit=1)),
        }

    @app.get("/api/history")
    async def history(host: str = "", search: str = "", scope_only: bool = False,
                      limit: int = 500, offset: int = 0):
        return state.store.list_flows(
            host=host or None, search=search or None,
            in_scope_only=scope_only, limit=limit, offset=offset,
        )

    @app.get("/api/flow/{flow_id}")
    async def flow(flow_id: str):
        f = state.store.get_flow(flow_id)
        return f or JSONResponse({"error": "not found"}, status_code=404)

    @app.post("/api/history/clear")
    async def clear_history():
        state.store.clear_flows()
        return {"ok": True}

    # ---- intercept --------------------------------------------------
    @app.post("/api/intercept/toggle")
    async def intercept_toggle():
        state.intercept_enabled = not state.intercept_enabled
        state.events.publish("intercept_state", {"enabled": state.intercept_enabled})
        return {"enabled": state.intercept_enabled}

    @app.get("/api/intercept/pending")
    async def intercept_pending():
        out = []
        for fid in state.held_ids():
            fo = state.get_held(fid)
            if fo is not None:
                from core.models import request_to_dict
                out.append({"id": fid, "request": request_to_dict(fo.request),
                            "host": fo.request.pretty_host})
        return out

    @app.post("/api/intercept/{flow_id}/forward")
    async def intercept_forward(flow_id: str, req: InterceptForward):
        fo = state.release(flow_id)
        if fo is None:
            return JSONResponse({"error": "no such held flow"}, status_code=404)
        if req.drop:
            fo.kill()
            state.events.publish("intercept_resolved", {"id": flow_id, "dropped": True})
            return {"ok": True, "dropped": True}
        if req.method:
            fo.request.method = req.method
        if req.path is not None:
            fo.request.path = req.path
        if req.headers is not None:
            fo.request.headers.clear()
            for k, v in req.headers:
                fo.request.headers.add(k, v)
        if req.body is not None:
            fo.request.raw_content = body_to_bytes(req.body, req.body_is_base64)
        fo.resume()
        state.events.publish("intercept_resolved", {"id": flow_id, "dropped": False})
        return {"ok": True}

    # ---- scope ------------------------------------------------------
    @app.get("/api/scope")
    async def get_scope():
        return state.scope.rules()

    @app.post("/api/scope")
    async def set_scope(req: ScopeReq):
        state.scope.set_rules(req.include, req.exclude)
        return state.scope.rules()

    # ---- repeater ---------------------------------------------------
    @app.post("/api/repeater/send")
    async def repeater_send(req: SendReq):
        from core import sender
        return await sender.send(
            method=req.method, url=req.url, headers=req.headers,
            body=req.body, body_is_base64=req.body_is_base64,
            follow_redirects=req.follow_redirects, verify=req.verify,
        )

    # ---- scanner ----------------------------------------------------
    @app.get("/api/scanner/checks")
    async def scanner_checks():
        return {
            "active": [{"id": c.check_id, "name": c.name, "severity": c.severity}
                       for c in state.scanner.active_checks],
            "passive": [{"id": c.check_id, "name": c.name}
                        for c in state.scanner.passive_checks],
        }

    @app.post("/api/scanner/audit")
    async def scanner_audit(req: AuditReq):
        flow = state.store.get_flow(req.flow_id)
        if not flow:
            return JSONResponse({"error": "flow not found"}, status_code=404)
        ids = set(req.check_ids) if req.check_ids else None
        return await state.scanner.active_audit(flow, ids)

    @app.get("/api/findings")
    async def findings():
        return state.store.list_findings()

    @app.post("/api/findings/clear")
    async def clear_findings():
        state.store.clear_findings()
        return {"ok": True}

    # ---- targets ----------------------------------------------------
    @app.get("/api/targets")
    async def targets_list():
        return state.targets.list()

    @app.post("/api/targets/add")
    async def targets_add(req: TargetsAddReq):
        n = state.targets.add(req.urls)
        return {"added": n, "total": len(state.targets.list())}

    @app.post("/api/targets/seed")
    async def targets_seed(req: TargetsSeedReq):
        return await state.targets.seed(crawl=req.crawl, max_crawl=req.max_crawl)

    @app.post("/api/targets/audit")
    async def targets_audit(req: AuditReq | None = None):
        ids = set(req.check_ids) if (req and req.check_ids) else None
        return await state.targets.audit_all(ids)

    # ---- intruder ---------------------------------------------------
    @app.post("/api/intruder/start")
    async def intruder_start(req: IntruderReq):
        # fire and forget; results stream over WS and are retrievable by id
        task = asyncio.create_task(state.intruder.run(
            template=req.template, scheme=req.scheme, host=req.host, port=req.port,
            attack=req.attack, payload_sets=req.payload_sets,
            sniper_original=req.sniper_original, concurrency=req.concurrency,
        ))
        app.state._intruder_task = task  # keep a ref
        return {"started": True}

    # ---- decoder ----------------------------------------------------
    @app.get("/api/decoder/modes")
    async def decoder_modes():
        return encoder.MODES

    @app.post("/api/decoder")
    async def decode(req: DecodeReq):
        return {"result": encoder.transform(req.mode, req.op, req.text)}

    # ---- extensions -------------------------------------------------
    @app.get("/api/extensions")
    async def extensions():
        return state.ext.list()

    @app.post("/api/extensions/{ext_id}/toggle")
    async def ext_toggle(ext_id: str, enabled: bool = True):
        state.ext.set_enabled(ext_id, enabled)
        return {"ok": True}

    # ---- built-in browser ------------------------------------------
    @app.get("/api/browser")
    async def browser_status():
        if not state.browser:
            return {"any": False, "error": "browser launcher not configured"}
        return state.browser.available()

    @app.post("/api/browser/launch")
    async def browser_launch(req: BrowserLaunchReq):
        if not state.browser:
            return JSONResponse({"ok": False, "error": "not configured"}, status_code=500)
        import asyncio as _a
        # run the blocking spawn off the event loop
        return await _a.get_running_loop().run_in_executor(
            None, lambda: state.browser.launch(
                engine=req.engine, headless=req.headless, start_url=req.start_url))

    @app.post("/api/browser/close")
    async def browser_close():
        if not state.browser:
            return {"ok": True}
        return state.browser.close()

    @app.get("/api/logs")
    async def logs():
        return list(state.logs)

    # ---- websocket --------------------------------------------------
    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        q = state.events.subscribe()
        try:
            while True:
                msg = await q.get()
                await websocket.send_text(msg)
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass
        finally:
            state.events.unsubscribe(q)

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
    return app
