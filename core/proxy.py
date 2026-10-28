"""mitmproxy addon + master bootstrap.

The addon is the bridge between mitmproxy's flow lifecycle and our AppState:
it captures flows, applies scope, drives interception, runs passive scans,
and streams live updates to the UI.
"""
from __future__ import annotations

import asyncio

from mitmproxy import http
from mitmproxy.addons import default_addons, script
from mitmproxy.master import Master
from mitmproxy.options import Options

from . import models
from .app_state import AppState


class CaptureAddon:
    def __init__(self, state: AppState) -> None:
        self.state = state

    async def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        in_scope = self.state.scope.in_scope(host)

        # Let extensions see/modify the request before it goes out.
        fd = models.flow_to_dict(flow)
        try:
            self.state.ext.run_request(fd)
        except Exception:
            pass

        if self.state.intercept_enabled and in_scope:
            self.state.hold(flow.id, flow)
            self.state.events.publish("intercept", {
                "id": flow.id,
                "request": models.request_to_dict(flow.request),
                "host": host,
            })
            flow.intercept()  # core awaits resume() before forwarding

    async def response(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        in_scope = self.state.scope.in_scope(host)
        fd = models.flow_to_dict(flow)
        seq = self.state.store.save_flow(fd, in_scope=in_scope)

        self.state.events.publish("flow", {
            "id": flow.id, "seq": seq, "host": host,
            "method": flow.request.method, "path": flow.request.path,
            "status_code": flow.response.status_code if flow.response else None,
            "mime_type": fd["mime_type"], "length": fd["response_length"],
            "in_scope": in_scope,
        })

        if self.state.passive_auto and in_scope:
            # offload scan so a slow check never stalls the proxy loop
            asyncio.get_running_loop().run_in_executor(None, self.state.scanner.passive_scan, fd)


def build_master(state: AppState, host: str, port: int) -> Master:
    opts = Options(listen_host=host, listen_port=port)
    master = Master(opts, event_loop=asyncio.get_running_loop())
    # Start from mitmproxy's default addon stack minus the interactive script
    # loader, then add ours.
    addons = [a for a in default_addons() if not isinstance(a, script.ScriptLoader)]
    master.addons.add(*addons)
    master.addons.add(CaptureAddon(state))
    opts.update(
        ssl_insecure=True,
        http2=True,
    )
    return master
