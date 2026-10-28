"""Example request-rewriting extension.

Adds a custom header to every outbound request so downstream tooling can
identify traffic from this proxy. Demonstrates the on_request hook mutating
a flow in place.
"""
NAME = "Example: tag outbound requests"
DESCRIPTION = "Adds 'X-Scanned-By: interceptor' to every in-scope request."


def on_request(ctx, flow):
    headers = flow["request"]["headers"]
    if not any(k.lower() == "x-scanned-by" for k, _ in headers):
        headers.append(["X-Scanned-By", "interceptor"])
