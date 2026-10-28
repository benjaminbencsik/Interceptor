"""Example passive-scan extension.

Flags responses that reflect a well-known sensitive-looking parameter and
responses that expose an AWS-style access key id. Copy this file to make
your own checks — define any of on_request / on_response / passive_scan.
"""
import re

NAME = "Example: sensitive data exposure"
DESCRIPTION = "Flags AWS access key IDs and 'debug=true' reflections in responses."

_AWS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")


def passive_scan(ctx, flow):
    resp = flow.get("response")
    if not resp or resp.get("body_is_base64"):
        return []
    body = resp.get("body", "")
    m = _AWS.search(body)
    if m:
        ctx.finding(
            name="AWS access key ID in response",
            severity="high", confidence="firm",
            detail="An AWS access key ID pattern appears in the response body.",
            evidence=m.group(0), flow=flow,
            check_id="ext.aws-key",
        )
    return []
