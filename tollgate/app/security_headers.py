"""Security headers on every response, errors included.

No inline scripts are allowed: the only script is /static/countdown.js.
`no-store` keeps pages (including the one-time QR page) out of the browser cache.
"""
from __future__ import annotations

from typing import Awaitable, Callable

from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")

HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


async def add_security_headers(request: Request,
                               call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    try:
        response = await call_next(request)
    except Exception:                     # fail closed: generic refusal, no details
        response = PlainTextResponse("refused: internal error", status_code=500)
    for name, value in HEADERS.items():
        response.headers[name] = value
    return response
