"""Tiny JSON-over-HTTPS client on the standard library (urllib). No new dependency.

Errors never carry headers (where the API key lives) or response bodies: callers
get only a status code or a fixed category such as "timeout".

Redirects are never followed. urllib would otherwise copy the authorization header
to the new address, which could be plain http. Any 3xx reply is a failure ("redirect").
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

MAX_RESPONSE_BYTES = 1_000_000
MAX_ERROR_BYTES = 20_000
USER_AGENT = "tollgate/0.3 (sandbox)"   # some API front-ends block the default Python-urllib agent


@dataclass(frozen=True)
class HttpReply:
    status: int
    body: Any                     # parsed JSON, or None if the body was not JSON
    retry_after: float | None = None
    error_code: str | None = None  # provider's short error code (e.g. "tool_use_failed"), never its message


class TransportError(Exception):
    """Network-level failure. `category` is "timeout", "network" or "redirect"; nothing else."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


class HttpClient(Protocol):
    def post_json(self, url: str, headers: Mapping[str, str], body: Mapping[str, Any],
                  timeout: float) -> HttpReply: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: returning None makes urllib raise HTTPError with the 3xx code."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class UrllibClient:
    """Real client. Only https URLs are accepted and redirects are refused, so a key
    never travels in clear text or to an address it was not meant for.

    `handlers` is for tests only (fake network handlers); real use passes nothing.
    """

    def __init__(self, handlers: tuple[urllib.request.BaseHandler, ...] = ()) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect(), *handlers)

    def post_json(self, url: str, headers: Mapping[str, str], body: Mapping[str, Any],
                  timeout: float) -> HttpReply:
        if not url.startswith("https://"):
            raise TransportError("network")
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"content-type": "application/json",
                                              "user-agent": USER_AGENT, **headers})
        try:
            with self._opener.open(req, timeout=timeout) as resp:  # noqa: S310 (https only)
                return HttpReply(resp.status, _parse(resp.read(MAX_RESPONSE_BYTES + 1)))
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                exc.close()
                raise TransportError("redirect") from None
            retry = _retry_after(exc.headers.get("retry-after") if exc.headers else None)
            code = error_code(_parse(_read_quietly(exc)))
            exc.close()
            return HttpReply(exc.code, None, retry, code)
        except (TimeoutError, socket.timeout):
            raise TransportError("timeout") from None
        except urllib.error.URLError as exc:
            category = "timeout" if isinstance(exc.reason, (TimeoutError, socket.timeout)) \
                else "network"
            raise TransportError(category) from None
        except OSError:
            raise TransportError("network") from None


def _parse(raw: bytes) -> Any:
    if len(raw) > MAX_RESPONSE_BYTES:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def _read_quietly(exc: urllib.error.HTTPError) -> bytes:
    try:
        return exc.read(MAX_ERROR_BYTES)
    except Exception:
        return b""


def error_code(body: Any) -> str | None:
    """Keep only a short identifier-like `error.code` (or `error.type`) from an error body.

    The error *message* is dropped: it can echo the request, including customer text.
    """
    err = body.get("error") if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return None
    for field in ("code", "type"):
        value = err.get(field)
        if isinstance(value, str) and 0 < len(value) <= 40 and value.replace("_", "").isalnum():
            return value
    return None


def _retry_after(value: str | None) -> float | None:
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None
