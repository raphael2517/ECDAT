"""
API authentication.

Opt-in by design. When ``ECDAT_API_KEY`` is unset the API stays open, because
that is what ``make up`` on localhost needs and enforcing a key there would
break the documented quickstart. Setting the variable turns enforcement on for
every route under ``/api``; the server logs a warning at startup while it is
unset, so a public deployment that forgot to set it is visible in the logs
rather than silently wide open.

Two transports, because they are not the same:

* **HTTP** carries the key in the ``X-ECDAT-Key`` header. Headers are not
  logged by default access-log formats and do not end up in shell history.
* **WebSocket** carries it as a ``?key=`` query parameter, because the browser
  WebSocket API cannot attach custom headers to the handshake. This is why the
  UI keeps the key in a field rather than a cookie: a query parameter on the
  WS URL is visible in server access logs, so keep it out of any log you
  publish, and always terminate TLS in front of this service.

Comparison is constant-time so a wrong key cannot be discovered one character
at a time.
"""

import hmac
import logging
import os
from typing import Optional

from fastapi import Header, HTTPException, Query, WebSocket

log = logging.getLogger("ecdat.api.auth")

API_KEY_ENV = "ECDAT_API_KEY"
API_KEY_HEADER = "X-ECDAT-Key"


def expected_key() -> Optional[str]:
    key = os.getenv(API_KEY_ENV, "").strip()
    return key or None


def auth_enabled() -> bool:
    return expected_key() is not None


def check_key(supplied: Optional[str]) -> bool:
    """Constant-time comparison against the configured key."""
    expected = expected_key()
    if expected is None:
        return True  # auth disabled - nothing to check
    if not supplied:
        return False
    return hmac.compare_digest(supplied, expected)


def _reject() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=(
            "missing or invalid API key; send it in the "
            f"{API_KEY_HEADER} header"
        ),
        headers={"WWW-Authenticate": API_KEY_HEADER},
    )


async def require_api_key(x_ecdat_key: Optional[str] = Header(default=None)) -> None:
    """FastAPI dependency for the HTTP routes."""
    if not check_key(x_ecdat_key):
        raise _reject()


async def require_ws_key(websocket: WebSocket) -> None:
    """
    WebSocket equivalent.

    Must run *before* ``accept()``: closing or rejecting after the handshake
    completes produces a confusing client-side error rather than a clean 401.
    """
    if not check_key(websocket.query_params.get("key")):
        await websocket.close(code=4401, reason="unauthorized")
        return
    await websocket.accept()


def startup_notice() -> None:
    if auth_enabled():
        log.warning("%s is set: /api requires a key", API_KEY_ENV)
    else:
        log.warning(
            "%s is not set: /api is OPEN to anyone who can reach this port. "
            "This is fine on localhost. It is NOT fine behind a tunnel - set "
            "%s to a long random value before exposing the service.",
            API_KEY_ENV, API_KEY_ENV,
        )
