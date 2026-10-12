"""
Tests for the API key gate.

Skipped when fastapi is not importable. The local unit-test venv carries only
the scanner's dependencies; the API's live in the container image, so this file
is exercised by `make test-e2e` and skipped by `make test-unit`. That is the
right split - there is nothing to test here without the API installed.

The property that matters is asymmetric, so both directions are asserted: with
a key configured, requests without it must fail, and requests with the right
key must still succeed. A gate that rejected everything would pass a naive "is
it locked?" check while breaking the product.

The async callables are driven with asyncio.run rather than pytest-asyncio,
which keeps the test dependency list to just pytest.
"""

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api" / "src"))

pytest.importorskip("fastapi", reason="API deps live in the image; run `make test-e2e`")

import security  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("ECDAT_API_KEY", raising=False)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# disabled (default, localhost dev)
# ---------------------------------------------------------------------------
def test_open_when_key_unset():
    assert security.auth_enabled() is False
    assert security.check_key(None) is True
    assert security.check_key("anything") is True


def test_blank_key_counts_as_unset(monkeypatch):
    monkeypatch.setenv("ECDAT_API_KEY", "   ")
    assert security.auth_enabled() is False


# ---------------------------------------------------------------------------
# enabled (deployment)
# ---------------------------------------------------------------------------
def test_rejects_missing_key(monkeypatch):
    monkeypatch.setenv("ECDAT_API_KEY", "s3cret-value")
    assert security.check_key(None) is False
    assert security.check_key("") is False


@pytest.mark.parametrize(
    "candidate",
    ["s3cret-valu", "s3cret-valueX", "S3CRET-VALUE", "s3cret-value\n", " s3cret-value"],
)
def test_rejects_near_misses(monkeypatch, candidate):
    """
    One char short, one char long, wrong case, stray newline, leading space.
    A pasted key must not be silently trimmed into working.
    """
    monkeypatch.setenv("ECDAT_API_KEY", "s3cret-value")
    assert security.check_key(candidate) is False


def test_accepts_exact_key(monkeypatch):
    monkeypatch.setenv("ECDAT_API_KEY", "s3cret-value")
    assert security.check_key("s3cret-value") is True


def test_key_is_trimmed_from_the_environment(monkeypatch):
    """env vars pick up stray whitespace from .env files and shells."""
    monkeypatch.setenv("ECDAT_API_KEY", "  s3cret-value  ")
    assert security.expected_key() == "s3cret-value"
    assert security.check_key("s3cret-value") is True


# ---------------------------------------------------------------------------
# HTTP dependency
# ---------------------------------------------------------------------------
def test_dependency_passes_when_disabled():
    assert run(security.require_api_key(x_ecdat_key=None)) is None


def test_dependency_raises_401_when_wrong(monkeypatch):
    from fastapi import HTTPException

    monkeypatch.setenv("ECDAT_API_KEY", "s3cret-value")
    with pytest.raises(HTTPException) as exc:
        run(security.require_api_key(x_ecdat_key="wrong"))
    assert exc.value.status_code == 401
    assert "X-ECDAT-Key" in exc.value.detail


def test_dependency_passes_with_right_key(monkeypatch):
    monkeypatch.setenv("ECDAT_API_KEY", "s3cret-value")
    assert run(security.require_api_key(x_ecdat_key="s3cret-value")) is None


# ---------------------------------------------------------------------------
# WebSocket gate
# ---------------------------------------------------------------------------
class _FakeWS:
    """Minimal stand-in for a Starlette WebSocket."""

    def __init__(self, query: str = ""):
        self.query_params = {"key": query} if query else {}
        self.accepted = False
        self.closed_with = None

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000, reason=""):
        self.closed_with = (code, reason)


def test_ws_rejected_without_key(monkeypatch):
    monkeypatch.setenv("ECDAT_API_KEY", "s3cret-value")
    ws = _FakeWS()
    run(security.require_ws_key(ws))
    assert ws.accepted is False, "must refuse before accepting the handshake"
    assert ws.closed_with[0] == 4401


def test_ws_rejected_with_wrong_key(monkeypatch):
    monkeypatch.setenv("ECDAT_API_KEY", "s3cret-value")
    ws = _FakeWS("nope")
    run(security.require_ws_key(ws))
    assert ws.accepted is False
    assert ws.closed_with[0] == 4401


def test_ws_accepted_with_right_key(monkeypatch):
    monkeypatch.setenv("ECDAT_API_KEY", "s3cret-value")
    ws = _FakeWS("s3cret-value")
    run(security.require_ws_key(ws))
    assert ws.accepted is True
    assert ws.closed_with is None


def test_ws_open_when_auth_disabled():
    ws = _FakeWS()
    run(security.require_ws_key(ws))
    assert ws.accepted is True


# ---------------------------------------------------------------------------
# wiring
# ---------------------------------------------------------------------------
def test_router_applies_key_dependency():
    """Every /api route inherits the gate; one missed route is an open door."""
    from fastapi import APIRouter

    import routes

    assert isinstance(routes.router, APIRouter)
    assert routes.router.dependencies, "router has no dependencies - the gate is detached"
    attached = [
        d for d in routes.router.dependencies
        if getattr(d, "dependency", None) is security.require_api_key
    ]
    assert attached, "require_api_key is not attached to the router"
