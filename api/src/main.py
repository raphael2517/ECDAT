"""
ECDAT API - FastAPI application.

CORS is intentionally NOT enabled. The service is bound to localhost (or an
internal Docker network) and the UI is served by nginx from the same origin,
so there is no cross-origin case to permit.
"""

import asyncio
import json
import os
import shutil
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict

# Sibling modules are imported by bare name, so this directory must be
# importable however uvicorn was pointed at us.
_SRC = str(Path(__file__).resolve().parent)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from models import HealthResponse
from routes import router
from security import startup_notice
from worker import manager

APP_VERSION = "1.0.0"
UI_DIR = Path(os.getenv("UI_DIR", "/var/www/html"))
RULES_DIR = Path(os.getenv("SCANNER_RULES_PATH", "/app/scanner/rules"))


def _run(cmd: list) -> Dict[str, Any]:
    """Run a --version style probe without letting it break startup."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {
            "ok": p.returncode == 0,
            "version": (p.stdout or p.stderr).strip().splitlines()[0] if (p.stdout or p.stderr) else None,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _health_payload() -> Dict[str, Any]:
    semgrep_bin = os.getenv("SEMGREP_BIN", "semgrep")
    syft_bin = os.getenv("SYFT_BIN", "/usr/local/bin/syft")

    oqs: Dict[str, Any]
    try:
        import oqs
        oqs = {
            "ok": True,
            "version": oqs.oqs_version(),
            "kem": list(oqs.get_enabled_kem_mechanisms()),
            "sig": list(oqs.get_enabled_sig_mechanisms()),
        }
    except BaseException as exc:
        # BaseException, not Exception: when liboqs.so cannot be found,
        # liboqs-python's loader shells out to build it and then calls
        # sys.exit(1) - a SystemExit, which derives from BaseException and
        # would sail straight past `except Exception`. A missing native lib
        # must degrade the health report, not 500 the whole endpoint.
        oqs = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    rules = list(RULES_DIR.glob("*.y*ml")) if RULES_DIR.exists() else []

    return {
        "status": "ok",
        "version": APP_VERSION,
        "semgrep": _run([semgrep_bin, "--version"]),
        "syft": _run([syft_bin, "version"]),
        "oqs": oqs,
        "rules": {"ok": bool(rules), "path": str(RULES_DIR), "files": [r.name for r in rules]},
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    manager.output_dir.mkdir(parents=True, exist_ok=True)
    print(f"[api] output dir: {manager.output_dir}")
    print(f"[api] rules dir : {RULES_DIR}")
    print(f"[api] scan root : {os.getenv('ECDAT_SCAN_ROOT') or '(unset - any local path is scannable)'}")
    print(f"[api] max scans : {manager.max_concurrent()} concurrent")
    # Say out loud, at startup, whether /api is open. A deployment that forgot
    # to set ECDAT_API_KEY should be obvious in the logs rather than something
    # you discover from an access log.
    startup_notice()
    yield


app = FastAPI(
    title="ECDAT",
    version=APP_VERSION,
    description="Enterprise Cryptographic Discovery & Analysis Tool",
    lifespan=lifespan,
)

app.include_router(router)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(**await _health_payload())


@app.get("/api/health")
async def health_alias() -> Dict[str, Any]:
    return await _health_payload()


# --- static UI (optional; API works standalone) -----------------------------
if UI_DIR.exists() and (UI_DIR / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(UI_DIR), html=True), name="ui")
else:
    @app.get("/", response_class=PlainTextResponse)
    async def root() -> str:
        return (
            "ECDAT API is running.\n"
            "The UI bundle is not present in this image.\n\n"
            "Try:\n"
            "  POST /api/scan   {\"target\": \"https://github.com/org/repo\"}\n"
            "  GET  /api/scan\n"
            "  GET  /health\n"
            "  WS   /api/scan/{id}/ws\n"
        )
