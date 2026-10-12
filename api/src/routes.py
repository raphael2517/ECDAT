"""
HTTP + WebSocket routes.
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from models import (
    BenchmarkResponse,
    CBOMResponse,
    FindingOut,
    HealthResponse,
    Recommendation,
    RiskResponse,
    ScanRequest,
    ScanStatus,
)
from worker import ScanJob, manager

router = APIRouter()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _job_or_404(scan_id: str) -> ScanJob:
    job = manager.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"unknown scan id {scan_id}")
    return job


def _load_report(scan_id: str) -> Dict[str, Any]:
    path = manager.output_dir / scan_id / "report.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"no report for {scan_id}")
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# scan lifecycle
# ---------------------------------------------------------------------------
@router.post("/api/scan", response_model=ScanStatus, status_code=202)
async def start_scan(req: ScanRequest) -> ScanStatus:
    job = await manager.launch(req.model_dump())
    return job.status


@router.get("/api/scan", response_model=List[ScanStatus])
async def list_scans() -> List[ScanStatus]:
    return manager.list()


@router.get("/api/scan/{scan_id}/status", response_model=ScanStatus)
async def scan_status(scan_id: str) -> ScanStatus:
    return _job_or_404(scan_id).status


@router.delete("/api/scan/{scan_id}", response_model=ScanStatus)
async def cancel_scan(scan_id: str) -> ScanStatus:
    job = _job_or_404(scan_id)
    await manager.cancel(job)
    return job.status


@router.websocket("/api/scan/{scan_id}/ws")
async def scan_ws(websocket: WebSocket, scan_id: str) -> None:
    await websocket.accept()
    job = manager.get(scan_id)
    if not job:
        await websocket.send_json({"stage": "error", "progress": 100,
                                  "message": f"unknown scan id {scan_id}"})
        await websocket.close(code=4404)
        return

    queue = manager.subscribe(job)
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=20.0)
            except asyncio.TimeoutError:
                # keepalive; also a chance to notice a finished job
                if job.status.state.value in ("done", "failed", "cancelled"):
                    await websocket.send_json({
                        "stage": job.status.state.value,
                        "progress": 100,
                        "message": job.status.error or "",
                    })
                    break
                await websocket.send_json({"stage": "ping", "progress": job.status.progress})
                continue

            await websocket.send_json(event)
            if event.get("stage") in ("done", "error", "cancelled"):
                break
    except WebSocketDisconnect:
        pass
    finally:
        manager.unsubscribe(job, queue)


# ---------------------------------------------------------------------------
# results
# ---------------------------------------------------------------------------
@router.get("/api/cbom/{scan_id}", response_model=CBOMResponse)
async def get_cbom(scan_id: str) -> CBOMResponse:
    report = _load_report(scan_id)
    bom_path = manager.output_dir / scan_id / "cbom.json"
    if not bom_path.exists():
        raise HTTPException(status_code=404, detail=f"no CBOM for {scan_id}")
    return CBOMResponse(
        scan_id=scan_id,
        spec_version=report.get("spec_version", "1.6"),
        bom=json.loads(bom_path.read_text(encoding="utf-8")),
        summary=report.get("summary", {}),
        findings=[FindingOut(**f) for f in report.get("findings", [])],
    )


@router.get("/api/risk/{scan_id}", response_model=RiskResponse)
async def get_risk(scan_id: str) -> RiskResponse:
    report = _load_report(scan_id)
    return RiskResponse(
        scan_id=scan_id,
        z_estimate=report.get("z_estimate", 15.0),
        summary=report.get("summary", {}),
        ranked=[FindingOut(**f) for f in report.get("findings", [])],
    )


@router.post("/api/risk/recalculate/{scan_id}", response_model=RiskResponse)
async def recalculate_risk(scan_id: str, z: float) -> RiskResponse:
    """
    Re-rank at a different Mosca collapse time. Runs the scanner's `rerisk`
    subcommand against the stored findings rather than reimplementing the
    scoring in the API, so there is exactly one implementation of the maths.
    """
    if z <= 0 or z > 100:
        raise HTTPException(status_code=400, detail="z must be in (0, 100]")

    _load_report(scan_id)  # 404 if the scan never produced a report

    out_path = manager.output_dir / scan_id / f"rerisk_z{z:g}.json"
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "scanner", "rerisk",
        str(manager.output_dir / scan_id / "report.json"),
        "--z-estimate", str(z),
        "--output", str(out_path),
        cwd="/app",
        env={**os.environ,
             "PYTHONPATH": "/app/scanner:/app",
             "PYTHONUNBUFFERED": "1"},
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, err = await proc.communicate()
    if proc.returncode != 0 or not out_path.exists():
        raise HTTPException(status_code=500,
                            detail=f"rerisk failed: {err.decode('utf-8', 'replace')[:400]}")

    data = json.loads(out_path.read_text(encoding="utf-8"))
    return RiskResponse(
        scan_id=scan_id,
        z_estimate=z,
        summary=data.get("summary", {}),
        ranked=[FindingOut(**f) for f in data.get("findings", [])],
    )


@router.get("/api/benchmark/{scan_id}", response_model=BenchmarkResponse)
async def get_benchmark(scan_id: str) -> BenchmarkResponse:
    report = _load_report(scan_id)
    oqs_version = None
    available = False
    try:
        import oqs
        oqs_version = oqs.oqs_version()
        available = True
    except Exception:
        pass
    return BenchmarkResponse(
        scan_id=scan_id,
        rows=report.get("benchmarks", []),
        comparisons=report.get("benchmark_comparisons", []),
        liboqs_available=available,
        liboqs_version=oqs_version,
    )


@router.get("/api/recommendations/{scan_id}", response_model=List[Recommendation])
async def get_recommendations(scan_id: str) -> List[Recommendation]:
    report = _load_report(scan_id)
    return [Recommendation(**r) for r in report.get("recommendations", [])]


@router.get("/api/report/{scan_id}")
async def get_report(scan_id: str) -> Dict[str, Any]:
    return _load_report(scan_id)
