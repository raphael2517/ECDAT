"""
Scan job store + subprocess worker.

One scan = one `python -m scanner scan` subprocess. stdout carries the result
handle, stderr carries newline-delimited progress events which we fan out to
any WebSocket listening on that scan id.

In-process store (dict + asyncio locks) rather than Redis: single container,
single-user tool, and it keeps the image free of another service.
"""

import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from models import ProgressEvent, ScanState, ScanStatus

OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/app/output"))
SCANNER_PKG = "/app/scanner"

# Resolved once at import so /health can report it.
PYTHON = os.getenv("PYTHON_BIN", sys.executable)


class ScanJob:
    def __init__(self, scan_id: str, request: Dict[str, Any]):
        self.scan_id = scan_id
        self.request = request
        self.status = ScanStatus(scan_id=scan_id, target=request.get("target"))
        self.events: List[ProgressEvent] = []
        self.listeners: Set[asyncio.Queue] = set()
        self.lock = asyncio.Lock()
        self.process: Optional[asyncio.subprocess.Process] = None
        self.started_monotonic: Optional[float] = None

    def to_status(self) -> ScanStatus:
        return self.status


class ScanManager:
    """Owns every job in this process."""

    def __init__(self, output_dir: Path = OUTPUT_DIR):
        self.jobs: Dict[str, ScanJob] = {}
        self.output_dir = output_dir
        self._counter = 0

    def next_id(self) -> str:
        self._counter += 1
        return f"{int(time.time() * 1000) % 10_000_000:07d}-{self._counter:04d}"

    def get(self, scan_id: str) -> Optional[ScanJob]:
        return self.jobs.get(scan_id)

    def list(self) -> List[ScanStatus]:
        return [j.status for j in sorted(self.jobs.values(), key=lambda j: j.scan_id, reverse=True)]

    # -- progress plumbing -------------------------------------------------
    def subscribe(self, job: ScanJob) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        job.listeners.add(q)
        # Replay what already happened so a late subscriber isn't blind.
        for ev in job.events:
            q.put_nowait(ev.model_dump(mode="json"))
        return q

    def unsubscribe(self, job: ScanJob, q: asyncio.Queue) -> None:
        job.listeners.discard(q)

    async def _emit(self, job: ScanJob, event: ProgressEvent) -> None:
        job.events.append(event)
        job.status.progress = max(job.status.progress, event.progress)
        if event.stage == "error":
            job.status.state = ScanState.FAILED
            job.status.error = event.message
        for q in list(job.listeners):
            try:
                q.put_nowait(event.model_dump(mode="json"))
            except asyncio.QueueFull:
                pass

    # -- execution ---------------------------------------------------------
    def running_count(self) -> int:
        return sum(1 for j in self.jobs.values() if j.status.state == ScanState.RUNNING)

    def max_concurrent(self) -> int:
        try:
            n = int(os.getenv("ECDAT_MAX_CONCURRENT_SCANS", "2"))
        except ValueError:
            n = 2
        return max(1, n)

    async def launch(self, request: Dict[str, Any]) -> ScanJob:
        scan_id = self.next_id()
        job = ScanJob(scan_id, request)
        self.jobs[scan_id] = job
        job.status.state = ScanState.RUNNING
        job.status.started_at = datetime.now(timezone.utc)
        asyncio.create_task(self._run(job))
        return job

    def _build_argv(self, job: ScanJob) -> List[str]:
        req = job.request
        out_dir = self.output_dir / job.scan_id
        argv = [
            PYTHON, "-m", "scanner", "scan", req["target"],
            "--output", str(out_dir / "cbom.json"),
            "--report", str(out_dir / "report.json"),
            "--z-estimate", str(req.get("z_estimate", 15.0)),
            "--iterations", str(req.get("iterations", 100)),
        ]
        if req.get("branch"):
            argv += ["--branch", req["branch"]]
        if not req.get("run_benchmarks", True):
            argv.append("--no-bench")
        if req.get("fast_bench"):
            argv.append("--fast-bench")
        return argv

    async def _run(self, job: ScanJob) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = f"{SCANNER_PKG}:/app"
        env["PYTHONUNBUFFERED"] = "1"

        argv = self._build_argv(job)
        started = time.monotonic()
        job.started_monotonic = started

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd="/app",
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            job.process = proc

            # Drain stderr as progress events concurrently with stdout.
            async def pump_stderr() -> None:
                assert proc.stderr is not None
                async for raw in proc.stderr:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    if not line.startswith("{"):
                        # plain log line - surface as a free-form event
                        await self._emit(job, ProgressEvent(
                            stage="log", progress=job.status.progress,
                            scan_id=job.scan_id, message=line[:500],
                        ))
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    stage = data.pop("stage", "log")
                    progress = int(data.pop("progress", job.status.progress) or 0)
                    message = data.pop("message", None)
                    # The scanner mints its own scan_id. Ours is the job id the
                    # caller holds, so drop theirs to avoid two ids meaning
                    # different things inside one payload.
                    data.pop("scan_id", None)
                    if stage == "done" and data.get("findings") is not None:
                        job.status.finding_count = int(data["findings"])
                    await self._emit(job, ProgressEvent(
                        stage=stage, progress=progress, scan_id=job.scan_id,
                        message=message, detail=data,
                    ))

            stdout_chunks: List[bytes] = []

            async def pump_stdout() -> None:
                assert proc.stdout is not None
                async for raw in proc.stdout:
                    stdout_chunks.append(raw)

            _, _ = await asyncio.gather(pump_stderr(), pump_stdout())
            rc = await proc.wait()

            elapsed = round(time.monotonic() - started, 2)
            job.status.elapsed_seconds = elapsed
            job.status.finished_at = datetime.now(timezone.utc)

            if rc == 0:
                out_dir = self.output_dir / job.scan_id
                job.status.state = ScanState.DONE
                job.status.result_path = str(out_dir / "report.json")
                try:
                    summary = json.loads((out_dir / "report.json").read_text())
                    job.status.finding_count = summary.get("summary", {}).get("total", 0)
                except Exception:
                    pass
                await self._emit(job, ProgressEvent(
                    stage="done", progress=100, scan_id=job.scan_id,
                    message=f"scan complete in {elapsed}s",
                    detail={"findings": job.status.finding_count,
                            "result_path": job.status.result_path},
                ))
            else:
                job.status.state = ScanState.FAILED
                if not job.status.error:
                    job.status.error = f"scanner exited with code {rc}"
                await self._emit(job, ProgressEvent(
                    stage="error", progress=100, scan_id=job.scan_id,
                    message=job.status.error,
                ))

        except Exception as exc:  # noqa: BLE001
            job.status.state = ScanState.FAILED
            job.status.error = str(exc)
            job.status.finished_at = datetime.now(timezone.utc)
            await self._emit(job, ProgressEvent(
                stage="error", progress=100, scan_id=job.scan_id, message=str(exc),
            ))

    async def cancel(self, job: ScanJob) -> bool:
        if job.process and job.process.returncode is None:
            job.process.terminate()
            job.status.state = ScanState.CANCELLED
            await self._emit(job, ProgressEvent(
                stage="cancelled", progress=job.status.progress, scan_id=job.scan_id,
            ))
            return True
        return False


manager = ScanManager()
