"""
Pydantic models for the ECDAT API.

These are the wire contract. `ScanRequest` is what the UI POSTs,
`ScanStatus` is what it polls or receives over the WebSocket.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class ScanState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanRequest(BaseModel):
    """POST /api/scan body."""
    target: str = Field(
        ...,
        description="Git URL, local path, zip archive, or container image reference",
        examples=["https://github.com/spring-projects/spring-petclinic"],
    )
    branch: Optional[str] = Field(None, description="Git branch, when target is a URL")
    z_estimate: float = Field(
        15.0, gt=0, le=100,
        description="Mosca collapse time Z in years. Drives the risk ranking.",
    )
    run_benchmarks: bool = Field(
        True, description="Run the liboqs before/after benchmark suite"
    )
    iterations: int = Field(100, ge=1, le=1000, description="Benchmark iterations")
    fast_bench: bool = Field(False, description="Use a reduced iteration count")

    @field_validator("target")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("target must not be empty")
        return v


class ProgressEvent(BaseModel):
    """One line of the stderr progress stream, surfaced over the WebSocket."""
    stage: str
    progress: int = Field(0, ge=0, le=100)
    scan_id: Optional[str] = None
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # stage-specific extras (artifacts, findings, cbom, kind, ...)
    detail: Dict[str, Any] = Field(default_factory=dict)


class ScanStatus(BaseModel):
    """GET /api/scan/{id}/status"""
    scan_id: str
    state: ScanState = ScanState.QUEUED
    progress: int = 0
    target: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    elapsed_seconds: Optional[float] = None
    finding_count: int = 0
    error: Optional[str] = None
    result_path: Optional[str] = None
    events: List[ProgressEvent] = Field(default_factory=list)


class FindingOut(BaseModel):
    """A single finding as the UI consumes it."""
    file: str
    line: int
    rule_id: str
    algorithm: str
    algorithm_family: str
    mode: str
    severity: str
    cwe: str
    cwe2: str
    snippet: str
    context: str
    source: str
    usage: str
    key_mgmt: str
    risk: str
    risk_score: float
    enrichment_source: str
    extra: Dict[str, Any] = Field(default_factory=dict)


class Recommendation(BaseModel):
    from_algorithm: str = Field(..., alias="from")
    migrate_to: List[str]
    rationale: str
    stdlib: Optional[str] = None
    occurrences: int = 1
    risk_score: float = 0.0
    source_finding: Dict[str, Any] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class CBOMResponse(BaseModel):
    """GET /api/cbom/{id} - the raw CycloneDX document plus a convenience rollup."""
    scan_id: str
    spec_version: str = "1.6"
    bom: Dict[str, Any]
    summary: Dict[str, Any] = Field(default_factory=dict)
    findings: List[FindingOut] = Field(default_factory=list)


class RiskResponse(BaseModel):
    """GET /api/risk/{id}"""
    scan_id: str
    z_estimate: float
    summary: Dict[str, Any] = Field(default_factory=dict)
    ranked: List[FindingOut] = Field(default_factory=list)


class BenchmarkResponse(BaseModel):
    """GET /api/benchmark/{id}"""
    scan_id: str
    rows: List[Dict[str, Any]] = Field(default_factory=list)
    comparisons: List[Dict[str, Any]] = Field(default_factory=list)
    liboqs_available: bool = False
    liboqs_version: Optional[str] = None


class HealthResponse(BaseModel):
    status: str
    version: str
    semgrep: Dict[str, Any] = Field(default_factory=dict)
    syft: Dict[str, Any] = Field(default_factory=dict)
    oqs: Dict[str, Any] = Field(default_factory=dict)
    rules: Dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
