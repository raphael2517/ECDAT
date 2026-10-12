"""
ECDAT Scanner - Shared utilities.
Logging, config, and file IO.
"""

import json
import logging
import os
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

# Project root: <root>/scanner/src/utils.py -> <root>
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure root logger once, to stderr."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
        force=True,
    )
    return logging.getLogger("ecdat")


log = setup_logging(os.getenv("ECDAT_VERBOSE") == "1")


def get_config() -> Dict[str, Any]:
    """Load configuration from environment, with sane defaults."""
    return {
        "output_dir": Path(os.getenv("OUTPUT_DIR", str(PROJECT_ROOT / "output"))),
        "rules_path": Path(os.getenv("SCANNER_RULES_PATH", str(PROJECT_ROOT / "scanner" / "rules"))),
        "oqs_install_path": os.getenv("OQS_INSTALL_PATH", "/opt/oqs"),
        "z_estimate": float(os.getenv("Z_ESTIMATE", "15")),
    }


def emit_progress(stage: str, progress: int, **extra: Any) -> None:
    """
    Emit a single JSON line to stderr for the API layer to consume as a
    progress stream. stdout is reserved for the scan result only.
    """
    payload = {"stage": stage, "progress": progress}
    payload.update(extra)
    sys.stderr.write(json.dumps(payload) + "\n")
    sys.stderr.flush()


def new_scan_id() -> str:
    """Short, sortable-ish unique id for a scan job."""
    return uuid.uuid4().hex[:12]


def read_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, data: Any, indent: int = 2) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, default=str)
    return path


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def truncate(text: str, limit: int = 4000) -> str:
    """Bound a string so a pathological snippet can't blow up a prompt or a CBOM."""
    text = text or ""
    return text if len(text) <= limit else text[:limit] + f"... [truncated {len(text) - limit} chars]"
