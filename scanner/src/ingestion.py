"""
ECDAT Scanner - Ingestion.
Accepts a Git URL, local path, zip archive, or container image reference and
normalises each into a directory we can scan plus a Syft SBOM.

Every scan gets an isolated workspace at /tmp/scan_<uuid> so concurrent scans
never touch each other's files.
"""

import re
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import git

from detection import run_syft
from utils import log

WORKSPACE_PREFIX = "ecdat-scan-"


class IngestionError(RuntimeError):
    """Raised when a target cannot be resolved to a scannable form."""


# ---------------------------------------------------------------------------
# Target classification
# ---------------------------------------------------------------------------
_IMAGE_RE = re.compile(
    r"""^
    (?:(?P<registry>[a-z0-9.\-]+(?::[0-9]+)?)/)?     # optional registry host
    (?P<name>[a-z0-9._\-/]+)                          # repository path
    (?::(?P<tag>[A-Za-z0-9._\-]+))?                   # optional tag
    (?:@(?P<digest>sha256:[a-f0-9]{64}))?             # optional digest
    $""",
    re.VERBOSE,
)


def is_existing_path(target: str) -> bool:
    return Path(target).expanduser().exists()


def is_git_url(target: str) -> bool:
    if target.startswith(("git@", "ssh://")):
        return True
    if re.match(r"^https?://.+\.git/?$", target):
        return True
    # Bare https URL we will try to clone; git will report if it is not a repo.
    return target.startswith(("http://", "https://", "git://"))


def is_zip(target: str) -> bool:
    return target.lower().endswith((".zip", ".jar", ".war", ".ear"))


def is_image_ref(target: str) -> bool:
    """Conservative: must not be an existing path, and must look like a ref."""
    if is_existing_path(target) or is_zip(target):
        return False
    if target.startswith(("/", "./", "../", "~")) or "://" in target:
        return False
    return bool(_IMAGE_RE.match(target))


def classify(target: str) -> str:
    if is_existing_path(target):
        return "path"
    if is_git_url(target):
        return "git"
    if is_zip(target):
        return "zip"
    if is_image_ref(target):
        return "image"
    raise IngestionError(
        f"cannot classify target {target!r}: expected a Git URL, "
        f"local path, zip archive, or container image reference"
    )


# ---------------------------------------------------------------------------
# Workspace
# ---------------------------------------------------------------------------
def make_workspace() -> Path:
    ws = Path(tempfile.gettempdir()) / f"{WORKSPACE_PREFIX}{uuid.uuid4().hex[:10]}"
    ws.mkdir(parents=True, exist_ok=False)
    return ws


def destroy_workspace(ws: Path) -> None:
    shutil.rmtree(ws, ignore_errors=True)


# ---------------------------------------------------------------------------
# Resolvers
# ---------------------------------------------------------------------------
def resolve_git(url: str, dest: Path, branch: Optional[str] = None, depth: int = 1) -> Path:
    log.info("cloning %s (branch=%s depth=%s)", url, branch or "default", depth)
    try:
        git.Repo.clone_from(url, dest, branch=branch, depth=depth)
    except git.GitCommandError as exc:
        # Shallow clone fails on some servers; retry unshallowed before giving up.
        log.warning("shallow clone failed (%s), retrying full clone", exc)
        try:
            git.Repo.clone_from(url, dest, branch=branch)
        except git.GitCommandError as exc2:
            raise IngestionError(f"git clone failed: {exc2}") from exc2
    return dest


def resolve_zip(archive: str, dest: Path) -> Path:
    src = Path(archive).expanduser()
    if not src.is_file():
        raise IngestionError(f"archive not found: {src}")
    log.info("extracting %s", src)
    with zipfile.ZipFile(src) as zf:
        # Refuse path traversal (zip-slip) from untrusted archives.
        for member in zf.namelist():
            target = (dest / member).resolve()
            if not str(target).startswith(str(dest.resolve())):
                raise IngestionError(f"unsafe path in archive: {member!r}")
        zf.extractall(dest)
    return dest


def resolve_path(local: str, dest: Path) -> Path:
    src = Path(local).expanduser().resolve()
    log.info("copying %s -> workspace", src)
    if src.is_dir():
        # ignore=shutil.ignore_patterns keeps the workspace small and avoids
        # recursing into build output and VCS metadata.
        shutil.copytree(
            src, dest, dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(
                ".git", ".svn", "node_modules", "__pycache__",
                "target", "build", "dist", ".venv", "*.pyc",
            ),
            symlinks=True,
        )
    else:
        shutil.copy2(src, dest / src.name)
    return dest


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def ingest(target: str, branch: Optional[str] = None) -> Tuple[str, Path, Optional[Path], Dict[str, Any]]:
    """
    Resolve `target` into something scannable.

    Returns:
        (kind, scan_root, source_path, sbom)
          kind       - "path" | "git" | "zip" | "image"
          scan_root  - directory to run Semgrep over (empty for "image")
          source_path- original material on disk, if any (None for "image")
          sbom       - Syft SBOM JSON dict
    """
    kind = classify(target)

    if kind == "image":
        # No filesystem to scan; the SBOM *is* the finding surface.
        log.info("scanning container image %s", target)
        return kind, Path(target), None, run_syft(f"docker:{target}")

    workspace = make_workspace()
    try:
        if kind == "git":
            root = resolve_git(target, workspace / "src", branch=branch)
            source = None
        elif kind == "zip":
            root = workspace / "src"
            root.mkdir(parents=True, exist_ok=True)
            root = resolve_zip(target, root)
            source = Path(target).expanduser().resolve()
        else:  # path
            root = workspace / "src"
            root.mkdir(parents=True, exist_ok=True)
            root = resolve_path(target, root)
            source = Path(target).expanduser().resolve()

        sbom = run_syft(str(root))
        log.info("workspace %s ready (%d sbom artifacts)", root, len(sbom.get("artifacts", []) or []))
        return kind, root, source, sbom
    except Exception:
        destroy_workspace(workspace)
        raise
