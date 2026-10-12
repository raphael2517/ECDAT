"""
ECDAT Scanner - Detection Engine.
Runs Semgrep over the ingested source tree and parses the Syft SBOM, then
normalises both into a single Finding shape.

Semgrep comes from PyPI (see requirements.txt for why there is no ./bin/semgrep).
Syft is the static binary at ./bin/syft.
"""

import json
import os
import subprocess
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils import log, truncate

SEMGREP_BIN = os.getenv("SEMGREP_BIN", "semgrep")
SYFT_BIN = os.getenv("SYFT_BIN", str(Path(__file__).resolve().parents[2] / "bin" / "syft"))

SEMGREP_TIMEOUT = int(os.getenv("SEMGREP_TIMEOUT", "900"))
SYFT_TIMEOUT = int(os.getenv("SYFT_TIMEOUT", "600"))


# ---------------------------------------------------------------------------
# Crypto libraries recognised in an SBOM.
#
# Keys are matched against the artifact name with word-boundary awareness so we
# do not get false positives (e.g. "ring" must not match "spring-boot-devtools").
# ---------------------------------------------------------------------------
CRYPTO_LIBRARIES: Dict[str, Dict[str, str]] = {
    # Python
    "bcrypt": {"algorithm": "BCRYPT", "type": "kdf", "family": "KDF"},
    "cryptography": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    "pycryptodome": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    "pycrypto": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    "pynacl": {"algorithm": "UNKNOWN", "type": "library", "family": "ECC"},
    "libsodium": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    # Java
    "bcprov": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    "bcpkix": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    "bouncycastle": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    "nimbus-jose-jwt": {"algorithm": "JWT", "type": "library", "family": "JWT"},
    "jjwt": {"algorithm": "JWT", "type": "library", "family": "JWT"},
    "auth0-java-jwt": {"algorithm": "JWT", "type": "library", "family": "JWT"},
    # Go
    "golang.org/x/crypto": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    # Node
    "jsonwebtoken": {"algorithm": "JWT", "type": "library", "family": "JWT"},
    "node-forge": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    "elliptic": {"algorithm": "UNKNOWN", "type": "library", "family": "ECC"},
    "bn.js": {"algorithm": "UNKNOWN", "type": "library", "family": "ECC"},
    # Native / TLS
    "openssl": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    "libressl": {"algorithm": "TLS", "type": "library", "family": "TLS"},
    "boringssl": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    "gnutls": {"algorithm": "TLS", "type": "library", "family": "TLS"},
    "mbedtls": {"algorithm": "TLS", "type": "library", "family": "TLS"},
    "wolfssl": {"algorithm": "TLS", "type": "library", "family": "TLS"},
    # .NET
    "system.security.cryptography": {"algorithm": "UNKNOWN", "type": "stdlib", "family": "MULTI"},
    # Rust
    "ring": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
    "rustls": {"algorithm": "TLS", "type": "library", "family": "TLS"},
    # PHP
    "phpseclib": {"algorithm": "UNKNOWN", "type": "library", "family": "MULTI"},
}


@dataclass
class Finding:
    """Normalised finding from Semgrep or Syft."""
    # --- location ---
    file: str
    line: int
    # --- classification ---
    rule_id: str
    algorithm: str          # as reported by static analysis
    algorithm_family: str   # SYM | ASYM | HASH | TLS | JWT | KDF | MULTI | UNKNOWN
    mode: str               # ECB, CBC, GCM, SIGNING, PUBLIC_KEY, LIBRARY, ...
    severity: str           # CRITICAL | ERROR | WARNING | INFO
    cwe: str
    cwe2: str
    # --- payload ---
    snippet: str
    context: str
    # --- provenance ---
    source: str             # "semgrep" | "syft"
    # --- heuristic enrichment (filled in by enrichment.py) ---
    usage: str = "unknown"
    key_mgmt: str = "unknown"
    risk: str = "info"
    risk_score: float = 0.0
    enrichment_source: str = ""
    # --- free-form ---
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Context extraction
# ---------------------------------------------------------------------------
def read_source(file_path: str) -> List[str]:
    """Read a file into lines, tolerating encoding and races (temp workspace)."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except OSError:
        return []


def get_file_context(file_path: str, line: int, context_lines: int = 5) -> str:
    """Return +/- context_lines around `line`, marking the hit with '>>>'."""
    lines = read_source(file_path)
    if not lines:
        return f"[unavailable: {file_path}:{line}]"

    idx = max(0, line - 1)
    start = max(0, idx - context_lines)
    end = min(len(lines), idx + context_lines + 1)

    out = []
    for i in range(start, end):
        marker = ">>>" if i == idx else "   "
        out.append(f"{marker} {i + 1:5d}| {lines[i].rstrip()}")
    return truncate("\n".join(out), 4000)


def get_snippet(file_path: str, start_line: int, end_line: int) -> str:
    """
    Extract the matched source lines.

    Semgrep 1.178 no longer populates `extra.lines` with source text - the
    field carries a login-gated placeholder string instead - so the snippet is
    read back off disk. That also keeps snippet and context consistent, since
    both come from the same read.
    """
    lines = read_source(file_path)
    if not lines:
        return ""
    lo = max(0, start_line - 1)
    hi = min(len(lines), max(start_line, end_line))
    return truncate("\n".join(l.rstrip() for l in lines[lo:hi]).strip(), 2000)


# ---------------------------------------------------------------------------
# Algorithm family inference
# ---------------------------------------------------------------------------
_SYMMETRIC = ("aes", "des", "3des", "desede", "rc2", "rc4", "rc5", "chacha", "camellia", "sm4", "blowfish")
_ASYMMETRIC = ("rsa", "ecdsa", "ecdh", "dsa", "ed25519", "ed448", "curve25519", "curve448", "elgamal", "dh")
_HASH = ("sha", "md5", "md4", "md2", "sha3", "blake", "whirlpool", "ripemd", "sm3", "shake")
_TLS = ("tls", "ssl")
_KDF = ("bcrypt", "scrypt", "pbkdf2", "argon2", "hkdf", "kdf")
_JWT = ("jwt", "jose", "jws", "jwe", "hs256", "rs256", "es256", "ps256")


def infer_family(algorithm: str, hint: str = "") -> str:
    """Best-effort map an algorithm string onto a coarse family."""
    blob = f"{algorithm} {hint}".lower()
    for needles, fam in (
        (_KDF, "KDF"), (_JWT, "JWT"), (_TLS, "TLS"),
        (_ASYMMETRIC, "ASYM"), (_HASH, "HASH"), (_SYMMETRIC, "SYM"),
    ):
        if any(n in blob for n in needles):
            return fam
    return "MULTI" if algorithm and algorithm not in ("UNKNOWN", "...") else "UNKNOWN"


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------
def run_semgrep_scan(scan_path: Path, rules_path: Path, extra_args: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Invoke `semgrep scan --config <rules> --json` and return the raw results list."""
    cmd = [
        SEMGREP_BIN, "scan",
        "--config", str(rules_path),
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--timeout", "60",
        "--max-target-bytes", "2000000",
    ]
    if extra_args:
        cmd += extra_args
    cmd.append(str(scan_path))

    log.info("semgrep: %s", " ".join(cmd))
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SEMGREP_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.error("semgrep timed out after %ss", SEMGREP_TIMEOUT)
        return []
    except FileNotFoundError:
        log.error("semgrep binary not found at %r - is it installed in the image?", SEMGREP_BIN)
        return []

    log.info("semgrep finished in %.1fs (rc=%d)", time.time() - started, proc.returncode)

    # semgrep prints its JSON to stdout; non-zero rc just means findings exist
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        log.error("semgrep produced unparseable output: %s", proc.stdout[:500])
        return []

    for err in payload.get("errors", [])[:10]:
        log.warning("semgrep rule error: %s", err.get("message", err)[:200])

    return payload.get("results", [])


def parse_semgrep_results(results: List[Dict[str, Any]], scan_root: Path) -> List[Finding]:
    """Map raw semgrep results onto Finding objects."""
    findings: List[Finding] = []

    for res in results:
        path = res.get("path", "")
        start = res.get("start", {}) or {}
        end = res.get("end", {}) or {}
        start_line = int(start.get("line", 0) or 0)
        end_line = int(end.get("line", start_line) or start_line)
        extra = res.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}

        try:
            rel = str(Path(path).resolve().relative_to(Path(scan_root).resolve()))
        except (ValueError, OSError):
            rel = path

        algorithm = str(meta.get("algorithm") or "UNKNOWN")
        mode = str(meta.get("mode") or "UNKNOWN")
        hint = str(meta.get("family") or "")

        findings.append(Finding(
            file=rel,
            line=start_line,
            rule_id=str(res.get("check_id", "unknown")),
            algorithm=algorithm,
            algorithm_family=infer_family(algorithm, hint),
            mode=mode,
            severity=str(meta.get("severity", "INFO")).upper(),
            cwe=str(meta.get("cwe", "")),
            cwe2=str(meta.get("cwe2", "")),
            snippet=get_snippet(path, start_line, end_line),
            context=get_file_context(path, start_line),
            source="semgrep",
            extra={"end_line": end_line, "message": extra.get("message", "")},
        ))

    return findings


# ---------------------------------------------------------------------------
# Syft
# ---------------------------------------------------------------------------
def run_syft(source: str) -> Dict[str, Any]:
    """Run syft against a directory, archive, or image reference."""
    target = source if ":" in source or source.startswith("dir:") else f"dir:{source}"
    cmd = [SYFT_BIN, "packages", target, "-o", "json", "-q"]
    log.info("syft: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=SYFT_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.error("syft timed out after %ss", SYFT_TIMEOUT)
        return {"artifacts": []}
    except FileNotFoundError:
        log.error("syft binary not found at %r", SYFT_BIN)
        return {"artifacts": []}

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        log.error("syft produced unparseable output: %s", proc.stderr[:300])
        return {"artifacts": []}


def _match_crypto_library(name: str) -> Optional[tuple]:
    """Match an SBOM artifact name against CRYPTO_LIBRARIES on word boundaries."""
    import re
    lowered = name.lower()
    for lib, info in CRYPTO_LIBRARIES.items():
        needle = lib.lower()
        if lowered == needle:
            return lib, info
        # jjwt-api, bcprov-jdk18on, golang.org/x/crypto/... etc.
        if re.search(rf"(^|[-_./]){re.escape(needle)}($|[-_./])", lowered):
            return lib, info
    return None


def parse_syft_sbom(sbom: Dict[str, Any]) -> List[Finding]:
    """Extract crypto library components from a Syft SBOM as Findings."""
    findings: List[Finding] = []

    for art in sbom.get("artifacts", []) or []:
        name = str(art.get("name", ""))
        if not name:
            continue
        matched = _match_crypto_library(name)
        if not matched:
            continue
        lib_key, info = matched

        version = str(art.get("version", "") or "UNKNOWN")
        locations = art.get("locations", []) or []
        loc_path = str(locations[0].get("path", "")) if locations else ""

        findings.append(Finding(
            file=loc_path or "(sbom)",
            line=1,
            rule_id=f"syft-crypto-lib-{lib_key}",
            algorithm=str(art.get("version", "") or info["algorithm"]),
            algorithm_family=info["family"],
            mode="LIBRARY",
            severity="INFO",
            cwe="CWE-327",
            cwe2="CWE-326",
            snippet=f"{name}@{version}",
            context=f"Crypto library in SBOM: {name} {version} (type={info['type']})",
            source="syft",
            usage="library",
            extra={"library": name, "version": version, "package_type": art.get("type", "")},
        ))

    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def dedupe(findings: List[Finding]) -> List[Finding]:
    """Drop duplicates on (source, rule_id, file, line)."""
    seen = set()
    out = []
    for f in findings:
        key = (f.source, f.rule_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def detect(scan_root: Path, sbom: Dict[str, Any], rules_path: Path) -> List[Finding]:
    """Run Semgrep + Syft parsing and return normalised, deduped findings."""
    semgrep_results = run_semgrep_scan(scan_root, rules_path)
    findings = parse_semgrep_results(semgrep_results, scan_root)
    log.info("semgrep produced %d finding(s)", len(findings))

    findings += parse_syft_sbom(sbom)
    findings = dedupe(findings)
    log.info("total findings after dedupe: %d", len(findings))
    return findings
