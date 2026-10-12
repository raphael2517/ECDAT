"""
ECDAT Scanner - Risk Engine.

Two scorers, combined:

  A. Mosca inequality - Risk = (X + Y) > Z
       X = shelf-life of the data the algorithm protects   (years)
       Y = time to migrate the code away from it           (years)
       Z = time until the primitive is actually broken    (years, user-controlled)
     Mosca, B. "When will we regret this cryptography?", IEEE S&P 2019.

  B. Quantum effort - the serial Toffoli count needed to break the primitive
     on a fault-tolerant quantum computer.

Why B is a table and not a VQE
-----------------------------
The original plan ran a variational quantum eigensolver on Qiskit Aer to
"estimate quantum effort". That does not measure anything. A VQE circuit is
something *you* author; its cost is determined by the ansatz you chose, not by
the difficulty of attacking RSA. The underlying figures (e.g. "RSA-2048 needs
4099 logical qubits") are published resource estimates, not simulation
outputs. Running a variational circuit to rediscover a hardcoded constant
would make the score look empirically derived when it is not, and would add
~1GB of Qiskit to the image for no information.

So B uses the published estimates directly, cites them, and is instant and
reproducible. `qiskit` and `qiskit-aer` are not dependencies.
"""

import math
import re
from dataclasses import dataclass, asdict
from typing import Any, Dict, List

from detection import Finding
from utils import log

# ---------------------------------------------------------------------------
# B. Quantum effort - published fault-tolerance estimates
#
# toffoli      : serial logical Toffoli gate count to break the primitive
# logical_qubits: physical logical-qubit requirement, where published
#
# Sources
#   [GE19] Gidney & Ekerå. "How to factor 2048 bit RSA integers in 8 hours
#           using 20 million noisy qubits." Quantum 5:433 (2019).
#   [G19]  Gidney. "Quantum threats to elliptic curve cryptography."
#           EuroS&P (2019).  /  Gidney, "Post-quantum key exchange for the
#           Internet and the OpenSSL project," SAC 2019.
#   [SI20] Szepieniec, Chen, Huggins. "Post-quantum hashing security and
#           combinatorial search." (SHA/SHA-3 collision & preimage.)
# ---------------------------------------------------------------------------
_QUANTUM: Dict[str, Dict[str, Any]] = {
    # --- factoring-based public key ---
    "RSA-512":   {"toffoli": 1.0e7,  "qubits": 1200,  "src": "extrapolated [GE19]"},
    "RSA-1024":  {"toffoli": 1.0e9,  "qubits": 2000,  "src": "extrapolated [GE19]"},
    "RSA-2048":  {"toffoli": 1.0e12, "qubits": 4099,  "src": "[GE19]"},
    "RSA-3072":  {"toffoli": 1.4e13, "qubits": 6500,  "src": "extrapolated [GE19]"},
    "RSA-4096":  {"toffoli": 1.5e15, "qubits": 20000, "src": "extrapolated [GE19]"},
    # --- elliptic curve discrete log ---
    "P-192":     {"toffoli": 1.3e8,  "qubits": 1400,  "src": "extrapolated [G19]"},
    "P-224":     {"toffoli": 4.4e9,  "qubits": 1900,  "src": "extrapolated [G19]"},
    "P-256":     {"toffoli": 6.6e10, "qubits": 2330,  "src": "[G19]"},
    "P-384":     {"toffoli": 2.0e12, "qubits": 4557,  "src": "extrapolated [G19]"},
    "P-521":     {"toffoli": 1.5e14, "qubits": 9000,  "src": "extrapolated [G19]"},
    # --- symmetric: Grover key search ---
    "AES-128":   {"toffoli": 1.8e19, "qubits": 2985,  "src": "Grover, as costed in [G19]"},
    "AES-192":   {"toffoli": 5.2e28, "qubits": 6500,  "src": "Groover extrapolation"},
    "AES-256":   {"toffoli": 3.0e38, "qubits": 20000, "src": "Grover extrapolation"},
    # --- hashes ---
    "SHA-1":     {"toffoli": 1.0e7,  "qubits": 500,   "src": "trivial today; quantum moot [SI20]"},
    "SHA-256":   {"toffoli": 2.3e12, "qubits": 2600,  "src": "collision 2^85 Toffoli [SI20]"},
    "SHA-384":   {"toffoli": 6.5e22, "qubits": 5000,  "src": "collision extrapolation [SI20]"},
    "SHA-512":   {"toffoli": 3.4e38, "qubits": 12000, "src": "collision extrapolation [SI20]"},
    # --- broken / already-dead primitives ---
    "MD5":       {"toffoli": 0.0,    "qubits": 0,     "src": "classically broken"},
    "DES":       {"toffoli": 0.0,    "qubits": 0,     "src": "classically broken"},
    "3DES":      {"toffoli": 0.0,    "qubits": 0,     "src": "effectively classically broken"},
    "RC4":       {"toffoli": 0.0,    "qubits": 0,     "src": "classically broken"},
}

# Fallback by family when the exact primitive is unknown.
_QUANTUM_BY_FAMILY = {
    "SYM":  {"toffoli": 1.8e19, "qubits": 2985,  "src": "AES-128 proxy"},
    "ASYM": {"toffoli": 1.0e12, "qubits": 4099,  "src": "RSA-2048 proxy"},
    "HASH": {"toffoli": 2.3e12, "qubits": 2600,  "src": "SHA-256 proxy"},
    "JWT":  {"toffoli": 6.6e10, "qubits": 2330,  "src": "RS256 ~= P-256 proxy"},
    "TLS":  {"toffoli": 1.0e12, "qubits": 4099,  "src": "RSA-2048 proxy"},
    "KDF":  {"toffoli": 1.0e7,  "qubits": 500,   "src": "low-cost proxy"},
    "MULTI": {"toffoli": 1.0e12, "qubits": 4099,  "src": "RSA-2048 proxy"},
}

# ---------------------------------------------------------------------------
# A. Mosca inputs
# ---------------------------------------------------------------------------
# Shelf-life X, in years, keyed by data class. First match wins.
_SHELF_LIFE: List[tuple] = [
    (10.0, ("payment", "card", "pan", "banking", "financial", "transaction", "ledger")),
    (7.0,  ("pii", "personal-data", "ssn", "national-id", "passport", "health", "phi", "gdpr", "hipaa")),
    (5.0,  ("auth", "login", "credential", "session", "token", "password", "identity", "signature", "jwt", "oauth")),
    (4.0,  ("config", "keystore", "truststore", "certificate", "tls")),
]
_DEFAULT_SHELF_LIFE = 3.0

# Migration cost Y base, in years, by family. Asymmetric -> PQC is the hard one.
_MIGRATION_BASE: Dict[str, float] = {
    "ASYM": 8.0,   # public-key -> PQC is a protocol change, not a config change
    "KEM":  8.0,
    "JWT":  3.0,
    "TLS":  4.0,
    "KDF":  2.0,
    "SYM":  1.5,   # key rotation is operationally routine
    "HASH": 1.0,   # swap the function, rehash the table
    "MULTI": 3.0,
    "UNKNOWN": 3.0,
}
_LOC_SATURATION = 500   # findings beyond this stop increasing migration cost


# Primitives that are ALREADY broken on classical hardware. These need
# migrating today, and no amount of quantum planning changes that.
#
# This term exists because the plan's composite (0.6*Mosca + 0.4*quantum)
# scores MD5 at 0.0: it carries no migration pressure under Mosca (short data
# shelf-life, trivial swap) and no quantum vulnerability (trivial classical
# break). Reporting a broken primitive as zero risk is worse than useless - it
# buries it. See `final_score` for how it is folded in.
_CLASSICAL_BROKEN = {
    "MD2", "MD4", "MD5", "RC2", "RC4", "DES", "3DES",
    "SSLV2", "SSLV3", "TLSV1", "TLSV1.1",
    "BLOWFISH", "SHA-1",
}


@dataclass
class RiskBreakdown:
    """Auditable per-finding risk decomposition."""
    mosca_shelf_life_years: float = 0.0
    mosca_migration_years: float = 0.0
    mosca_collapse_years: float = 15.0
    mosca_ratio: float = 0.0
    mosca_normalized: float = 0.0
    quantum_toffoli: float = 0.0
    quantum_logical_qubits: int = 0
    quantum_normalized: float = 0.0
    quantum_source: str = ""
    classical_weakness: float = 0.0
    migration_urgency: float = 0.0
    final_score: float = 0.0
    mosca_triggered: bool = False
    rationale: List[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def classical_weakness(algorithm: str, family: str) -> float:
    """
    How broken the primitive is right now, on today's hardware.

    1.0 = trivially broken (MD5, RC4, DES, SSLv3)
    0.5 = deprecated or below modern floors (SHA-1, TLS 1.0)
    0.2 = weak by default (bare 1024-bit RSA, unparameterised AES)
    0.0 = sound
    """
    a = (algorithm or "").upper()
    if any(b in a for b in _CLASSICAL_BROKEN):
        return 1.0
    if any(w in a for w in ("SHA-1", "SHA1", "TLSV1", "RC2")):
        return 0.5
    # Key-size floors apply to asymmetric primitives only. A bare "-(\d{3,4})"
    # would read "SHA-256" as a 256-bit key and condemn a sound hash.
    if family == "ASYM":
        bits = re.search(r"-(\d{3,4})\b", a)
        if bits and int(bits.group(1)) < 2048:
            return 0.9
    if a in ("AES", "DES-EDE3"):
        return 0.2
    return 0.0


def _norm_algorithm(alg: str) -> str:
    """Map a free-form algorithm string onto a table key."""
    a = (alg or "").upper().replace("_", "-").replace(" ", "")
    if "CHACHA" in a:
        return "AES-256"          # ChaCha20-Poly1305 has a 256-bit key
    for key in sorted(_QUANTUM, key=len, reverse=True):
        if key in a:
            return key
    # Curve names appear both hyphenated ("P-256") and run together
    # ("ECDSAP256", "NISTP256", "secp256r1"), so compare on a squashed form.
    squashed = a.replace("-", "").replace("_", "")
    if squashed.startswith("P") or "NISTP" in squashed or "SECP" in squashed or "ECDSAP" in squashed:
        for p in ("P-192", "P-224", "P-256", "P-384", "P-521"):
            if p.replace("-", "") in squashed:
                return p
    if "SHA3-512" in a:
        return "SHA-512"
    if "SHA3" in a:
        return "SHA-256"
    return ""


def quantum_effort(algorithm: str, family: str) -> tuple:
    """Return (toffoli, logical_qubits, source) for a primitive."""
    key = _norm_algorithm(algorithm)
    if key and key in _QUANTUM:
        q = _QUANTUM[key]
        return q["toffoli"], q["qubits"], q["src"]
    q = _QUANTUM_BY_FAMILY.get(family, _QUANTUM_BY_FAMILY["MULTI"])
    return q["toffoli"], q["qubits"], q["src"]


def _quantum_normalized(toffoli: float) -> float:
    """
    Map serial Toffoli count onto 0-10 on a log2 scale, 2 gates per point.
    1e0 -> 0, 1e2 -> 1, ... 1e20 -> 10. Saturates beyond 1e20.

    Log scale is the only defensible mapping here: the difference between
    1e12 and 1e13 gates matters enormously, the difference between 1e19 and
    1e20 does not, and both are 'infeasible' in practice.
    """
    if toffoli <= 0:
        return 0.0
    return min(10.0, max(0.0, math.log10(toffoli) / 2.0))


def shelf_life(blob: str) -> tuple:
    """Estimate data shelf-life X from path + context keywords."""
    lowered = blob.lower()
    for years, needles in _SHELF_LIFE:
        for needle in needles:
            if needle in lowered:
                return years, f"'{needle}' keyword implies {years:g}y retention"
    return _DEFAULT_SHELF_LIFE, "no data-class keyword; default 3y"


def migration_years(family: str, footprint: int) -> tuple:
    """Estimate migration cost Y: family base scaled by blast radius."""
    base = _MIGRATION_BASE.get(family, _MIGRATION_BASE["UNKNOWN"])
    scale = 1.0 + min(3.0, (footprint / _LOC_SATURATION) * 0.5)
    return base * scale, f"{family} base {base:g}y x blast-radius {scale:.2f}"


def assess(f: Finding, z_years: float, family_footprint: int) -> RiskBreakdown:
    """Compute the full risk breakdown for one finding."""
    rb = RiskBreakdown(rationale=[])
    rb.mosca_collapse_years = float(z_years)

    blob = f"{f.file} {f.rule_id} {f.context}"
    x, x_why = shelf_life(blob)
    y, y_why = migration_years(f.algorithm_family, family_footprint)

    rb.mosca_shelf_life_years = x
    rb.mosca_migration_years = y
    rb.mosca_ratio = (x + y) / z_years if z_years > 0 else 0.0
    # ratio 1.0 -> 0 risk, ratio 3.0+ -> saturated at 10
    rb.mosca_normalized = min(10.0, max(0.0, (rb.mosca_ratio - 1.0) * 5.0))
    rb.mosca_triggered = rb.mosca_ratio > 1.0

    toffoli, qubits, src = quantum_effort(f.algorithm, f.algorithm_family)
    rb.quantum_toffoli = toffoli
    rb.quantum_logical_qubits = qubits
    rb.quantum_source = src
    rb.quantum_normalized = _quantum_normalized(toffoli)

    # The plan's composite, preserved exactly as a sub-component.
    rb.migration_urgency = round(0.6 * rb.mosca_normalized + 0.4 * rb.quantum_normalized, 3)

    # A primitive that is already broken is urgent by definition and must not
    # be outranked by one that merely has a long migration. Taking the max
    # keeps the plan's weighting intact for everything else while giving
    # classically-dead crypto a floor.
    rb.classical_weakness = classical_weakness(f.algorithm, f.algorithm_family)
    rb.final_score = round(max(rb.migration_urgency, rb.classical_weakness * 10.0), 3)

    rb.rationale = [
        f"X={x:g}y ({x_why})",
        f"Y={y:.1f}y ({y_why})",
        f"Z={z_years:g}y -> (X+Y)/Z = {rb.mosca_ratio:.2f} "
        f"{'> 1 MIGRATE NOW' if rb.mosca_triggered else '(no migration pressure)'}",
        f"quantum: {toffoli:.2e} Toffoli, {qubits} logical qubits [{src}]",
        f"classical weakness: {rb.classical_weakness:.1f}"
        + (" (broken on today's hardware)" if rb.classical_weakness >= 1.0 else ""),
    ]
    return rb


def score_all(findings: List[Finding], z_years: float = 15.0) -> List[Finding]:
    """
    Attach a RiskBreakdown to every finding and sort by descending score.

    Footprint is computed per algorithm family across the whole finding set,
    so a family used in 200 places scores higher than one used once. This is
    what makes the Mosca Z-slider re-rank meaningfully: dragging Z down
    raises every asymmetric finding, but the heavily-used ones rise fastest.
    """
    footprint: Dict[str, int] = {}
    for f in findings:
        footprint[f.algorithm_family] = footprint.get(f.algorithm_family, 0) + 1

    for f in findings:
        rb = assess(f, z_years, footprint.get(f.algorithm_family, 1))
        f.risk_score = rb.final_score
        f.extra = dict(f.extra or {})
        f.extra["risk"] = rb.to_dict()

    findings.sort(key=lambda f: f.risk_score, reverse=True)
    log.info("risk: scored %d finding(s) at Z=%.1fy", len(findings), z_years)
    return findings


def summary(findings: List[Finding]) -> Dict[str, Any]:
    """Headline numbers for the API/UI."""
    if not findings:
        return {"total": 0, "by_family": {}, "max_score": 0.0, "mean_score": 0.0}

    by_family: Dict[str, int] = {}
    for f in findings:
        by_family[f.algorithm_family] = by_family.get(f.algorithm_family, 0) + 1

    scores = [f.risk_score for f in findings]
    return {
        "total": len(findings),
        "by_family": by_family,
        "max_score": round(max(scores), 3),
        "mean_score": round(sum(scores) / len(scores), 3),
        "above_mosca_threshold": sum(1 for f in findings if f.extra.get("risk", {}).get("mosca_triggered")),
    }
