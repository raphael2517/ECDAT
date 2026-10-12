"""
ECDAT Scanner - Recommendation & Benchmark Engine.

Maps detected primitives onto post-quantum replacements and measures the
before/after delta using the locally built liboqs (via liboqs-python) against
a classical baseline (via `cryptography`).

No network calls: liboqs is a shared library baked into the image and loaded
from $OQS_INSTALL_PATH.
"""

import os
import statistics
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Tuple

from detection import Finding
from utils import log

# Point the ctypes loader at the baked-in liboqs before importing oqs.
os.environ.setdefault("OQS_INSTALL_PATH", os.getenv("OQS_INSTALL_PATH", "/opt/oqs"))

DEFAULT_ITERATIONS = int(os.getenv("BENCH_ITERATIONS", "100"))

# ---------------------------------------------------------------------------
# Primitive -> PQC replacement map
# ---------------------------------------------------------------------------
# `migrate_to` is what a team should actually deploy today. `family` groups
# the mapping for the UI heatmap.
REPLACEMENTS: Dict[str, Dict[str, Any]] = {
    "RSA-2048": {
        "replaces": "RSA-2048", "family": "ASYM",
        "migrate_to": ["ML-KEM-768", "ML-DSA-65"],
        "rationale": "RSA-2048 is factored by a fault-tolerant machine in ~8h [GE19]. Hybrid ML-KEM-768 + ML-DSA-65 preserves the KEM+signature shape of TLS/PGP.",
        "stdlib": "TLS 1.3 hybrid key exchange (X25519MLKEM768 / SecP256r1MLKEM768)",
    },
    "RSA-3072": {
        "replaces": "RSA-3072", "family": "ASYM",
        "migrate_to": ["ML-KEM-768", "ML-DSA-65"],
        "rationale": "Same migration path as RSA-2048; the larger modulus only delays the quantum deadline, it does not remove it.",
        "stdlib": "TLS 1.3 hybrid key exchange",
    },
    "RSA-4096": {
        "replaces": "RSA-4096", "family": "ASYM",
        "migrate_to": ["ML-KEM-768", "ML-DSA-65"],
        "rationale": "Same migration path as RSA-2048.",
        "stdlib": "TLS 1.3 hybrid key exchange",
    },
    "RSA-1024": {
        "replaces": "RSA-1024", "family": "ASYM",
        "migrate_to": ["ML-KEM-768", "ML-DSA-65"],
        "rationale": "Already below the 2048-bit floor. This is a classical weakness, not a quantum one - fix it now regardless of PQC plans.",
        "stdlib": "TLS 1.3 hybrid key exchange",
    },
    "P-256": {
        "replaces": "ECDSA-P256", "family": "ASYM",
        "migrate_to": ["ML-DSA-65"],
        "rationale": "ECDSA P-256 is broken by Shor's algorithm at ~2330 logical qubits [G19]. ML-DSA-65 is NIST FIPS 204 level 3, matching P-256's classical level.",
        "stdlib": "TLS 1.3 hybrid signature (ECDSA + ML-DSA)",
    },
    "P-384": {
        "replaces": "ECDSA-P384", "family": "ASYM",
        "migrate_to": ["ML-DSA-87"],
        "rationale": "ML-DSA-87 is FIPS 204 level 5, matching P-384.",
        "stdlib": "TLS 1.3 hybrid signature",
    },
    "P-521": {
        "replaces": "ECDSA-P521", "family": "ASYM",
        "migrate_to": ["ML-DSA-87"],
        "rationale": "Highest NIST level available today.",
        "stdlib": "TLS 1.3 hybrid signature",
    },
    "AES-128": {
        "replaces": "AES-128-GCM", "family": "SYM",
        "migrate_to": ["AES-256-GCM", "ChaCha20-Poly1305"],
        "rationale": "Grover halves the effective key length: AES-128 drops to 64-bit effective security. Doubling to 256 restores it. This is a schedule change, not a protocol change - the cheapest fix in the whole report.",
        "stdlib": "AES-256-GCM (hardware AES-NI support is universal)",
    },
    "AES-256": {
        "replaces": "AES-256-GCM", "family": "SYM",
        "migrate_to": ["AES-256-GCM", "ChaCha20-Poly1305"],
        "rationale": "AES-256 is already quantum-resistant (Grover only reduces it to 128-bit effective security) and needs no migration. Listed for completeness: the one action item is key rotation to AES-256 wherever AES-128 is still in use elsewhere in the estate.",
        "stdlib": "AES-256-GCM (no change required)",
    },
    "SHA-256": {
        "places": "SHA-256 collision resistance", "family": "HASH",
        "migrate_to": ["SHA-512", "SHA3-512"],
        "rationale": "Quantum collision search on SHA-256 is ~2^85 Toffoli, below the fault-tolerance threshold. SHA3-512 gives a wider margin.",
        "stdlib": "SHA3-512",
    },
    "TLS": {
        "replaces": "TLS 1.2/1.3 session", "family": "TLS",
        "migrate_to": ["TLS 1.3 + hybrid KEM"],
        "rationale": "Restrict to TLS 1.3, drop RSA key exchange and static DH, enable X25519MLKEM768.",
        "stdlib": "TLS 1.3 with hybrid key exchange",
    },
}


def _key(algorithm: str, family: str) -> Optional[str]:
    a = (algorithm or "").upper().replace("_", "-")
    if "RSA" in a:
        m = [k for k in ("RSA-2048", "RSA-3072", "RSA-4096") if k in a]
        if m:
            return m[0]
        if "1024" in a:
            return "RSA-1024"
        return "RSA-2048"
    if "P-384" in a or "NISTP384" in a or "384" in a and "P" in a:
        return "P-384"
    if "P-521" in a or "521" in a:
        return "P-521"
    if "P-256" in a or "P256" in a or "256" in a and ("ECDSA" in a or "EC" in a):
        return "P-256"
    if family == "SYM" and "AES" in a:
        return "AES-128" if "128" in a else "AES-256"
    if family == "HASH" and "SHA-256" in a:
        return "SHA-256"
    if family == "TLS":
        return "TLS"
    return None


def recommend(f: Finding) -> Optional[Dict[str, Any]]:
    """Return a replacement recommendation for one finding, if we have one."""
    key = _key(f.algorithm, f.algorithm_family)
    if not key:
        return None
    # A missing table entry is a gap in our mapping, not a reason to abort a
    # scan. Skip this finding rather than raising.
    if key not in REPLACEMENTS:
        return None
    rec = dict(REPLACEMENTS[key])
    rec["from"] = f.algorithm
    rec["from_key"] = key
    rec["source_finding"] = {"file": f.file, "line": f.line, "rule_id": f.rule_id}
    rec["risk_score"] = f.risk_score
    return rec


def recommend_all(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Deduplicated recommendations, most urgent first."""
    seen, out = set(), []
    for f in sorted(findings, key=lambda x: x.risk_score, reverse=True):
        rec = recommend(f)
        if not rec:
            continue
        if rec["from_key"] in seen:
            continue
        seen.add(rec["from_key"])
        rec["occurrences"] = sum(1 for x in findings if _key(x.algorithm, x.algorithm_family) == rec["from_key"])
        out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Benchmarking
# ---------------------------------------------------------------------------
@dataclass
class BenchRow:
    """One algorithm's measured performance, classical or PQC."""
    scheme: str
    kind: str                  # "KEM" | "SIG" | "AEAD"
    implementation: str        # "classical" | "pqc"
    keygen_ms: float = 0.0
    primary_ms: float = 0.0    # encaps / sign / encrypt
    secondary_ms: float = 0.0  # decaps / verify / decrypt
    pub_key_bytes: int = 0
    payload_bytes: int = 0    # ciphertext / signature
    sec_key_bytes: int = 0
    iterations: int = 0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _stats(samples: List[float]) -> Tuple[float, float]:
    if not samples:
        return 0.0, 0.0
    return statistics.mean(samples), statistics.pstdev(samples) or 0.0


def _measure(fn, iterations: int) -> float:
    """Mean wall-clock ms over `iterations` calls."""
    samples = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    mean, _ = _stats(samples)
    return round(mean, 4)


# --- classical baseline (cryptography) ------------------------------------
def bench_classical_rsa(bits: int = 2048, iterations: int = DEFAULT_ITERATIONS) -> BenchRow:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

    priv = generate_private_key(public_exponent=65537, key_size=bits)
    pub = priv.public_key()
    msg = b"ecdat benchmark payload"
    sig_alg = __import__("cryptography.hazmat.primitives.asymmetric.padding", fromlist=["PKCS1v15"]).PKCS1v15()

    def do_enc() -> None:
        pub.encrypt(msg, padding.PKCS1v15())

    ct = pub.encrypt(msg, padding.PKCS1v15())

    def do_dec() -> None:
        priv.decrypt(ct, padding.PKCS1v15())

    return BenchRow(
        scheme=f"RSA-{bits}", kind="KEM", implementation="classical",
        keygen_ms=_measure(lambda: generate_private_key(public_exponent=65537, key_size=bits), max(1, iterations // 10)),
        primary_ms=_measure(do_enc, iterations),
        secondary_ms=_measure(do_dec, iterations),
        pub_key_bytes=len(pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
        payload_bytes=len(ct),
        sec_key_bytes=len(priv.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        iterations=iterations,
    )


def bench_classical_ecdsa(curve_name: str = "P-256", iterations: int = DEFAULT_ITERATIONS) -> BenchRow:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    curve = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1}[curve_name]
    priv = ec.generate_private_key(curve())
    msg = b"ecdat benchmark payload"

    def do_keygen() -> None:
        ec.generate_private_key(curve())

    def do_sign() -> None:
        priv.sign(msg, ec.ECDSA(hashes.SHA256()))

    sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))

    def do_verify() -> None:
        priv.public_key().verify(sig, msg, ec.ECDSA(hashes.SHA256()))

    return BenchRow(
        scheme=f"ECDSA-{curve_name}", kind="SIG", implementation="classical",
        keygen_ms=_measure(do_keygen, max(1, iterations // 10)),
        primary_ms=_measure(do_sign, iterations),
        secondary_ms=_measure(do_verify, iterations),
        pub_key_bytes=len(priv.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)),
        payload_bytes=len(sig),
        sec_key_bytes=len(priv.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
        iterations=iterations,
    )


def bench_classical_aes(bits: int = 256, iterations: int = DEFAULT_ITERATIONS) -> BenchRow:
    import os as _os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = _os.urandom(bits // 8)
    nonce = _os.urandom(12)
    aead = AESGCM(key)
    msg = b"ecdat benchmark payload"

    def do_enc() -> None:
        aead.encrypt(nonce, msg, None)

    ct = aead.encrypt(nonce, msg, None)

    def do_dec() -> None:
        AESGCM(key).decrypt(nonce, ct, None)

    return BenchRow(
        scheme=f"AES-{bits}-GCM", kind="AEAD", implementation="classical",
        keygen_ms=_measure(lambda: _os.urandom(bits // 8), iterations),
        primary_ms=_measure(do_enc, iterations),
        secondary_ms=_measure(do_dec, iterations),
        pub_key_bytes=len(key),
        payload_bytes=len(ct),
        sec_key_bytes=len(key),
        iterations=iterations,
    )


def bench_classical_chacha20(iterations: int = DEFAULT_ITERATIONS) -> BenchRow:
    """Alternative AEAD, so the AES-256-GCM -> ChaCha20-Poly1305 pair is real."""
    import os as _os
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    key = _os.urandom(32)
    nonce = _os.urandom(12)
    aead = ChaCha20Poly1305(key)
    msg = b"ecdat benchmark payload"

    def do_enc() -> None:
        aead.encrypt(nonce, msg, None)

    ct = aead.encrypt(nonce, msg, None)

    def do_dec() -> None:
        ChaCha20Poly1305(key).decrypt(nonce, ct, None)

    return BenchRow(
        scheme="ChaCha20-Poly1305", kind="AEAD", implementation="classical",
        keygen_ms=_measure(lambda: _os.urandom(32), iterations),
        primary_ms=_measure(do_enc, iterations),
        secondary_ms=_measure(do_dec, iterations),
        pub_key_bytes=len(key),
        payload_bytes=len(ct),
        sec_key_bytes=len(key),
        iterations=iterations,
    )


# --- PQC (liboqs) ----------------------------------------------------------
#
# liboqs-python 0.16.0 changed the API to be STATEFUL. The older shape was
#     pk, sk = kem.generate_keypair(); kem.encap_secret(pk); kem.decap_secret(ct, sk)
# Now the object owns the secret key and only the public key comes back:
#     pk = kem.generate_keypair(); ct, ss = kem.encap_secret(pk); ss2 = kem.decap_secret(ct)
# Signature.sign(msg) likewise takes no key, and verify takes (msg, sig, pk)
# in that order. Getting this wrong fails at runtime, not at import.
def bench_pq_kem(scheme: str = "ML-KEM-768", iterations: int = DEFAULT_ITERATIONS) -> BenchRow:
    import oqs

    kem = oqs.KeyEncapsulation(scheme)
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()

    def do_keygen() -> None:
        kem.generate_keypair()

    def do_encap() -> None:
        kem.encap_secret(public_key)

    ciphertext, _shared = kem.encap_secret(public_key)

    def do_decap() -> None:
        kem.decap_secret(ciphertext)

    return BenchRow(
        scheme=scheme, kind="KEM", implementation="pqc",
        keygen_ms=_measure(do_keygen, max(1, iterations // 10)),
        primary_ms=_measure(do_encap, iterations),
        secondary_ms=_measure(do_decap, iterations),
        pub_key_bytes=len(public_key),
        payload_bytes=len(ciphertext),
        sec_key_bytes=len(secret_key),
        iterations=iterations,
    )


def bench_pq_sig(scheme: str = "ML-DSA-65", iterations: int = DEFAULT_ITERATIONS) -> BenchRow:
    import oqs

    sig = oqs.Signature(scheme)
    public_key = sig.generate_keypair()
    secret_key = sig.export_secret_key()
    msg = b"ecdat benchmark payload"

    def do_keygen() -> None:
        sig.generate_keypair()

    def do_sign() -> None:
        sig.sign(msg)

    signature = sig.sign(msg)

    def do_verify() -> None:
        sig.verify(msg, signature, public_key)   # arg order is (msg, sig, pk) in 0.16.0

    return BenchRow(
        scheme=scheme, kind="SIG", implementation="pqc",
        keygen_ms=_measure(do_keygen, max(1, iterations // 10)),
        primary_ms=_measure(do_sign, iterations),
        secondary_ms=_measure(do_verify, iterations),
        pub_key_bytes=len(public_key),
        payload_bytes=len(signature),
        sec_key_bytes=len(secret_key),
        iterations=iterations,
    )


def run_benchmarks(iterations: int = DEFAULT_ITERATIONS, fast: bool = False) -> List[BenchRow]:
    """
    Run the before/after benchmark suite.

    Each pair (classical, pqc) brackets one migration so the UI can render a
    delta table. A failing row is reported with `error` set rather than
    aborting the suite - a missing algorithm must not lose the whole report.
    """
    if fast:
        iterations = max(5, iterations // 10)

    suite = [
        ("classical RSA-2048", lambda: bench_classical_rsa(2048, iterations)),
        ("classical ECDSA-P256", lambda: bench_classical_ecdsa("P-256", iterations)),
        ("classical AES-256-GCM", lambda: bench_classical_aes(256, iterations)),
        ("classical ChaCha20-Poly1305", lambda: bench_classical_chacha20(iterations)),
        ("PQC ML-KEM-768", lambda: bench_pq_kem("ML-KEM-768", iterations)),
        ("PQC ML-DSA-65", lambda: bench_pq_sig("ML-DSA-65", iterations)),
        ("PQC ML-DSA-87", lambda: bench_pq_sig("ML-DSA-87", iterations)),
    ]

    rows: List[BenchRow] = []
    for label, fn in suite:
        try:
            row = fn()
            log.info("bench %-22s keygen=%.3fms primary=%.3fms", row.scheme, row.keygen_ms, row.primary_ms)
            rows.append(row)
        except Exception as exc:
            log.error("bench %s failed: %s", label, exc)
            rows.append(BenchRow(scheme=label.split(" ", 1)[-1], kind="?", implementation=label.split()[0].lower(), error=str(exc)))
    return rows


PAIRS = [
    ("RSA-2048", "ML-KEM-768", "KEM"),
    ("ECDSA-P256", "ML-DSA-65", "SIG"),
    ("ML-DSA-87", "ML-DSA-65", "SIG"),   # size/class tradeoff at the higher level
    ("AES-256-GCM", "ChaCha20-Poly1305", "AEAD"),
]


def compare(rows: List[BenchRow]) -> List[Dict[str, Any]]:
    """Pair up benchmark rows and compute before/after deltas for the UI."""
    by_scheme = {r.scheme: r for r in rows if not r.error}
    out = []

    for classical, pqc, kind in PAIRS:
        c, p = by_scheme.get(classical), by_scheme.get(pqc)
        if not c:
            continue
        entry: Dict[str, Any] = {
            "kind": kind,
            "classical": c.to_dict(),
            "pqc": p.to_dict() if p else None,
            "pairs_with": pqc,
        }

        if p:
            def delta(field_name, lower_is_better):
                a, b = getattr(c, field_name), getattr(p, field_name)
                if not a:
                    return None
                pct = ((b - a) / a) * 100.0
                # A negative delta is an improvement for every metric we track:
                # less time and fewer bytes are both better. `lower_is_better`
                # is kept only to record intent in the payload.
                if abs(pct) < 0.5:
                    direction = "same"
                else:
                    direction = "better" if pct < 0 else "worse"
                return {
                    "metric": field_name,
                    "classical": a,
                    "pqc": b,
                    "delta_pct": round(pct, 2),
                    "direction": direction,
                    "lower_is_better": lower_is_better,
                }

            entry["deltas"] = [
                d for d in (
                    delta("keygen_ms", False),
                    delta("primary_ms", False),
                    delta("secondary_ms", False),
                    delta("pub_key_bytes", True),
                    delta("payload_bytes", True),
                ) if d
            ]
        out.append(entry)

    return out
