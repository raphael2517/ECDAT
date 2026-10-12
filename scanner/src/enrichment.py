"""
ECDAT Scanner - Heuristic Enrichment.

The LLM phase was cut. This module fills the same enrichment fields
(algorithm / usage / key_mgmt / risk) using deterministic rules over the
snippet, the surrounding context, and the static-analysis metadata.

Everything here is explainable: each field records which rule fired in
`extra.enrichment_rule` so a reviewer can audit the decision. No network
calls, no model, no external dependency.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from detection import Finding, infer_family
from utils import log

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
_USAGE_RULES: List[Tuple[str, str]] = [
    (r"\b(encapsulate|encap|decapsulate|decap)\b", "key-exchange"),
    # Cipher construction alone does not say encrypt vs decrypt; conventional
    # crypto-inventory tooling labels it "encryption" unless a decrypt signal
    # is present, so we order the explicit decrypt rules first (see below).
    (r"\bdecrypt\s*\(|Cipher\.DECRYPT_MODE|openssl_decrypt|\.doFinal\s*\(\s*ct", "decryption"),
    (r"\bencrypt\s*\(|Cipher\.ENCRYPT_MODE|Cipher\.encrypt|Cipher\.getInstance\(|AES\.new\(|DES\.new\(|ARC4\.new\(|createCipher", "encryption"),
    (r"\b(sign|signature|signing)\b|Jwts\.builder|\.signWith|Signer\.sign", "signing"),
    (r"\b(verify|verification)\b|\.verify\s*\(|Signature\.verify", "verification"),
    (r"\b(digest|hash|checksum)\b|getInstance\(\s*[\"']SHA|getInstance\(\s*[\"']MD|\.new\(\)", "hashing"),
    (r"\b(kdf|derive|hkdf|pbkdf2|scrypt|argon2|bcrypt)\b", "key-derivation"),
    (r"\bgetRandomBytes|SecureRandom|randomBytes", "randomness"),
    (r"\b(keystore|truststore|KeyStore|TrustManager)\b", "key-management"),
    (r"\b(tls|ssl|handshake|SSLSocket|SSLContext)\b", "transport-security"),
]

# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------
_KEYMGMT_RULES: List[Tuple[str, str, str]] = [
    # (regex, label, rationale)
    (r"(private\s*key|secret\s*key|passphrase|password|api[_-]?key)\s*=\s*[\"'][^\"']{6,}[\"']",
     "hardcoded", "credential assigned an inline literal"),
    (r"-----BEGIN\s+(RSA\s+|EC\s+)?PRIVATE\s+KEY-----", "hardcoded", "inline PEM private key"),
    (r"new\s+SecretKeySpec\s*\(\s*[\"']", "hardcoded", "SecretKeySpec built from a literal"),
    (r"getenv\s*\(|System\.getProperty\s*\(\s*[\"']|ENV\[|os\.environ",
     "env-var", "key sourced from the environment"),
    (r"(application\.yml|application\.properties|\.env\b|web\.config|appsettings\.json)",
     "config-file", "key material in an application config file"),
    (r"KeyStore\.getInstance|loadKeyStore|FileInputStream.*\.(jks|p12|pfx)",
     "keystore", "key loaded from a Java keystore"),
    (r"\b(KMS|kms\.|KeyManagementService|AwsKms|GcpKms|AzureKeyVault)",
     "kms", "key held in a managed key service"),
    (r"\b(HSM|PKCS.?11|SoftHSM|Session\.open)\b", "hsm", "key held in a hardware token"),
    (r"\b(HKDF|Kdf\.derive|SecretKeyFactory|deriveKey)\b", "derived", "key derived at runtime"),
    (r"KeyPairGenerator\.getInstance|generateKeyPair|keygen|new\s+SecureRandom",
     "ephemeral", "key generated locally per session"),
]

# ---------------------------------------------------------------------------
# Weak / broken primitives -> risk floor
# ---------------------------------------------------------------------------
_BROKEN = {
    "md2": "critical", "md4": "critical", "md5": "critical",
    "rc4": "critical", "rc2": "critical",
    "des": "critical", "3des": "critical", "desede": "critical", "tripledes": "critical",
    "ssl2": "critical", "ssl3": "critical",
    "tls1.0": "critical", "tls1.1": "critical", "tlsv1": "critical", "tlsv1.1": "critical",
    "sha-1": "high", "sha1": "high",
    "dsa": "high", "ecdsa-sha1": "high",
}
_WEAK_RSA_BITS = re.compile(r"\b(512|1024)\b")

_RISK_ORDER = ["info", "low", "medium", "high", "critical"]


def _worst(*levels: str) -> str:
    best = "info"
    for lv in levels:
        if lv in _RISK_ORDER and _RISK_ORDER.index(lv) > _RISK_ORDER.index(best):
            best = lv
    return best


def _match_first(blob: str, rules: List[Tuple[str, ...]]) -> Optional[Tuple[str, str]]:
    for rule in rules:
        for pattern in rule[:-1] if len(rule) == 3 else [rule[0]]:
            m = re.search(pattern, blob, re.IGNORECASE)
            if m:
                label = rule[-2] if len(rule) == 3 else rule[1]
                why = rule[-1] if len(rule) == 3 else ""
                return label, why
    return None


# ---------------------------------------------------------------------------
# Per-finding enrichment
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Primitive sniffing
#
# Semgrep does NOT interpolate metavariables inside `metadata` - a rule with
# `metadata.algorithm: "$ALG"` emits the literal string "$ALG" in the JSON. It
# does interpolate `message`, but the message is prose. So the algorithm a
# static rule claims is often a placeholder, and the real primitive has to be
# read back out of the matched text.
#
# These sniffs run before anything family-gated, because the family we would
# otherwise trust is itself derived from the placeholder.
# ---------------------------------------------------------------------------
_SNIFFERS: List[Tuple[str, str, str]] = [
    # (regex, family, normaliser)
    (r"\b(ML-KEM-\d+|Kyber\d+)\b", "KEM", "upper"),
    (r"\b(ML-DSA-\d+|Dilithium\d+)\b", "ASYM", "upper"),
    (r"\b(HS|RS|ES|PS)(256|384|512)\b", "JWT", "jwt"),
    (r"\b(RSA)[-/]?(\d{3,4})\b", "ASYM", "rsa"),
    (r"\b(ECDSA|EC|DSA)[-/ ]?(?:NIST)?P[- ]?(\d{3})\b", "ASYM", "curve"),
    (r"\b(Ed25519|Ed448|X25519|X448|curve25519)\b", "ASYM", "title"),
    (r"\b(ChaCha20[-_]?Poly1305|ChaCha20)\b", "SYM", "title"),
    (r"\b(AES)[-/]?(?:ECB|CBC|GCM|CTR|CFB|OFB|CCM)?[/]?(?:PKCS\w+)?\b", "SYM", "aes"),
    (r"\b(3DES|DESede|DES)[-/]?(?:ECB|CBC)?\b", "SYM", "des"),
    (r"\b(RC4|ARC4|RC2|Blowfish|Camellia|SM4)\b", "SYM", "upper"),
    (r"\b(SHA3[-_]?512|SHA3[-_]?256|SHA-?512|SHA-?384|SHA-?256|SHA-?224|SHA-?1|SHA)\b", "HASH", "hash"),
    (r"\b(MD5|MD4|MD2)\b", "HASH", "upper"),
    (r"\b(BLAKE2[bsx]|BLAKE3|RIPEMD-?160|SM3)\b", "HASH", "upper"),
    (r"\b(TLSv?1(?:\.[0-3])?|SSLv?[23](?:\.[0-3])?)\b", "TLS", "upper"),
    (r"\b(bcrypt|scrypt|Argon2\w*|PBKDF2|HKDF)\b", "KDF", "title"),
    # Bare asymmetric primitives with no explicit size. These must come last:
    # "RSA" alone is far less specific than "RSA-2048", and a preceding
    # keygen line in the context window may carry the size separately.
    (r"\b(RSA|RSASSA[-_]?PSS)\b", "ASYM", "rsa_bare"),
    (r"\b(ECDSA|ECDH|DSA|EdDSA)\b", "ASYM", "upper"),
]

# A keygen/size call in the context window, used to qualify a bare primitive.
_BITS = re.compile(
    r"(?:initialize|keysize|key[-_ ]?size|length|size)\s*\(?\s*(\d{3,4})", re.IGNORECASE
)

# Longest/most-specific primitives must win, so try the JWE/PGP-style
# multi-part strings before the bare primitive names.
_BLOCK_BROKEN = ("ECBNOPADDING",)


def _normalise(kind: str, match: re.Match) -> str:
    """Turn a regex hit into a canonical primitive name."""
    if kind == "jwt":
        return f"{match.group(1).upper()}{match.group(2)}"
    if kind == "rsa":
        return f"RSA-{match.group(2)}"
    if kind == "rsa_bare":
        base = "RSA" if "RSA" in match.group(1).upper() else "RSASSA-PSS"
        # The size usually lives on a neighbouring keygen call, not on the
        # primitive name itself, so look for it in the surrounding text.
        bits = _BITS.search(match.string)
        return f"{base}-{bits.group(1)}" if bits else base
    if kind == "curve":
        prefix = match.group(1).upper()
        return f"{prefix}-P{match.group(2)}"
    if kind == "aes":
        bits = re.search(r"-(\d{3})", match.group(0))
        return f"AES-{bits.group(1)}" if bits else "AES"
    if kind == "des":
        token = match.group(1).upper()
        return "3DES" if token in ("3DES", "DESEDE") else "DES"
    if kind == "hash":
        token = re.sub(r"[-_]", "-", match.group(1).upper())
        return "SHA-1" if token == "SHA-1" else token
    if kind == "title":
        return match.group(1)
    return match.group(1).upper()


def sniff(blob: str, family: Optional[str] = None) -> Tuple[Optional[str], str]:
    """
    Identify the primitive in a chunk of source text.

    `family` is an optional prior from the rule's own metadata. When a rule
    knows it is matching, say, asymmetric crypto, restricting the search to
    that family stops a nearby unrelated primitive elsewhere in the context
    window from winning. The window is +/-5 lines, so an RSA keygen block
    sitting under a block-cipher call would otherwise resolve as AES.

    Returns (algorithm, family); (None, "UNKNOWN") when nothing matches.
    """
    if not blob:
        return None, "UNKNOWN"
    candidates = (
        [s for s in _SNIFFERS if s[1] == family]
        if family and family not in ("UNKNOWN", "MULTI")
        else _SNIFFERS
    )
    for rx, fam, kind in candidates:
        m = re.search(rx, blob, re.IGNORECASE)
        if m:
            return _normalise(kind, m), fam
    return None, "UNKNOWN"


def classify_usage(f: Finding) -> Tuple[str, str]:
    blob = f"{f.snippet}\n{f.context}"
    hit = _match_first(blob, [tuple(r) for r in _USAGE_RULES])
    if hit:
        return hit[0], f"usage regex matched ({hit[0]})"
    if f.source == "syft" or f.mode == "LIBRARY":
        return "library", "SBOM component, not a call site"
    return "unknown", "no usage signal"


def classify_key_mgmt(f: Finding) -> Tuple[str, str]:
    blob = f"{f.snippet}\n{f.context}"
    hit = _match_first(blob, [tuple(r) for r in _KEYMGMT_RULES])
    if hit:
        return hit[0], hit[1]
    if f.source == "syft" or f.mode == "LIBRARY":
        return "unknown", "SBOM component, no key handling"
    return "unknown", "no key-management signal"


def refine_algorithm(f: Finding) -> Tuple[str, str]:
    """Sharpen the algorithm beyond whatever the static rule could name."""
    blob = f"{f.snippet}\n{f.context}"
    fam = f.algorithm_family

    if fam == "SYM":
        m = re.search(r"\b(3DES|DESede|DES|AES-?(?:128|192|256)?|RC4|RC2|ChaCha20[-_]?Poly1305|Camellia|SM4|Blowfish)\b", blob, re.I)
        if m:
            name = m.group(1).upper().replace("_", "-")
            if name == "DESEDE":
                name = "3DES"
            if "CHACHA" in name:
                return "ChaCha20-Poly1305", "symmetric AEAD cipher identified in snippet"
            return name, "symmetric algorithm read from snippet"
        return f.algorithm, "symmetric family, exact primitive unresolved"

    if fam == "ASYM":
        m = re.search(r"\b(ECDSA|ECDH|Ed25519|Ed448|RSA|DSA|ElGamal|DH)\b", blob, re.I)
        if m:
            name = m.group(1)
            bits = re.search(r"(?:keysize|initialize|length)\D{0,12}(\d{3,4})", blob, re.I)
            if name.upper() in ("RSA", "DSA") and bits:
                return f"{name.upper()}-{bits.group(1)}", "asymmetric primitive and key size read from snippet"
            if name.upper() == "EC" and bits:
                return f"EC-{bits.group(1)}", "elliptic curve key size read from snippet"
            return name, "asymmetric primitive read from snippet"
        return f.algorithm, "asymmetric family, exact primitive unresolved"

    if fam == "HASH":
        m = re.search(r"\b(SHA-?(?:1|224|256|384|512|3-\d{3})|SHA3-\d{3}|MD5|BLAKE2[bs]?|BLAKE3|RIPEMD-?160|SM3)\b", blob, re.I)
        if m:
            return m.group(1).upper().replace("SHA3", "SHA3-"), "hash function read from snippet"
        return f.algorithm, "hash family, exact function unresolved"

    if fam == "TLS":
        m = re.search(r"\b(TLSv?1(?:\.[0-3])?|SSLv?[23](?:\.[0-3])?)\b", blob, re.I)
        if m:
            return m.group(1).upper(), "transport protocol read from snippet"
        return f.algorithm, "transport-security family"

    if fam == "JWT":
        m = re.search(r"\b(HS|RS|ES|PS)(256|384|512)\b", blob)
        if m:
            return f"{m.group(1).upper()}{m.group(2)}", "JWT signing algorithm read from snippet"
        return "JWT", "JWT family, signing algorithm unresolved"

    if f.source == "syft":
        return f.extra.get("library", f.algorithm), "SBOM component name"
    return f.algorithm, "no refinement available"


def assess_risk(f: Finding, usage: str, key_mgmt: str) -> Tuple[str, str]:
    """Qualitative risk for this finding, independent of the Mosca score."""
    blob = f"{f.snippet}\n{f.context}".lower()
    levels: List[str] = []
    reasons: List[str] = []

    for needle, level in _BROKEN.items():
        if needle in blob:
            levels.append(level)
            reasons.append(f"{needle} is {level}")
            break

    if re.search(r"/(ecb|cbc|ctr|ofb|cfb)\b", blob):
        if "ecb" in blob:
            levels.append("high")
            reasons.append("ECB mode leaks plaintext structure")
        else:
            levels.append("low")
            reasons.append("unauthenticated-or-legacy block mode")

    if re.search(r"/(gcm|chacha20[-_]poly1305|eax|ccm|siv)\b", blob):
        levels.append("low")
        reasons.append("authenticated encryption mode")

    bits = _WEAK_RSA_BITS.search(blob)
    if bits:
        levels.append("critical")
        reasons.append(f"{bits.group(1)}-bit key length")

    if key_mgmt == "hardcoded":
        levels.append("critical")
        reasons.append("credential committed in source")
    elif key_mgmt == "env-var":
        levels.append("low")
        reasons.append("credential sourced from environment")
    elif key_mgmt in ("kms", "hsm"):
        levels.append("low")
        reasons.append(f"key held in {key_mgmt}")

    if usage in ("key-derivation", "hashing") and not levels:
        levels.append("info")
        reasons.append("primitive used as intended")
    if f.source == "syft":
        levels.append("info")
        reasons.append("library presence is informational")

    if not levels:
        levels.append("medium")
        reasons.append("crypto use present without sufficient context to clear it")

    return _worst(*levels), "; ".join(reasons)


# Semgrep leaves metavariable names in `metadata` verbatim. Match only the
# dollar-prefixed form and the explicit "not resolvable" markers - a bare
# uppercase token like "AES" or "RSA" is a legitimate value and must survive.
_PLACEHOLDER = re.compile(r"^\$[A-Z_][A-Z_0-9]*$")


def _is_placeholder(value: str) -> bool:
    v = (value or "").strip()
    return bool(_PLACEHOLDER.match(v)) or v in ("", "...", "UNKNOWN", "MULTI")


def enrich(f: Finding) -> Finding:
    """Populate usage / key_mgmt / risk / refined algorithm on one finding."""
    blob = f"{f.snippet}\n{f.context}"

    # Prefer the precise match over the wider context window: a context that
    # spans two unrelated crypto blocks would otherwise let the wrong one win.
    prior = f.algorithm_family if f.algorithm_family not in ("UNKNOWN", "MULTI") else None
    sniffed, fam = sniff(f.snippet, family=prior)
    if not sniffed:
        sniffed, fam = sniff(f"{f.snippet}\n{f.context}", family=prior)
    if not sniffed and prior is None:
        sniffed, fam = sniff(f.context)

    if sniffed:
        f.algorithm = sniffed
        f.algorithm_family = fam
        algo_why = f"sniffed '{sniffed}' from matched text"
    elif _is_placeholder(f.algorithm):
        # Nothing recognisable in the text and static analysis gave us a
        # metavariable name. Saying "UNKNOWN" is honest; emitting "$ALG" is not.
        f.algorithm = "UNKNOWN"
        algo_why = "no primitive identifiable in snippet; static rule gave a metavariable only"
    else:
        f.algorithm, algo_why = refine_algorithm(f)

    if f.algorithm_family in ("UNKNOWN", "MULTI"):
        f.algorithm_family = infer_family(f.algorithm, f.rule_id)

    f.usage, usage_why = classify_usage(f)
    f.key_mgmt, km_why = classify_key_mgmt(f)
    f.risk, risk_why = assess_risk(f, f.usage, f.key_mgmt)

    f.enrichment_source = "heuristic"
    f.extra = dict(f.extra or {})
    f.extra["enrichment_rule"] = {
        "algorithm": algo_why,
        "usage": usage_why,
        "key_mgmt": km_why,
        "risk": risk_why,
    }
    return f


def enrich_all(findings: List[Finding]) -> List[Finding]:
    for f in findings:
        try:
            enrich(f)
        except Exception as exc:  # enrichment must never break a scan
            log.warning("enrichment failed for %s:%s: %s", f.file, f.line, exc)
            f.enrichment_source = "error"
    return findings
