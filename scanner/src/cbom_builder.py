"""
ECDAT Scanner - CycloneDX CBOM assembly.

Emits a CycloneDX 1.6 document where:
  * each detected cryptographic primitive becomes a CRYPTOGRAPHIC_ASSET
  * each crypto library from the Syft SBOM becomes a LIBRARY component
  * Dependency edges express "library implements/uses asset", plus the
    asset -> replacement edge from the recommender

cryptoProperties (asset_type / algorithmProperties / oid /
nistQuantumSecurityLevel) is the part that makes this a real CBOM rather
than a relabelled inventory - it is CycloneDX 1.6 only.
"""

import datetime
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyclonedx.model import Property, Tool
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentScope, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoMode,
    CryptoPadding,
    CryptoPrimitive,
    CryptoProperties,
    ProtocolProperties,
    ProtocolPropertiesType,
    RelatedCryptoMaterialProperties,
    RelatedCryptoMaterialType,
)

from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.output.xml import XmlV1Dot6

from detection import Finding
from utils import log

TOOL_NAME = "ECDAT"
TOOL_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Enum mapping: our coarse family -> CycloneDX vocabulary
# ---------------------------------------------------------------------------
_PRIMITIVE_BY_FAMILY = {
    "SYM": CryptoPrimitive.BLOCK_CIPHER,
    "ASYM": CryptoPrimitive.PKE,
    "HASH": CryptoPrimitive.HASH,
    "KDF": CryptoPrimitive.KDF,
    "JWT": CryptoPrimitive.SIGNATURE,
    "TLS": CryptoPrimitive.KEY_AGREE,
    "KEM": CryptoPrimitive.KEM,
    "MULTI": CryptoPrimitive.OTHER,
    "UNKNOWN": CryptoPrimitive.UNKNOWN,
}

_MODE_BY_NAME = {
    "ECB": CryptoMode.ECB, "CBC": CryptoMode.CBC, "CTR": CryptoMode.CTR,
    "CFB": CryptoMode.CFB, "OFB": CryptoMode.OFB, "GCM": CryptoMode.GCM,
    "CCM": CryptoMode.CCM,
}

_PADDING_BY_NAME = {
    "PKCS5": CryptoPadding.PKCS5, "PKCS7": CryptoPadding.PKCS7,
    "PKCS1V15": CryptoPadding.PKCS1V15, "OAEP": CryptoPadding.OAEP,
    "RAW": CryptoPadding.RAW,
}

_FUNCTION_BY_USAGE = {
    "encryption": CryptoFunction.ENCRYPT, "decryption": CryptoFunction.DECRYPT,
    "signing": CryptoFunction.SIGN, "verification": CryptoFunction.VERIFY,
    "hashing": CryptoFunction.DIGEST, "key-derivation": CryptoFunction.KEYDERIVE,
    "key-exchange": CryptoFunction.ENCAPSULATE, "key-management": CryptoFunction.GENERATE,
    "randomness": CryptoFunction.GENERATE, "transport-security": CryptoFunction.OTHER,
    "library": CryptoFunction.OTHER, "unknown": CryptoFunction.UNKNOWN,
}

_MATERIAL_BY_KEYMGMT = {
    "hardcoded": RelatedCryptoMaterialType.PRIVATE_KEY,
    "keystore": RelatedCryptoMaterialType.KEY,
    "kms": RelatedCryptoMaterialType.KEY,
    "hsm": RelatedCryptoMaterialType.KEY,
    "env-var": RelatedCryptoMaterialType.SECRET_KEY,
    "derived": RelatedCryptoMaterialType.SEED,
    "ephemeral": RelatedCryptoMaterialType.KEY,
}

# NIST SP 800-57 security levels keyed off our normalised quantum score.
def _nist_level(quantum_normalized: float) -> Optional[int]:
    if quantum_normalized >= 8.0:
        return 5
    if quantum_normalized >= 6.0:
        return 4
    if quantum_normalized >= 4.0:
        return 3
    if quantum_normalized >= 2.0:
        return 2
    if quantum_normalized >= 0.5:
        return 1
    return None


def _slug(text: str) -> str:
    return hashlib.sha1((text or "x").encode("utf-8")).hexdigest()[:16]


def _crypto_properties(f: Finding) -> CryptoProperties:
    """Build the 1.6 cryptoProperties block for one finding."""
    fam = f.algorithm_family
    risk = (f.extra or {}).get("risk", {}) or {}

    alg = AlgorithmProperties(
        primitive=_PRIMITIVE_BY_FAMILY.get(fam, CryptoPrimitive.UNKNOWN),
        parameter_set_identifier=f.algorithm or None,
        mode=_MODE_BY_NAME.get((f.mode or "").upper().replace("/", "")),
        padding=_PADDING_BY_NAME.get((f.mode or "").upper()),
    )

    fn = _FUNCTION_BY_USAGE.get(f.usage)
    if fn:
        alg.crypto_functions = [fn]

    lvl = _nist_level(float(risk.get("quantum_normalized", 0.0) or 0.0))
    if lvl:
        alg.nist_quantum_security_level = lvl

    crypto = CryptoProperties(
        asset_type=CryptoAssetType.ALGORITHM,
        algorithm_properties=alg,
    )

    # Key material block
    mat = _MATERIAL_BY_KEYMGMT.get(f.key_mgmt)
    if mat and fam in ("SYM", "ASYM", "KEM", "JWT"):
        crypto.related_crypto_material_properties = RelatedCryptoMaterialProperties(
            type=mat,
            id=Path(f.file).name if f.file else None,
        )

    # TLS gets a protocol block instead of a bare algorithm
    if fam == "TLS":
        crypto.asset_type = CryptoAssetType.PROTOCOL
        crypto.protocol_properties = ProtocolProperties(type=ProtocolPropertiesType.TLS)

    return crypto


# Publication that defines each primitive. CycloneDX cryptographic-asset
# components carry their defining spec in `version`, so "AES" reads as
# FIPS 197 rather than an arbitrary synthetic string.
_SPEC_REFERENCE = {
    "AES": "FIPS 197", "AES-GCM": "NIST SP 800-38D", "AES-CBC": "NIST SP 800-38A",
    "DES": "FIPS 46-3", "3DES": "NIST SP 800-67",
    "RC4": "RFC 6229", "RC2": "RFC 2268", "BLOWFISH": "RFC 4493",
    "CHACHA20-POLY1305": "RFC 8439", "CAMELLIA": "RFC 3713",
    "RSA": "RFC 8017", "RSA-PSS": "RFC 8017",
    "ECDSA": "FIPS 186-5", "ECDH": "SP 800-56A", "DSA": "FIPS 186-5",
    "ED25519": "RFC 8032", "ED448": "RFC 8032", "X25519": "RFC 7748",
    "MD2": "RFC 1319", "MD4": "RFC 1320", "MD5": "RFC 1321",
    "SHA-1": "FIPS 180-4", "SHA-224": "FIPS 180-4", "SHA-256": "FIPS 180-4",
    "SHA-384": "FIPS 180-4", "SHA-512": "FIPS 180-4", "SHA3-256": "FIPS 202",
    "SHA3-512": "FIPS 202", "BLAKE2B": "RFC 7693", "BLAKE3": "BLAKE3 spec",
    "ML-KEM-768": "FIPS 203", "ML-DSA-65": "FIPS 204", "ML-DSA-87": "FIPS 204",
    "TLSV1.1": "RFC 4346", "TLSV1.2": "RFC 5246", "TLSV1.3": "RFC 8446",
    "SSLV3": "RFC 6101", "SSLV2": "RFC 6176",
    "HS256": "RFC 7518", "RS256": "RFC 7518", "ES256": "RFC 7518", "PS256": "RFC 7518",
    "HS384": "RFC 7518", "RS384": "RFC 7518", "HS512": "RFC 7518", "RS512": "RFC 7518",
    "BCRYPT": "Provos-Mazieres", "HKDF": "RFC 5869", "PBKDF2": "RFC 8018",
    "SCRYPT": "RFC 7914", "ARGON2": "RFC 9106",
}


def _spec_for(algorithm: str) -> Optional[str]:
    """Best-matching publication for a primitive name."""
    a = (algorithm or "").upper()
    if a in _SPEC_REFERENCE:
        return _SPEC_REFERENCE[a]
    # Longest key first so "AES-256" does not match a bare "AES" rule first,
    # and "SHA3-256" is not swallowed by "SHA-256".
    for key in sorted(_SPEC_REFERENCE, key=len, reverse=True):
        if key in a:
            return _SPEC_REFERENCE[key]
    return None


def _asset_component(f: Finding) -> Component:
    """One CRYPTOGRAPHIC_ASSET per finding."""
    name = f.algorithm or "unknown-primitive"

    return Component(
        name=name,
        bom_ref=f"crypto/{_slug(f'{f.file}:{f.line}:{f.rule_id}')}",
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        version=_spec_for(name),
        crypto_properties=_crypto_properties(f),
        description=(
            f"{f.usage} via {f.rule_id}; key management: {f.key_mgmt}; "
            f"heuristic risk: {f.risk}"
        ),
        properties=[
            Property(name="ecdat:file", value=f.file),
            Property(name="ecdat:line", value=str(f.line)),
            Property(name="ecdat:rule-id", value=f.rule_id),
            Property(name="ecdat:source", value=f.source),
            Property(name="ecdat:algorithm-family", value=f.algorithm_family),
            Property(name="ecdat:usage", value=f.usage),
            Property(name="ecdat:key-management", value=f.key_mgmt),
            Property(name="ecdat:heuristic-risk", value=f.risk),
            Property(name="ecdat:cwe", value=f.cwe or "unknown"),
            Property(name="ecdat:risk-score", value=f"{f.risk_score:.3f}"),
        ],
    )


def _library_component(f: Finding) -> Optional[Component]:
    """One LIBRARY component per Syft crypto-library finding."""
    if f.source != "syft":
        return None
    name = (f.extra or {}).get("library") or f.algorithm
    version = (f.extra or {}).get("version", "unknown")

    return Component(
        name=name,
        version=version or None,
        bom_ref=f"lib/{_slug(f'{name}@{version}')}",
        type=ComponentType.LIBRARY,
        description=f"crypto library present in target (type={(f.extra or {}).get('package_type', '')})",
        scope=ComponentScope.REQUIRED,
        properties=[
            Property(name="ecdat:algorithm-family", value=f.algorithm_family),
            Property(name="ecdat:detected-by", value="syft"),
        ],
    )


def build(
    findings: List[Finding],
    recommendations: Optional[List[Dict[str, Any]]] = None,
    benchmarks: Optional[List[Dict[str, Any]]] = None,
    scan_meta: Optional[Dict[str, Any]] = None,
) -> Bom:
    """Assemble the CycloneDX 1.6 BOM."""
    bom = Bom()
    bom.metadata.timestamp = datetime.datetime.now(datetime.timezone.utc)
    # bom.metadata.tools is a SortedSet[Tool], and its constructor has already
    # seeded it with ThisTool. Adding a Component there raises
    # "'<' not supported between instances of 'Component' and 'Tool'" - the
    # library has a TODO acknowledging CDX 1.5+ should allow components here,
    # but 7.6.2 still types it as Tool only. Use Tool.
    bom.metadata.tools.add(Tool(name=TOOL_NAME, version=TOOL_VERSION, vendor="ecdat"))

    meta = scan_meta or {}
    if meta.get("target"):
        bom.metadata.component = Component(
            name=str(meta["target"])[:180], type=ComponentType.APPLICATION, bom_ref="ecdat-scan-target"
        )

    assets: List[Component] = []
    libraries: Dict[str, Component] = {}
    asset_deps: Dict[str, List[str]] = {}
    lib_deps: Dict[str, List[str]] = {}

    for f in findings:
        if f.source == "syft":
            lib = _library_component(f)
            # Key on str(bom_ref): BomRef defines no __eq__/__hash__ of its own,
            # so keying on the object makes a freshly built ref unequal to the
            # stored one and silently drops every library->asset edge.
            lib_key = str(lib.bom_ref) if lib else None
            if lib and lib_key not in libraries:
                libraries[lib_key] = lib
                lib_deps.setdefault(lib_key, [])
            continue
        asset = _asset_component(f)
        assets.append(asset)
        asset_deps.setdefault(str(asset.bom_ref), [])

    # library -> asset edges: "this library provides/is used with that primitive"
    for f in findings:
        if f.source != "syft":
            continue
        lib = _library_component(f)
        lib_key = str(lib.bom_ref) if lib else None
        if not lib or lib_key not in libraries:
            continue
        for other in findings:
            if other.source == "syft" or other.algorithm_family != f.algorithm_family:
                continue
            ref = f"crypto/{_slug(f'{other.file}:{other.line}:{other.rule_id}')}"
            if ref not in asset_deps.get(ref, []):
                lib_deps.setdefault(lib_key, []).append(ref)

    # NOTE: Component.bom_ref is a BomRef object, not a str (it is not even a
    # str subclass), so by_ref must be keyed on str(ref) or every lookup by the
    # string refs built above silently misses and the graph comes out empty.
    by_ref: Dict[str, Component] = {}
    for comp in libraries.values():
        bom.components.add(comp)
        by_ref[str(comp.bom_ref)] = comp
    for comp in assets:
        bom.components.add(comp)
        by_ref[str(comp.bom_ref)] = comp

    # recommendation edges: asset -> replacement
    rec_by_key = {r.get("from_key"): r for r in (recommendations or [])}
    for f in findings:
        if f.source == "syft":
            continue
        ref = f"crypto/{_slug(f'{f.file}:{f.line}:{f.rule_id}')}"
        rec = rec_by_key.get(_rec_key_for(f))
        if not rec:
            continue
        for repl in rec.get("migrate_to", []):
            rref = f"pqc/{_slug(repl)}"
            if rref not in asset_deps.get(ref, []):
                asset_deps.setdefault(ref, []).append(rref)
            if rref not in by_ref:
                pqc_component = Component(
                    name=repl, bom_ref=rref, type=ComponentType.CRYPTOGRAPHIC_ASSET,
                    version=_spec_for(repl),
                    description=rec.get("rationale", ""),
                    crypto_properties=CryptoProperties(
                        asset_type=CryptoAssetType.ALGORITHM,
                        algorithm_properties=AlgorithmProperties(
                            primitive=CryptoPrimitive.KEM if "KEM" in repl else CryptoPrimitive.SIGNATURE,
                            parameter_set_identifier=repl,
                            nist_quantum_security_level=3 if ("768" in repl or "65" in repl) else 5,
                        ),
                    ),
                )
                bom.components.add(pqc_component)
                by_ref[str(pqc_component.bom_ref)] = pqc_component

    # benchmark payload rides along as a property on the metadata component
    if benchmarks:
        bom.metadata.properties.add(
            Property(name="ecdat:benchmarks", value=f"{len(benchmarks)} comparison row(s) generated")
        )

    # Register the dependency graph. register_dependency() takes Dependable
    # objects (anything with .bom_ref) and recurses into the targets itself, so
    # we hand it components rather than pre-built Dependency objects.
    edge_count = 0
    for ref, targets in {**asset_deps, **lib_deps}.items():
        source = by_ref.get(ref)
        if source is None:
            continue
        edges = [by_ref[t] for t in sorted(set(targets)) if t in by_ref]
        if not edges:
            continue
        bom.register_dependency(source, edges)
        edge_count += len(edges)

    log.info("cbom: %d asset(s), %d librar(ies), %d dependency edge(s)",
             len(assets), len(libraries), edge_count)
    return bom


def _rec_key_for(f: Finding) -> str:
    from recommender import _key
    return _key(f.algorithm, f.algorithm_family) or ""


def serialize(bom: Bom, fmt: str = "json") -> str:
    """Render the BOM as CycloneDX 1.6 JSON or XML.

    We bind the concrete 1.6 outputters directly rather than going through a
    schema/factory indirection: this tool only ever emits 1.6, and the explicit
    import makes that a compile-time fact rather than a runtime lookup.
    """
    outputter = JsonV1Dot6(bom) if fmt.lower() == "json" else XmlV1Dot6(bom)
    return outputter.output_as_string(indent=2)
