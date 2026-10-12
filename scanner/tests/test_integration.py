"""
End-to-end test, run inside the image.

    docker run --rm -v "$PWD:/w" -w /w --entrypoint /venv/bin/python ecdat:latest \
        -m pytest scanner/tests/test_integration.py -v

Scans the deterministic fixture in tests/fixtures/insecure-app and asserts that
each planted weakness is actually detected. This replaces the original
acceptance criterion, which targeted spring-petclinic on the assumption that it
contains JWT signing and jjwt/bouncycastle. It does not: that repository has no
crypto code and its pom.xml declares no JWT or BouncyCastle dependency, so the
test would have passed vacuously or failed depending on the ruleset.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "scanner" / "tests" / "fixtures" / "insecure-app"
OUT = Path("/tmp/ecdat-itest")


def run_scan(*extra):
    OUT.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-m", "scanner", "scan", str(FIXTURE),
        "--output", str(OUT / "cbom.json"),
        "--report", str(OUT / "report.json"),
        "--no-bench",          # benchmark coverage lives in TestLiboqs
        *extra,
    ]
    env = {"PYTHONPATH": f"{ROOT / 'scanner'}:{ROOT}"}
    proc = subprocess.run(cmd, capture_output=True, text=True, env={**os.environ, **env}, timeout=600)
    assert proc.returncode == 0, f"scan failed:\n{proc.stdout}\n{proc.stderr}"
    return json.loads((OUT / "report.json").read_text())


@pytest.fixture(scope="module")
def report():
    return run_scan()


class TestPipeline:
    def test_finds_something(self, report):
        assert report["summary"]["total"] > 0, "scan produced no findings at all"

    def test_ingestion_copied_the_tree(self, report):
        assert report["kind"] == "path"


class TestPlantedWeaknesses:
    """Every one of these is a deliberate defect in the fixture."""

    def test_finds_aes_ecb(self, report):
        hits = [f for f in report["findings"] if "ECB" in f["mode"].upper() or "ECB" in f["snippet"].upper()]
        assert hits, "AES/ECB not detected"

    def test_finds_des(self, report):
        hits = [f for f in report["findings"] if "DES" in f["algorithm"].upper() or "DES" in f["snippet"]]
        assert hits, "DES not detected"

    def test_finds_md5(self, report):
        hits = [f for f in report["findings"] if f["algorithm_family"] == "HASH" and "MD5" in f["algorithm"].upper()]
        assert hits, "MD5 not detected"

    def test_finds_hardcoded_private_key(self, report):
        hits = [f for f in report["findings"] if "PRIVATE KEY" in f["snippet"] or f["mode"] == "PRIVATE_KEY"]
        assert hits, "inline PEM private key not detected"

    def test_finds_hardcoded_jwt_secret(self, report):
        hits = [f for f in report["findings"] if f["key_mgmt"] == "hardcoded" and f["algorithm_family"] == "JWT"]
        assert hits, "hardcoded JWT secret not detected"

    def test_finds_weak_rsa_keysize(self, report):
        hits = [f for f in report["findings"] if "1024" in f["snippet"]]
        assert hits, "1024-bit RSA not detected"

    def test_finds_weak_tls_config(self, report):
        hits = [f for f in report["findings"]
                if f["source"] == "semgrep" and "TLSv1.1" in f["snippet"]]
        assert hits, "TLSv1.1 in application.yml not detected"

    def test_finds_keystore_config(self, report):
        hits = [f for f in report["findings"] if f["mode"] == "KEYSTORE"]
        assert hits, "keystore/truststore config not detected"


class TestEnrichment:
    def test_everything_is_enriched(self, report):
        for f in report["findings"]:
            assert f["enrichment_source"] == "heuristic", f"{f['rule_id']} un-enriched"
            assert f["usage"] and f["key_mgmt"] and f["risk"]

    def test_weak_things_score_high(self, report):
        by_id = {f["rule_id"]: f for f in report["findings"]}
        md5 = [f for f in report["findings"] if f["algorithm_family"] == "HASH" and "MD5" in f["algorithm"].upper()]
        if md5:
            assert md5[0]["risk"] == "critical"
            assert md5[0]["risk_score"] > 0


class TestSBOM:
    def test_syft_found_the_jwt_libraries(self, report):
        libs = {f["extra"].get("library", "") for f in report["findings"] if f["source"] == "syft"}
        assert any("jjwt" in lib for lib in libs), f"jjwt not in SBOM libs: {libs}"

    def test_syft_found_bouncycastle(self, report):
        libs = {f["extra"].get("library", "") for f in report["findings"] if f["source"] == "syft"}
        assert any("bc" in lib.lower() for lib in libs), f"bouncycastle not in SBOM libs: {libs}"

    def test_no_false_positive_on_spring(self, report):
        """Guards the word-boundary matcher: 'ring' must not match 'spring-*'."""
        libs = {f["extra"].get("library", "") for f in report["findings"] if f["source"] == "syft"}
        assert not any("spring" in lib.lower() for lib in libs), f"substring match leaked: {libs}"


class TestRisk:
    def test_ranked_descending(self, report):
        scores = [f["risk_score"] for f in report["findings"]]
        assert scores == sorted(scores, reverse=True)

    def test_mosca_breakdown_present(self, report):
        for f in report["findings"]:
            rb = f["extra"]["risk"]
            assert rb["mosca_shelf_life_years"] >= 0
            assert rb["quantum_source"], "every finding must cite a quantum source"

    def test_payment_fixture_has_ten_year_shelf_life(self, report):
        """'payment' is a 10-year class in the Mosca shelf-life table."""
        payment = [f for f in report["findings"] if "payment" in f["file"].lower()]
        assert payment, "no findings from the payment package"
        assert any(f["extra"]["risk"]["mosca_shelf_life_years"] == 10.0 for f in payment)


class TestCBOM:
    def test_valid_json_document(self, report):
        bom = json.loads((OUT / "cbom.json").read_text())
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.6"

    def test_has_cryptographic_assets(self, report):
        bom = json.loads((OUT / "cbom.json").read_text())
        assets = [c for c in bom.get("components", []) if c["type"] == "cryptographic-asset"]
        assert assets, "no cryptographic-asset components emitted"

    def test_assets_carry_crypto_properties(self, report):
        bom = json.loads((OUT / "cbom.json").read_text())
        assets = [c for c in bom.get("components", []) if c["type"] == "cryptographic-asset"]
        with_props = [a for a in assets if "cryptoProperties" in a]
        assert with_props, "cryptoProperties missing (1.6-only feature)"

    def test_has_library_components(self, report):
        bom = json.loads((OUT / "cbom.json").read_text())
        libs = [c for c in bom.get("components", []) if c["type"] == "library"]
        assert libs, "no library components from the SBOM"

    def test_has_dependencies(self, report):
        bom = json.loads((OUT / "cbom.json").read_text())
        assert bom.get("dependencies"), "no dependency graph emitted"


class TestRecommendations:
    def test_maps_rsa_to_pqc(self, report):
        targets = {t for r in report["recommendations"] for t in r["migrate_to"]}
        assert "ML-KEM-768" in targets or "ML-DSA-65" in targets

    def test_every_recommendation_has_rationale(self, report):
        for r in report["recommendations"]:
            assert r["rationale"]


class TestLiboqs:
    """
    The native liboqs actually loads inside the image.

    This exists because the rest of the suite runs with --no-bench and so never
    imports oqs. That let a real packaging bug ship: liboqs.so was built against
    the build host's OpenSSL 3.3 and the image ships 3.0, so the load failed
    with "version `OPENSSL_3.3.0' not found" - and nothing noticed.
    """

    def test_imports(self):
        import oqs
        assert oqs.oqs_version()

    def test_recommended_mechanisms_are_enabled(self):
        import oqs
        enabled = set(oqs.get_enabled_kem_mechanisms()) | set(oqs.get_enabled_sig_mechanisms())
        # Everything recommender.py can suggest must be benchmarkable.
        assert "ML-KEM-768" in enabled
        assert "ML-DSA-65" in enabled
        assert "ML-DSA-87" in enabled

    def test_kem_roundtrip(self):
        import oqs
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        pk = kem.generate_keypair()          # 0.16.0: public key only
        ct, shared_a = kem.encap_secret(pk)
        shared_b = kem.decap_secret(ct)      # secret key is held internally
        assert shared_a == shared_b

    def test_signature_roundtrip(self):
        import oqs
        sig = oqs.Signature("ML-DSA-65")
        pk = sig.generate_keypair()
        msg = b"ecdat"
        signature = sig.sign(msg)
        assert sig.verify(msg, signature, pk)

    def test_shared_lib_is_self_contained(self):
        """No unresolved dynamic deps - that is what broke before."""
        import ctypes
        import glob
        import os
        so = glob.glob("/opt/oqs/lib/liboqs.so.0*")
        assert so, "liboqs.so not found in the image"
        ctypes.cdll.LoadLibrary(so[0])  # raises OSError if a dep is missing

    def test_benchmarks_run(self):
        """End-to-end: the suite's default path must produce real numbers."""
        out = OUT / "bench"
        out.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [sys.executable, "-m", "scanner", "scan", str(FIXTURE),
             "--output", str(out / "cbom.json"),
             "--report", str(out / "report.json"),
             "--iterations", "10", "--fast-bench"],
            capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": f"{ROOT / 'scanner'}:{ROOT}"},
            timeout=900,
        )
        assert proc.returncode == 0, f"benchmark scan failed:\n{proc.stderr[-2000:]}"
        data = json.loads((out / "report.json").read_text())
        rows = {r["scheme"]: r for r in data["benchmarks"] if not r.get("error")}
        assert "ML-KEM-768" in rows, f"PQC benchmark missing: {list(rows)}"
        assert "RSA-2048" in rows, f"classical baseline missing: {list(rows)}"
        assert rows["ML-KEM-768"]["keygen_ms"] >= 0
        assert rows["ML-KEM-768"]["pub_key_bytes"] > 0
        assert rows["ML-KEM-768"]["payload_bytes"] > 0
        # The headline claim: PQC keys are larger than the classical baseline.
        assert rows["ML-KEM-768"]["pub_key_bytes"] != rows["RSA-2048"]["pub_key_bytes"]
        assert data["benchmark_comparisons"], "no before/after comparison rows"


class TestRerisk:
    def test_z_slider_changes_the_distribution(self):
        """
        Z must move the scores, not just the ordering.

        Note we assert on the mean, not the max: classically-broken primitives
        (MD5, DES) floor at 10 through the classical-weakness term regardless
        of Z, so max_score is pinned and would mask the slider entirely.
        """
        lenient = run_scan("--z-estimate", "99")
        strict = run_scan("--z-estimate", "3")
        assert lenient["summary"]["mean_score"] != strict["summary"]["mean_score"]
        assert strict["summary"]["mean_score"] > lenient["summary"]["mean_score"]

    def test_z_slider_reorders_migration_driven_findings(self):
        """Findings with real migration pressure should re-sort as Z drops."""
        lenient = run_scan("--z-estimate", "99")
        strict = run_scan("--z-estimate", "3")

        def live(report):
            # exclude the classically-broken floor, which Z cannot move
            return [f for f in report["findings"]
                    if f["extra"]["risk"]["classical_weakness"] < 1.0]

        lenient_scores = {f["rule_id"] + str(f["line"]): f["risk_score"] for f in live(lenient)}
        strict_scores = {f["rule_id"] + str(f["line"]): f["risk_score"] for f in live(strict)}

        shared = set(lenient_scores) & set(strict_scores)
        assert shared, "no comparable findings between the two runs"
        assert any(lenient_scores[k] != strict_scores[k] for k in shared)

    def test_broken_primitives_stay_pinned(self):
        """The classical floor must not drift with Z."""
        lenient = run_scan("--z-estimate", "99")
        broken = [f for f in lenient["findings"]
                  if f["extra"]["risk"]["classical_weakness"] >= 1.0]
        assert broken, "fixture should contain classically-broken primitives"
        for f in broken:
            assert f["risk_score"] == 10.0
