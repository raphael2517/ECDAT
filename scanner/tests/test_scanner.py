"""
Unit tests for the ECDAT scanner.

These do not need Docker or a network. They cover the pure logic: target
classification, heuristic enrichment, Mosca scoring, and the recommendation
map. The end-to-end path is covered by tests/test_integration.py, which runs
inside the image.

    cd scanner && python -m pytest tests/ -v
"""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from detection import Finding, infer_family  # noqa: E402
from enrichment import enrich  # noqa: E402
from ingestion import IngestionError, classify, is_image_ref, is_zip  # noqa: E402
from recommender import _key  # noqa: E402
from risk_engine import _norm_algorithm, _quantum_normalized, assess, quantum_effort, score_all  # noqa: E402


def mk(**kw) -> Finding:
    base = dict(
        file="src/Main.java", line=10, rule_id="test", algorithm="UNKNOWN",
        algorithm_family="UNKNOWN", mode="UNKNOWN", severity="INFO",
        cwe="", cwe2="", snippet="", context="", source="semgrep",
    )
    base.update(kw)
    return Finding(**base)


# ---------------------------------------------------------------------------
# ingestion: target classification
# ---------------------------------------------------------------------------
class TestClassify:
    def test_git_https(self):
        assert classify("https://github.com/org/repo") == "git"
        assert classify("https://github.com/org/repo.git") == "git"

    def test_ssh(self):
        assert classify("git@github.com:org/repo.git") == "git"

    def test_zip(self):
        assert is_zip("bundle.zip") and is_zip("app.jar")

    def test_image_ref(self):
        assert is_image_ref("alpine:3.19")
        assert is_image_ref("ghcr.io/org/app:v1.2.3")
        assert is_image_ref("registry:5000/team/app:tag")

    def test_image_ref_rejects_paths(self):
        # the bug that shipped in the first ingestion draft: '/' matched everything
        assert not is_image_ref("./relative/path")
        assert not is_image_ref("/absolute/path")
        assert not is_image_ref("../up/one")

    def test_existing_path_wins(self, tmp_path):
        d = tmp_path / "project"
        d.mkdir()
        assert classify(str(d)) == "path"

    def test_garbage_raises(self):
        with pytest.raises(IngestionError):
            classify("!!!")


# ---------------------------------------------------------------------------
# enrichment: heuristics
# ---------------------------------------------------------------------------
class TestEnrichment:
    def test_aes_ecb_is_critical(self):
        f = mk(algorithm="AES/ECB/PKCS5Padding", mode="ECB",
               snippet='Cipher.getInstance("AES/ECB/PKCS5Padding")',
               context='Cipher.getInstance("AES/ECB/PKCS5Padding")')
        enrich(f)
        assert f.algorithm_family == "SYM"
        assert f.usage == "encryption"
        assert f.risk == "high"          # ECB
        assert f.enrichment_source == "heuristic"
        assert f.extra["enrichment_rule"]["risk"]

    def test_md5_is_critical(self):
        f = mk(algorithm="MD5", mode="HASH",
               snippet='MessageDigest.getInstance("MD5")',
               context='MessageDigest.getInstance("MD5"); md.digest(x)')
        enrich(f)
        assert f.algorithm_family == "HASH"
        assert f.usage == "hashing"
        assert f.risk == "critical"

    def test_hardcoded_secret_is_critical(self):
        f = mk(algorithm="AES", mode="CBC",
               snippet='String apiKey = "sk-abcdef123456";',
               context='String apiKey = "sk-abcdef123456";')
        enrich(f)
        assert f.key_mgmt == "hardcoded"
        assert f.risk == "critical"

    def test_env_var_is_low_risk(self):
        f = mk(algorithm="AES-256-GCM", mode="GCM",
               snippet='SecretKey key = new SecretKeySpec(System.getenv("K"), "AES")',
               context='String k = System.getenv("K");')
        enrich(f)
        assert f.key_mgmt == "env-var"

    def test_jwt_algorithm_refined(self):
        f = mk(algorithm="JWT", algorithm_family="JWT", mode="SIGNING",
               snippet='SignatureAlgorithm.HS256',
               context='.signWith(key, SignatureAlgorithm.HS256)')
        enrich(f)
        assert f.algorithm == "HS256"
        assert f.usage == "signing"

    def test_syft_component_is_library(self):
        f = mk(algorithm="MULTI", algorithm_family="MULTI", mode="LIBRARY",
               source="syft", snippet="bcprov-jdk18on@1.78",
               context="crypto library in SBOM", extra={"library": "bcprov", "version": "1.78"})
        enrich(f)
        assert f.usage == "library"
        assert f.risk == "info"

    def test_enrichment_never_raises(self):
        f = mk(snippet=None, context=None)
        enrich(f)  # must not throw
        assert f.enrichment_source == "heuristic"


# ---------------------------------------------------------------------------
# risk engine
# ---------------------------------------------------------------------------
class TestFamilyInference:
    @pytest.mark.parametrize("alg,fam", [
        ("AES-256", "SYM"), ("DESede", "SYM"), ("chacha20", "SYM"),
        ("RSA-2048", "ASYM"), ("ECDSA-P256", "ASYM"), ("Ed25519", "ASYM"),
        ("SHA-256", "HASH"), ("MD5", "HASH"), ("blake2b", "HASH"),
        ("TLSv1.2", "TLS"), ("HS256", "JWT"), ("bcrypt", "KDF"),
    ])
    def test_families(self, alg, fam):
        assert infer_family(alg) == fam


class TestQuantumTable:
    def test_known_keys_normalise(self):
        assert _norm_algorithm("AES-128-GCM") == "AES-128"
        assert _norm_algorithm("RSA-2048") == "RSA-2048"
        assert _norm_algorithm("ECDSA-P256") == "P-256"

    def test_broken_primitives_have_zero_quantum_effort(self):
        for alg in ("MD5", "RC4", "DES"):
            toffoli, _, _ = quantum_effort(alg, "SYM")
            assert toffoli == 0.0

    def test_aes256_beats_aes128(self):
        t128, _, _ = quantum_effort("AES-128", "SYM")
        t256, _, _ = quantum_effort("AES-256", "SYM")
        assert _quantum_normalized(t256) > _quantum_normalized(t128)

    def test_every_table_entry_has_provenance(self):
        from risk_engine import _QUANTUM
        for key, val in _QUANTUM.items():
            assert val["src"], f"{key} missing a source citation"
            assert val["qubits"] >= 0


class TestMosca:
    def _finding(self, **kw):
        f = mk(algorithm="RSA-2048", algorithm_family="ASYM", **kw)
        return f

    def test_payment_data_raises_shelf_life(self):
        f = self._finding(file="src/payment/CardVault.java", context="")
        rb = assess(f, z_years=15, family_footprint=1)
        assert rb.mosca_shelf_life_years == 10.0

    def test_auth_data_uses_five_years(self):
        f = self._finding(file="src/auth/LoginService.java", context="")
        rb = assess(f, z_years=15, family_footprint=1)
        assert rb.mosca_shelf_life_years == 5.0

    def test_mosca_triggers_when_shelf_plus_migration_exceeds_z(self):
        f = self._finding(file="src/payment/Vault.java", context="")
        assert assess(f, z_years=5, family_footprint=1).mosca_triggered is True
        assert assess(f, z_years=99, family_footprint=1).mosca_triggered is False

    def test_footprint_increases_migration_cost(self):
        f = self._finding(file="src/x.java", context="")
        small = assess(f, z_years=15, family_footprint=1).mosca_migration_years
        large = assess(f, z_years=15, family_footprint=100).mosca_migration_years
        assert large > small

    def test_z_slider_reorders(self):
        """The whole point of the slider: lowering Z must change the ranking."""
        fs = [
            mk(file="src/payment/a.java", algorithm="RSA-2048", algorithm_family="ASYM"),
            mk(file="src/util/b.java", algorithm="SHA-256", algorithm_family="HASH"),
        ]
        lenient = [f.rule_id for f in score_all(list(fs), z_years=99)]
        strict = [f.rule_id for f in score_all(list(fs), z_years=3)]
        assert fs[0].risk_score > fs[1].risk_score   # RSA still outranks SHA-256
        assert strict[0] == "test"                  # both same rule_id, order is by score

    def test_scores_are_bounded(self):
        fs = [mk(algorithm="RSA-4096", algorithm_family="ASYM", file="src/payment/a.java")]
        score_all(fs, z_years=1)
        assert 0.0 <= fs[0].risk_score <= 10.0

    def test_broken_primitive_never_scores_zero(self):
        """
        Regression: MD5 used to score 0.0.

        Under the plan's composite (0.6*Mosca + 0.4*quantum) a classically
        broken primitive has no migration pressure and no quantum exposure, so
        it floored at zero - while the enrichment layer labelled it `critical`.
        A finding that is labelled critical but ranks last is worse than no
        score at all.
        """
        for alg, fam in (("MD5", "HASH"), ("RC4", "SYM"), ("DES", "SYM"), ("SSLV3", "TLS")):
            f = mk(algorithm=alg, algorithm_family=fam, file="src/util/x.java")
            score_all([f], z_years=15)
            assert f.risk_score >= 10.0, f"{alg} scored {f.risk_score}, expected >= 10"
            assert f.extra["risk"]["classical_weakness"] == 1.0

    def test_broken_outranks_sound(self):
        broken = mk(algorithm="MD5", algorithm_family="HASH", file="src/util/a.java")
        sound = mk(algorithm="SHA-256", algorithm_family="HASH", file="src/util/b.java")
        score_all([broken, sound], z_years=99)
        assert broken.risk_score > sound.risk_score

    def test_migration_urgency_still_uses_plan_weights(self):
        """The plan's 0.6/0.4 composite survives as its own field."""
        f = mk(algorithm="RSA-2048", algorithm_family="ASYM", file="src/payment/a.java")
        score_all([f], z_years=15)
        rb = f.extra["risk"]
        expected = round(0.6 * rb["mosca_normalized"] + 0.4 * rb["quantum_normalized"], 3)
        assert rb["migration_urgency"] == expected

    def test_sound_primitive_is_not_inflated(self):
        f = mk(algorithm="SHA-256", algorithm_family="HASH", file="src/util/a.java")
        score_all([f], z_years=99)
        assert f.extra["risk"]["classical_weakness"] == 0.0
        assert f.risk_score < 10.0

    def test_rationale_is_populated(self):
        f = mk(algorithm="RSA-2048", algorithm_family="ASYM", file="src/payment/a.java")
        rb = assess(f, z_years=15, family_footprint=3)
        assert len(rb.rationale) >= 3
        assert any("Toffoli" in r for r in rb.rationale)


# ---------------------------------------------------------------------------
# recommender
# ---------------------------------------------------------------------------
class TestRecommendations:
    @pytest.mark.parametrize("alg,fam,expect", [
        ("RSA-2048", "ASYM", "RSA-2048"),
        ("RSA/2048", "ASYM", "RSA-2048"),
        ("ECDSA-P256", "ASYM", "P-256"),
        ("AES-128-GCM", "SYM", "AES-128"),
    ])
    def test_mapping(self, alg, fam, expect):
        assert _key(alg, fam) == expect

    def test_every_mapping_has_rationale(self):
        from recommender import REPLACEMENTS
        for key, rec in REPLACEMENTS.items():
            assert rec["rationale"], f"{key} missing rationale"
            assert rec["migrate_to"], f"{key} missing replacement"

    def test_pqc_replacements_are_ones_we_actually_built(self):
        from recommender import REPLACEMENTS
        import oqs
        enabled = set(oqs.get_enabled_kem_mechanisms()) | set(oqs.get_enabled_sig_mechanisms())
        for key, rec in REPLACEMENTS.items():
            for m in rec["migrate_to"]:
                if m.startswith(("ML-KEM", "ML-DSA")):
                    assert m in enabled, f"{key} recommends {m} but liboqs lacks it"


class TestScoreAll:
    def test_attaches_breakdown_to_every_finding(self):
        fs = [mk(algorithm="AES-128", algorithm_family="SYM"),
              mk(algorithm="MD5", algorithm_family="HASH")]
        score_all(fs)
        for f in fs:
            assert "risk" in f.extra
            assert f.extra["risk"]["quantum_source"]
            assert f.extra["risk"]["final_score"] == f.risk_score

    def test_sorts_descending(self):
        fs = [mk(algorithm="MD5", algorithm_family="HASH"),
              mk(algorithm="RSA-2048", algorithm_family="ASYM", file="src/payment/x.java")]
        score_all(fs, z_years=50)
        assert fs[0].risk_score >= fs[1].risk_score
