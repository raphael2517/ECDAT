"""
Tests for target_guard - the policy layer that stands between an untrusted
`target` string and `git clone` / `shutil.copytree`.

These matter more than most of the rest of the suite. The rest of the scanner
being wrong means a missed finding; this being wrong means the service hands out
files it should not, or becomes a proxy into a network it should not reach.
"""

import socket
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import target_guard as tg  # noqa: E402


# ---------------------------------------------------------------------------
# Private / non-routable addresses
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "addr",
    [
        "127.0.0.1",          # loopback
        "10.0.0.5",           # RFC1918
        "172.16.4.4",         # RFC1918
        "192.168.1.1",        # RFC1918
        "169.254.169.254",    # cloud metadata - the highest-value SSRF target
        "0.0.0.0",            # unspecified
        "100.64.0.1",         # CGNAT, which ipaddress reports as not-global
        "::1",                # IPv6 loopback
        "fd00::1",            # IPv6 unique-local
        "fe80::1",            # IPv6 link-local
    ],
)
def test_non_public_addresses_are_refused(addr):
    assert not tg._is_routable(__import__("ipaddress").ip_address(addr))


@pytest.mark.parametrize("addr", ["8.8.8.8", "1.1.1.1", "140.82.121.4", "2606:4700::1111"])
def test_public_addresses_are_allowed(addr):
    assert tg._is_routable(__import__("ipaddress").ip_address(addr))


# ---------------------------------------------------------------------------
# Hostname extraction across git URL dialects
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://github.com/org/repo.git", "github.com"),
        ("http://example.com/a/b", "example.com"),
        ("git://example.com/x.git", "example.com"),
        ("ssh://git@gitlab.com:2222/org/repo.git", "gitlab.com"),
        ("git@github.com:org/repo.git", "github.com"),
    ],
)
def test_host_extraction(url, expected):
    assert tg._host_from_git_url(url) == expected


def test_host_extraction_of_garbage_is_none():
    assert tg._host_from_git_url("") is None


# ---------------------------------------------------------------------------
# guard_git_url
# ---------------------------------------------------------------------------
def _fake_resolve(*addrs):
    """Patch getaddrinfo to return the given literal addresses."""
    return mock.patch.object(
        socket, "getaddrinfo",
        side_effect=lambda host, *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))
            for addr in addrs
        ],
    )


def test_public_host_is_allowed():
    with _fake_resolve("140.82.121.4"):
        tg.guard_git_url("https://github.com/org/repo.git")  # must not raise


def test_loopback_host_is_refused():
    with _fake_resolve("127.0.0.1"):
        with pytest.raises(tg.TargetNotAllowed, match="not a public address"):
            tg.guard_git_url("https://evil.example.com/repo.git")


def test_metadata_endpoint_is_refused():
    """The single most valuable SSRF target; assert it by name in the message."""
    with _fake_resolve("169.254.169.254"):
        with pytest.raises(tg.TargetNotAllowed, match="169.254.169.254"):
            tg.guard_git_url("http://169.254.169.254/latest/meta-data/")


def test_split_horizon_name_is_refused_if_any_address_is_private():
    """
    A name resolving to one public and one private address must still be
    refused - otherwise the public A record is just cover for the private one.
    """
    with _fake_resolve("93.184.216.34", "10.1.2.3"):
        with pytest.raises(tg.TargetNotAllowed, match="10.1.2.3"):
            tg.guard_git_url("https://split.example.com/repo.git")


def test_unresolvable_host_is_refused():
    with mock.patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("nope")):
        with pytest.raises(tg.TargetNotAllowed, match="does not resolve"):
            tg.guard_git_url("https://nowhere.invalid/repo.git")


def test_private_network_is_opt_in(monkeypatch):
    monkeypatch.setenv("ECDAT_ALLOW_PRIVATE_NETWORK", "1")
    with _fake_resolve("10.0.0.5"):
        tg.guard_git_url("https://internal.corp/repo.git")  # must not raise


def test_allow_private_network_accepts_common_spellings(monkeypatch):
    for value in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("ECDAT_ALLOW_PRIVATE_NETWORK", value)
        assert tg.allow_private_network() is True
    monkeypatch.setenv("ECDAT_ALLOW_PRIVATE_NETWORK", "0")
    assert tg.allow_private_network() is False


# ---------------------------------------------------------------------------
# guard_local_path
# ---------------------------------------------------------------------------
def test_local_path_allowed_under_root(tmp_path, monkeypatch):
    monkeypatch.setenv("ECDAT_SCAN_ROOT", str(tmp_path))
    target = tmp_path / "project"
    target.mkdir()
    assert tg.guard_local_path(target) == target.resolve()


def test_local_path_refused_outside_root(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "secrets"
    outside.mkdir()
    monkeypatch.setenv("ECDAT_SCAN_ROOT", str(allowed))
    with pytest.raises(tg.TargetNotAllowed, match="outside ECDAT_SCAN_ROOT"):
        tg.guard_local_path(outside)


def test_local_path_refuses_traversal(tmp_path, monkeypatch):
    """`allowed/../secrets` must not be laundered into looking like it is under root."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    monkeypatch.setenv("ECDAT_SCAN_ROOT", str(allowed))
    with pytest.raises(tg.TargetNotAllowed):
        tg.guard_local_path(allowed / ".." / "secrets")


def test_symlink_out_of_root_is_refused(tmp_path, monkeypatch):
    """
    A symlink *inside* the root that points outside it must not be a way out.
    This is why the guard compares resolved paths rather than string prefixes.
    """
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secret_file := secrets / "id_rsa").write_text("PRIVATE")
    link = allowed / "innocent"
    link.symlink_to(secret_file)
    monkeypatch.setenv("ECDAT_SCAN_ROOT", str(allowed))
    with pytest.raises(tg.TargetNotAllowed):
        tg.guard_local_path(link)


def test_root_itself_is_allowed(tmp_path, monkeypatch):
    monkeypatch.setenv("ECDAT_SCAN_ROOT", str(tmp_path))
    assert tg.guard_local_path(tmp_path) == tmp_path.resolve()


def test_unset_root_permits_but_warns(tmp_path, monkeypatch, caplog):
    """
    With ECDAT_SCAN_ROOT unset the documented local workflow must keep working,
    but it must leave a trace - otherwise a public deployment fails silently.
    """
    monkeypatch.delenv("ECDAT_SCAN_ROOT", raising=False)
    target = tmp_path / "anything"
    target.mkdir()
    with caplog.at_level("WARNING"):
        assert tg.guard_local_path(target) == target.resolve()
    assert any("ECDAT_SCAN_ROOT is unset" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Integration with the resolvers
# ---------------------------------------------------------------------------
def test_resolve_path_refuses_outside_root(tmp_path, monkeypatch):
    """The guard has to be reached through ingestion, not just in isolation."""
    import ingestion

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setenv("ECDAT_SCAN_ROOT", str(allowed))
    with pytest.raises(tg.TargetNotAllowed):
        ingestion.resolve_path(str(outside), tmp_path / "dest")


def test_resolve_git_refuses_private_host(monkeypatch):
    import ingestion

    with _fake_resolve("192.168.0.10"):
        with pytest.raises(tg.TargetNotAllowed):
            ingestion.resolve_git("https://intranet.corp/app.git", Path("/tmp/x"))


def test_resolve_zip_refuses_outside_root(tmp_path, monkeypatch):
    import ingestion

    archive = tmp_path / "outside.zip"
    archive.write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("ECDAT_SCAN_ROOT", str(allowed))
    with pytest.raises(tg.TargetNotAllowed):
        ingestion.resolve_zip(str(archive), tmp_path / "dest")
