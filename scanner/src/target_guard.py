"""
ECDAT Scanner - Untrusted target validation.

The scanner is written to be operated by the person who owns the host. That
assumption breaks the moment the API is reachable by anyone else, because two
parts of the target surface are dangerous with a hostile caller:

**Local paths -> arbitrary file disclosure.** A CBOM response carries source
snippets, not just algorithm names. A caller who submits ``{"target": "/app"}``
gets the scanner's own source read back out over HTTP. There is no second
permission check between "which directory did you name" and "here are its
contents".

**Git URLs -> SSRF.** ``git clone`` makes this host open an outbound connection
to whatever URL it is handed. A caller who submits an RFC1918 address, the
loopback interface, or a cloud metadata endpoint turns the scanner into a proxy
for reaching things that are not supposed to be reachable from the internet.

Both checks live here rather than in the HTTP layer on purpose: the CLI and the
API share this module, so running ``scanner scan /etc`` locally and POSTing the
same target are governed by exactly one implementation.

Configuration (environment):

``ECDAT_SCAN_ROOT``
    When set, local-path and zip targets must resolve underneath this
    directory. When unset, local targets are permitted - which keeps the
    documented ``make scan SCAN_TARGET=.`` workflow working - but a warning is
    logged, because the host is then one POST away from being read.

``ECDAT_ALLOW_PRIVATE_NETWORK``
    Set to ``1`` to permit cloning from private/loopback/link-local hosts.
    Needed only if you deliberately host the repository to scan inside your own
    network. Defaults to blocking.

Known limitation: DNS is resolved once, here, and ``git`` resolves it again
when it connects. A host whose DNS answer changes between the two checks (DNS
rebinding) can slip past this. Closing that properly means pinning the resolved
address into git's invocation, which is a larger change; for a deployment
guarded by an authenticating proxy it is an acceptable trade.
"""

import ipaddress
import os
import socket
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from utils import log

_TRUTHY = {"1", "true", "yes", "on"}


class TargetNotAllowed(RuntimeError):
    """
    Raised when a target is refused by policy.

    Distinct from IngestionError so the API can turn it into a 400 ("that
    target is not permitted") rather than a 500 ("something went wrong"), which
    keeps policy refusals from looking like server faults in the logs.
    """


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
def allow_private_network() -> bool:
    return os.getenv("ECDAT_ALLOW_PRIVATE_NETWORK", "").strip().lower() in _TRUTHY


def scan_root() -> Optional[Path]:
    raw = os.getenv("ECDAT_SCAN_ROOT", "").strip()
    return Path(raw).expanduser().resolve() if raw else None


# ---------------------------------------------------------------------------
# Local paths
# ---------------------------------------------------------------------------
def guard_local_path(path: Path, *, what: str = "local path") -> Path:
    """
    Refuse a local path that escapes ECDAT_SCAN_ROOT.

    Returns the resolved path so callers can use the return value instead of
    re-resolving and accidentally re-introducing a traversal.
    """
    resolved = path.expanduser().resolve()
    root = scan_root()

    if root is None:
        log.warning(
            "%s %s accepted: ECDAT_SCAN_ROOT is unset, so any readable path on "
            "this host can be scanned and its contents returned in the CBOM. Set "
            "ECDAT_SCAN_ROOT before exposing this service.",
            what, resolved,
        )
        return resolved

    # is_relative_to resolves symlinks in both arguments, so a symlink planted
    # inside the root cannot be used to step outside it.
    if not resolved.is_relative_to(root):
        raise TargetNotAllowed(
            f"{what} {resolved} is outside ECDAT_SCAN_ROOT ({root}); "
            f"only targets under that directory may be scanned"
        )
    return resolved


# ---------------------------------------------------------------------------
# Git URLs
# ---------------------------------------------------------------------------
def _host_from_git_url(url: str) -> Optional[str]:
    """Extract the hostname from any of the git URL forms we accept."""
    if url.startswith("git@"):
        # scp-like syntax: git@github.com:org/repo.git
        rest = url[len("git@"):]
        host, _, _path = rest.partition(":")
        return host or None
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _is_routable(ip: ipaddress._BaseAddress) -> bool:
    """
    True when the address is one a public internet host could legitimately own.

    Two conditions, both required. ``is_global`` is the broad net and catches
    ranges the explicit list misses - notably CGNAT (100.64.0.0/10), which
    ``is_private`` reports as False even though it is carrier NAT space and
    routinely used inside networks. The explicit list is the narrow net: it
    keeps the intent legible and keeps us strict if ``is_global`` ever disagrees
    with us about an address family.
    """
    if not ip.is_global:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def guard_git_url(url: str) -> None:
    """
    Refuse a Git URL that points at something other than a public host.

    Resolves the hostname and checks every address it maps to, so a name with
    both a public and a private A record cannot be used to reach the private
    one.
    """
    if allow_private_network():
        log.info("cloning %s: private-network targets permitted by policy", url)
        return

    host = _host_from_git_url(url)
    if not host:
        raise TargetNotAllowed(
            f"cannot determine the host in {url!r}; refusing to clone an "
            f"unresolvable remote"
        )

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetNotAllowed(f"host {host!r} does not resolve: {exc}") from exc

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not _is_routable(ip):
            raise TargetNotAllowed(
                f"refusing to clone {host!r}: it resolves to {ip}, which is not "
                f"a public address. Scanning a target on a private network is "
                f"disabled; set ECDAT_ALLOW_PRIVATE_NETWORK=1 to permit it."
            )
