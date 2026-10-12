#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ECDAT - expose a local instance through Cloudflare.
#
# Two modes:
#
#   ./deploy/tunnel.sh quick     throwaway trycloudflare.com URL, no account
#   ./deploy/tunnel.sh named     stable hostname on your own domain
#
# Both print a URL. Both are only safe because ECDAT itself refuses local paths
# outside ECDAT_SCAN_ROOT and refuses to clone non-public hosts - see
# .env.public.example. Put Cloudflare Access in front of it for anything you
# intend to keep.
#
# CAVEAT, and it is not a small one: this runs on your laptop. The URL is dead
# whenever the machine sleeps, closes the lid, or loses power. That is fine for
# showing someone at a desk and bad for a link on a portfolio page.
# ---------------------------------------------------------------------------
set -euo pipefail

MODE="${1:-quick}"
UI_PORT="${UI_PORT:-8080}"

cd "$(dirname "$0")/.."

# Policy checks first. These deliberately run before the cloudflared lookup:
# whether this host has the tunnel client installed is an environment detail,
# and a script that bails out on that before telling you your API is
# unauthenticated has its priorities backwards.
if [ -z "${ECDAT_API_KEY:-}" ]; then
    cat >&2 <<'EOF'
ECDAT_API_KEY is not set.

Everything under /api is open to anyone who reaches this URL, and anyone can
make the scanner read files off this host. Generate a key and export it:

    export ECDAT_API_KEY="$(openssl rand -base64 32)"

or use .env.public.example as a template.
EOF
    exit 1
fi

if [ -z "${ECDAT_SCAN_ROOT:-}" ]; then
    cat >&2 <<'EOF'
WARNING: ECDAT_SCAN_ROOT is unset.

A caller can POST {"target": "/etc"} or {"target": "/app"} and read the
contents back in the CBOM response. Set it to a directory holding only the
material you intend to expose:

    export ECDAT_SCAN_ROOT="$PWD/demo-targets"

EOF
    read -r -p "Continue anyway? [y/N] " reply
    case "$reply" in
        [yY]) ;;
        *) exit 1 ;;
    esac
fi

if ! command -v cloudflared >/dev/null 2>&1; then
    echo "cloudflared is not installed."
    echo
    echo "  Arch:   sudo pacman -S cloudflared"
    echo "  or:     https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
    exit 1
fi

if ! curl -sf "http://localhost:${UI_PORT}/health" >/dev/null 2>&1; then
    echo "No ECDAT responding on localhost:${UI_PORT} - run 'make up' first."
    exit 1
fi

case "$MODE" in
quick)
    echo ">> starting a quick tunnel (URL changes every restart)"
    echo ">> pointing at http://localhost:${UI_PORT}"
    exec cloudflared tunnel --url "http://localhost:${UI_PORT}"
    ;;
named)
    : "${CLOUDFLARE_TUNNEL_TOKEN:?set CLOUDFLARE_TUNNEL_TOKEN from 'cloudflared tunnel token create <name>'}"
    echo ">> starting named tunnel"
    exec cloudflared tunnel --no-autoupdate run --token "$CLOUDFLARE_TUNNEL_TOKEN"
    ;;
*)
    echo "usage: $0 [quick|named]" >&2
    exit 2
    ;;
esac
