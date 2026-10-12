# Running ECDAT somewhere other than your laptop

ECDAT is a localhost tool by default. Nothing about it stops you putting it on
the public internet, and this page is the part you should read first if you are
about to.

## What you are exposing

`POST /api/scan` takes a `target` and does one of four things with it:

| Target kind | What actually happens | Abuse if unauthenticated |
|---|---|---|
| local path | copies the directory into the workspace and scans it | **file disclosure** - the CBOM response contains source snippets, so `{"target": "/app"}` reads this container's own source back out |
| Git URL | `git clone <url>` | **SSRF** - the host will open a connection to anything you name, including RFC1918 and `169.254.169.254` |
| zip | extracts and scans | same as local path, plus zip-slip (already handled in `ingestion.py`) |
| image ref | Syft pulls the manifest | outbound fetch to an arbitrary registry |

There is also no ceiling on concurrent scans. Each one is a Semgrep run plus,
optionally, real keygen and signature benchmarks. Unthrottled, one caller can
pin every core on the machine.

None of this matters when the only client is you on `localhost`. All of it
matters the moment a URL exists.

## The three settings that change this

```bash
export ECDAT_API_KEY="$(openssl rand -base64 32)"   # required
export ECDAT_SCAN_ROOT="$PWD/demo-targets"          # strongly recommended
export ECDAT_MAX_CONCURRENT_SCANS=2                 # recommended
```

| Variable | Unset behaviour | Set behaviour |
|---|---|---|
| `ECDAT_API_KEY` | `/api` is open to anyone who can reach the port. A startup log line says so. | every `/api` route requires `X-ECDAT-Key` |
| `ECDAT_SCAN_ROOT` | any readable path can be scanned. A warning is logged per scan. | local-path and zip targets must resolve under that directory; symlinks that escape are still refused |
| `ECDAT_MAX_CONCURRENT_SCANS` | 2 | as set; over the cap returns HTTP 429 |

`/health` stays open regardless, because the container `HEALTHCHECK` and uptime
monitors need it. It reports component versions and nothing more.

`.env.public.example` is a template for all of this.

### Where each check lives

- **Target policy** is in `scanner/src/target_guard.py`, called from the
  resolvers in `scanner/src/ingestion.py`. It is in the scanner rather than the
  HTTP layer on purpose, so the CLI and the API share one implementation — a
  check that lives only in a route is a check `docker run ecdat scan /etc`
  walks straight past.
- **The API key** is in `api/src/security.py`, attached as a dependency on the
  router in `api/src/routes.py`. The WebSocket authenticates separately because
  browsers cannot set headers on a handshake, so it takes `?key=` instead.
- **The concurrency cap** is in `POST /api/scan`.

## Known gaps

Stated plainly, because a hardening page that only lists what works is
misleading:

- **The container still runs as root.** nginx binds port 80 and the entrypoint
  starts both servers, so dropping privileges means moving nginx to a high port
  and giving it writable temp paths. Not done yet. The container has no docker
  socket and no host mounts other than `./output`, which limits what root-in-
  container buys an attacker, but it is not the same as non-root.
- **DNS rebinding.** `target_guard` resolves the hostname, checks the address,
  and then `git` resolves it again when it connects. A host whose DNS answer
  changes between the two can slip through. Closing it means pinning the
  resolved address into git's invocation.
- **`git` option injection.** The URL reaches `git clone` as an argument. It is
  not passed through a shell, so this is not remote code execution, but a
  leading `--upload-pack=` style payload is not obviously rejected.

If any of these matter for your use, the honest answer is that Cloudflare
Access in front of the whole thing removes all three at once, because nothing
reaches the scanner without passing the proxy.

## Tunnel + Access (the recommended shape)

### 1. Run it locally, hardened

```bash
set -a && . ./.env.public && set +a
make up
```

### 2. Cloudflare Access

Workers & Pages → Zero Trust → Access → Applications → Add. Hostname
`ecdat.yourdomain.com`, policy **Emails** listing whoever should get in.

This is the single most valuable control here: it puts an authenticating proxy
in front of everything, so an unauthenticated request never reaches the
scanner at all.

### 3. Named tunnel

```bash
sudo pacman -S cloudflared
cloudflared tunnel login
cloudflared tunnel create ecdat
cloudflared tunnel route dns ecdat ecdat.yourdomain.com

export CLOUDFLARE_TUNNEL_TOKEN="$(cloudflared tunnel token ecdat)"
export ECDAT_API_KEY="$(openssl rand -base64 32)"
export ECDAT_SCAN_ROOT="$PWD/demo-targets"
./deploy/tunnel.sh named
```

`deploy/tunnel.sh quick` gives you a throwaway `*.trycloudflare.com` URL with no
account at all. The script refuses to start without `ECDAT_API_KEY`, and warns
before starting without `ECDAT_SCAN_ROOT`.

## The laptop problem

A tunnel to a laptop produces a URL that is **dead whenever the machine
sleeps, closes the lid, or loses power**. That is fine for walking someone
through it at a desk. It is bad for a link on a portfolio page that someone
clicks three weeks later.

If you want the link to work when you are not sitting at the machine, the
options in rough order of effort:

1. **Tailscale + a second always-on box** — cheapest, keeps it private.
2. **A $4-6/mo VPS** — always on, public IP, you own the whole story. This is
   what a portfolio demo wants.
3. **Fly.io / Render** — free tier exists, but cold starts and sleep limits make
   a demo URL unreliable.

## Before you point a real URL at this

- [ ] `ECDAT_API_KEY` set, and you have tested that omitting it returns 401
- [ ] `ECDAT_SCAN_ROOT` set, and you have tested that a target outside it is refused
- [ ] Cloudflare Access in front, with a real email allowlist
- [ ] `docker/entrypoint.sh` logs are not published anywhere
- [ ] You accept that a WebSocket key travels in a URL and will appear in access logs
