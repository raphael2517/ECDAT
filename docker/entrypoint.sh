#!/bin/sh
# ECDAT container entrypoint.
#
#   api            run the FastAPI service (default)
#   scan  <args>   run the scanner CLI once and exit
#   rerisk <args>  re-score a finished report
#   shell          drop into a shell
#   <anything>     exec it verbatim
set -e

MODE="${1:-api}"

# Each subcommand consumes its own verb. Without this, `scan /target` becomes
# `python -m scanner scan scan /target` and argparse rejects the duplicate.
case "$MODE" in
    api)
        shift || true
        ;;
    scan|rerisk)
        shift || true
        ;;
esac

run_api() {
    echo "[entrypoint] starting uvicorn on 0.0.0.0:8000"
    # nginx proxies /api -> uvicorn and serves the UI bundle on /
    if [ -f /var/www/html/index.html ]; then
        nginx -g 'daemon off;' &
        NGINX_PID=$!
    else
        echo "[entrypoint] no UI bundle present - API only"
    fi

    exec /venv/bin/uvicorn api.src.main:app --host 0.0.0.0 --port 8000 --log-level info
}

case "$MODE" in
    api)
        run_api
        ;;
    scan)
        exec /venv/bin/python -m scanner scan "$@"
        ;;
    rerisk)
        exec /venv/bin/python -m scanner rerisk "$@"
        ;;
    shell|sh)
        exec /bin/sh
        ;;
    *)
        exec "$MODE" "$@"
        ;;
esac
