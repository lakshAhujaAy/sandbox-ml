#!/usr/bin/env bash
# Starts Redis, the ML worker and the API in one container. If any of them dies
# the container exits, so the host's restart policy brings the whole thing back.
set -euo pipefail
cd /app
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379}"

redis-server --bind 127.0.0.1 --port 6379 --save "" --appendonly no &
until redis-cli -h 127.0.0.1 ping >/dev/null 2>&1; do sleep 0.3; done

python -m ml.worker &
uvicorn api.main:app --host 0.0.0.0 --port "${PORT:-7860}" &

wait -n
exit $?
