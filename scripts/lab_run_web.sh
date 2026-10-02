#!/usr/bin/env bash
# Start the AI Guardrails app (with Gateway Mode at /gateway) on a lab Linux host.
#
#   ./scripts/lab_run_web.sh            build the image if needed, then (re)start the container
#   ./scripts/lab_run_web.sh --rebuild  rebuild the image first (after a code or certs/ change)
#   ./scripts/lab_run_web.sh --stop     stop and remove the container
#
# One container, host networking: the app listens on this host's port APP_PORT
# (default 9000) and the gateway sees this host's own IP, so the demo rule's
# scope and the log matching use the right address without AIGUARD_LOCAL_IP.
# Settings come from .env (cp .env.example .env). Data stays on this host in
# ./instance (database, generated keys) and ./logs (app log, aiguard run logs).
case "$(head -c 4096 -- "$0" 2>/dev/null || true)" in *$'\r'*) printf '%s\n' "This file has Windows (CRLF) line endings. Fix: sed -i 's/\r\$//' \"$0\"" >&2; exit 2 ;; esac # CRLF guard: this line ends in a comment so it still parses with CRLF
set -euo pipefail

cd "$(dirname "$0")/.."
IMAGE="${AIGUARD_IMAGE:-aiguard-web:lab}"
NAME="${AIGUARD_CONTAINER:-aiguard-web}"
command -v docker >/dev/null 2>&1 || { echo "Docker is not installed (Ubuntu: sudo apt-get install docker.io)." >&2; exit 1; }
SUDO=""
if [ "$(id -u)" -ne 0 ] && ! docker info >/dev/null 2>&1; then SUDO="sudo"; fi

if [ "${1:-}" = "--stop" ]; then
  if $SUDO docker rm -f "$NAME" >/dev/null 2>&1; then echo "Stopped $NAME."; else echo "$NAME is not running."; fi
  exit 0
fi

if [ ! -f .env ]; then
  echo "Missing .env. Run: cp .env.example .env   then set DEFAULT_ADMIN_EMAIL and DEFAULT_ADMIN_PASSWORD." >&2
  exit 1
fi
if ! grep -qE '^DEFAULT_ADMIN_(PASSWORD|PASSWORD_HASH)=.+' .env; then
  echo "Set DEFAULT_ADMIN_PASSWORD in .env first (sign-in is refused without it)." >&2
  exit 1
fi

if [ "${1:-}" = "--rebuild" ] || ! $SUDO docker image inspect "$IMAGE" >/dev/null 2>&1; then
  if ! ls certs/*.crt >/dev/null 2>&1; then
    echo "Note: certs/ has no .crt file. Behind HTTPS Inspection the build's pip downloads fail;"
    echo "      copy the gateway's outbound CA to certs/outbound-ca.crt first (see certs/README.md)."
  fi
  echo "Building $IMAGE (first build takes 10-20 minutes)..."
  $SUDO docker build -t "$IMAGE" .
fi

PORT="$( (grep -E '^APP_PORT=' .env || true) | tail -n 1 | cut -d= -f2 | tr -d "\r\"' ")"
case "$PORT" in ''|*[!0-9]*) PORT=9000 ;; esac
# AIGUARD_DOCKER_NET=bridge publishes the port instead (then set AIGUARD_LOCAL_IP
# in .env to this host's IP, because the gateway sees the host, not the container).
if [ "${AIGUARD_DOCKER_NET:-host}" = "host" ]; then
  NET_ARGS=(--network host)
else
  NET_ARGS=(-p "${PORT}:${PORT}")
fi

mkdir -p instance logs data
$SUDO docker rm -f "$NAME" >/dev/null 2>&1 || true
# Another program (for example an older copy of this app) on the same port would
# make the new container fail to start, and its /health would look like ours.
if command -v ss >/dev/null 2>&1; then
  BUSY="$($SUDO ss -ltnpH 2>/dev/null | awk -v p="$PORT" '{n=split($4,a,":"); if (a[n]==p) print}' || true)"
  if [ -n "$BUSY" ]; then
    echo "Port $PORT is already in use on this host by another program:" >&2
    echo "$BUSY" | sed 's/^/  /' >&2
    echo "Stop that program, or pick another port: set APP_PORT in .env (installer: --port N)." >&2
    exit 1
  fi
fi
$SUDO docker run -d --name "$NAME" --restart unless-stopped "${NET_ARGS[@]}" \
  --env-file .env \
  -e AIGUARD_HOME=/app/logs/aiguard \
  -v "$PWD/instance:/app/instance" \
  -v "$PWD/logs:/app/logs" \
  -v "$PWD/data:/app/data" \
  "$IMAGE" >/dev/null

echo "Started $NAME. Waiting for the app..."
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    IP="$( (hostname -I 2>/dev/null || true) | awk '{print $1}')"
    echo "Ready: http://${IP:-<this-host>}:${PORT}  (sign in, then open Gateway Mode)"
    echo "CLI in the same container (shares logs and rollback points with the web console):"
    echo "  ${SUDO:+$SUDO }docker exec -it $NAME python -m aiguard setup"
    exit 0
  fi
  sleep 3
done
echo "The app did not answer on port ${PORT} within 3 minutes. Last log lines:" >&2
$SUDO docker logs --tail 40 "$NAME" >&2
exit 1
