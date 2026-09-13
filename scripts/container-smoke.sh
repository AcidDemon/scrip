#!/bin/sh
# Test uploads, persistence, and shutdown in a built scrip image.
#
#   scripts/container-smoke.sh localhost/scrip:dev
#   CONTAINER_ENGINE=podman scripts/container-smoke.sh localhost/scrip:dev
#
# Runs the image the way deploy/README.md tells operators to run it: read-only
# root, all capabilities dropped, config mounted at /etc/scrip/scrip.toml, data
# in a named volume. Then it pastes over TCP, reads the paste back over HTTP,
# restarts the container to check persistence, and checks for a clean exit
# on shutdown. Any failure prints the container log.
#
# Needs curl and nc on the host. The image needs neither: it has no shell.
set -eu

image="${1:-}"
[ -n "$image" ] || { echo "usage: $0 <image>" >&2; exit 2; }

engine="${CONTAINER_ENGINE:-docker}"
command -v "$engine" >/dev/null 2>&1 || { echo "no $engine on PATH" >&2; exit 2; }

http_port="${SMOKE_HTTP_PORT:-18080}"
tcp_port="${SMOKE_TCP_PORT:-19999}"
name="scrip-smoke-$$"
volume="scrip-smoke-$$"
workdir=$(mktemp -d)

# GNU and OpenBSD netcat spell "close the socket at EOF" differently, and
# without it the server waits out idle_timeout_secs before replying.
if nc -h 2>&1 | grep -q -- '-N'; then
  nc_eof="-N"
elif nc -h 2>&1 | grep -q -- '-q'; then
  nc_eof="-q1"
else
  nc_eof=""
fi

cleanup() {
  rc=$?
  [ "$rc" = 0 ] || { echo; echo "== container log =="; "$engine" logs "$name" 2>&1 | tail -30; }
  "$engine" rm -f "$name" >/dev/null 2>&1 || true
  "$engine" volume rm -f "$volume" >/dev/null 2>&1 || true
  rm -rf "$workdir"
  exit "$rc"
}
trap cleanup EXIT INT TERM

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { printf '  ok  %s\n' "$*"; }

echo "== image =="

user=$("$engine" inspect "$image" --format '{{.Config.User}}')
[ "$user" = "65532:65532" ] || fail "image runs as '$user', expected 65532:65532"
ok "runs as 65532:65532"

# A shell in a scratch image means the build leaked a base layer.
if "$engine" run --rm --entrypoint /bin/sh "$image" -c true >/dev/null 2>&1; then
  fail "/bin/sh exists in the image"
fi
ok "no shell"

echo "== run =="

cat > "$workdir/scrip.toml" <<EOF
base_url = "http://127.0.0.1:$http_port"
db_path = "/var/lib/scrip/scrip.db"
listen_http = ["0.0.0.0:8080"]
listen_tcp = ["0.0.0.0:9999"]
EOF
chmod 644 "$workdir/scrip.toml"

"$engine" run -d --name "$name" \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  -p "$http_port:8080" \
  -p "$tcp_port:9999" \
  -v "$volume:/var/lib/scrip" \
  -v "$workdir/scrip.toml:/etc/scrip/scrip.toml:ro" \
  "$image" >/dev/null

wait_healthy() {
  i=0
  while [ "$i" -lt 30 ]; do
    curl -fsS -o /dev/null "http://127.0.0.1:$http_port/healthz" 2>/dev/null && return 0
    i=$((i + 1))
    sleep 1
  done
  return 1
}

wait_healthy || fail "/healthz never came up"
ok "healthz, with the config picked up from /etc/scrip/scrip.toml"

echo "== paste =="

payload="container smoke $$"
url=$(printf '%s\n' "$payload" | timeout 30 nc $nc_eof 127.0.0.1 "$tcp_port" | tr -d '\r\n')
case "$url" in
  http://127.0.0.1:$http_port/*) ;;
  *) fail "intake returned '$url', expected a base_url link" ;;
esac
slug=${url##*/}
ok "intake returned $url"

got=$(curl -fsS "http://127.0.0.1:$http_port/raw/$slug")
[ "$got" = "$payload" ] || fail "raw read returned '$got', expected '$payload'"
ok "raw read matches"

curl -fsS -o /dev/null "http://127.0.0.1:$http_port/$slug" || fail "view page failed"
# The frontend is compiled into the binary; a scratch image ships no files.
for asset in view.js view.css; do
  curl -fsS -o /dev/null "http://127.0.0.1:$http_port/assets/$asset" \
    || fail "embedded asset /assets/$asset not served"
done
ok "view page and embedded assets"

"$engine" exec "$name" /scrip ban list >/dev/null || fail "admin subcommand failed"
ok "admin subcommands run without a shell"

echo "== restart =="

"$engine" stop --time 45 "$name" >/dev/null
code=$("$engine" inspect "$name" --format '{{.State.ExitCode}}')
[ "$code" = 0 ] || fail "SIGTERM shutdown exited $code, expected 0"
ok "SIGTERM shutdown exited 0"

"$engine" start "$name" >/dev/null
wait_healthy || fail "/healthz never came back after restart"
got=$(curl -fsS "http://127.0.0.1:$http_port/raw/$slug")
[ "$got" = "$payload" ] || fail "paste did not survive the restart"
ok "paste survived the restart"

echo
echo "container smoke passed: $image"
