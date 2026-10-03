# scrip deployment

## NixOS

The repo is a flake with a NixOS module. Add the input and enable the service:

```nix
inputs.scrip.url = "github:AcidDemon/scrip";
```

```nix
imports = [ scrip.nixosModules.default ];
services.scrip = {
  enable = true;
  openFirewall = true; # intake port
  settings.base_url = "https://paste.example.com";
};
```

`settings` is the scrip.toml content; every key is optional. The module ships
the same hardened unit as `scrip.service` below, and
`services.scrip.nftables.enable = true` installs the anti-abuse ruleset plus
the boot-time ban export. Everything below is for non-Nix hosts.

## Debian

Download the `.deb` from the GitHub releases page, then:

```bash
apt install ./scrip_*.deb
$EDITOR /etc/scrip/scrip.toml   # set base_url
systemctl start scrip-firewall scrip
```

The package installs the units, nftables ruleset, and scrip user; everything
below is the manual equivalent.

## Manual installation

Install the binary:
```bash
install -m 755 target/release/scrip /usr/bin/
```

Create the scrip user (systemd's `StateDirectory=scrip` in the unit creates
and owns `/var/lib/scrip` for you, no manual `mkdir`/`chown` needed):
```bash
useradd -r -d /var/lib/scrip -s /usr/sbin/nologin scrip
mkdir -p /etc/scrip
```

Install the systemd units and the nftables ruleset:
```bash
install -m 644 scrip.service scrip-firewall.service /etc/systemd/system/
install -D -m 644 nftables-scrip.conf /etc/nftables.d/scrip.conf
systemctl daemon-reload
systemctl enable scrip-firewall scrip
```

`scrip-firewall` loads the base ruleset and then the ban export on every boot,
before scrip starts. It runs as root: `nft` needs `CAP_NET_ADMIN`, and the
export reads the database at `db_path`. Each export replaces the contents of
`scrip_bans4` and `scrip_bans6`, so a reload resyncs them. Reloading the base
ruleset deletes and recreates the table, so the export has to run after it.
Timed auto-bans carry a kernel timeout
and expire on their own. This ruleset is scrip-scoped only; a default-drop
base firewall or cloud security group remains the operator's job.

scrip pulls the firewall unit in with `Wants=`, not `Requires=`: if the nft
layer fails to load, scrip still starts and enforces bans and rate limits
in-process. Check
`systemctl status scrip-firewall` after boot if you rely on it.

## Running in a container

The root `Containerfile` builds a static musl executable in Alpine, then
copies it into `scratch`. The runtime has no shell, package manager, shared
libraries, or separate frontend files. It runs as UID/GID `65532:65532` and
stores state in `/var/lib/scrip`. The release tarballs still target glibc;
do not copy those executables into `scratch`.

Build from the repository root with either engine:

```sh
podman build --format oci -f Containerfile -t localhost/scrip:dev .
# Or:
docker build -f Containerfile -t localhost/scrip:dev .
```

The build uses `Cargo.lock`, strips symbols, and rejects executables that
need a dynamic loader or shared libraries. `.dockerignore` admits only
compilation inputs. Update the pinned builder when Rust or musl receives
security fixes; bundled SQLite and Rust dependencies also need rebuilds.

The release workflow publishes native `linux/amd64` and `linux/arm64` images
to `ghcr.io/aciddemon/scrip` under the Git tag, such as `v0.1.0`. After a
release has published its image, use that version instead of
`localhost/scrip:dev` below. `latest` follows stable releases only; pin a
version or digest for deployments that must not change unexpectedly.

On Linux, with a reverse proxy running on the host:

```sh
cp deploy/scrip.toml.example scrip.toml
chmod 644 scrip.toml
$EDITOR scrip.toml # Set base_url to the public HTTPS URL.

podman run -d --name scrip \
  --network=host \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --ulimit core=0 \
  --stop-timeout=45 \
  -v scrip-data:/var/lib/scrip \
  -v "$PWD/scrip.toml:/etc/scrip/scrip.toml:ro,Z" \
  localhost/scrip:dev
```

Replace `podman` with `docker` to run the same image with Docker. `:Z` labels
the config mount for private SELinux access; use `:z` when sharing that file
with other containers. The image contains no site-specific configuration. The mounted
TOML file controls HTTP binding and all other settings; command-line
overrides remain available after `run`.

The named volume is initialized for the image's non-root user. A bind mount is
not: the directory has to belong to container UID 65532 before the first
start, or scrip exits with `unable to open database file`. Rootless Podman
maps that UID into your subuid range, so chown it from inside that mapping:

```sh
mkdir -p ./data
podman unshare chown 65532:65532 ./data
```

Under rootful Docker it is a plain `sudo chown 65532:65532 ./data`. Mount the
directory, not just `scrip.db`: SQLite also needs its WAL and SHM files. Keep this volume across
upgrades. Back up through SQLite using external tools, or stop the container
before copying the whole volume; do not copy a live database file alone.

Host networking preserves the existing loopback proxy setup but removes
network isolation. A proxy in the same network namespace, such as a Podman
pod, can also connect over loopback. A separate proxy on a bridge network
is not trusted: scrip ignores its `X-Forwarded-For`, so readers share the
proxy's limits and bans. Plain port publishing also requires
`listen_http = ["0.0.0.0:8080"]`; verify that the chosen TCP forwarding mode
preserves client source IPs. Do not expose a bridged proxy deployment without
addressing this trust boundary.

TLS and nftables stay outside the application container. Application bans
and rate limits still work without nftables; no `NET_ADMIN` capability is
needed. Set host firewall rules and runtime resource limits for your load.

Logs, health checks, and administrative commands need no container shell:

```sh
podman logs scrip
curl -fsS http://127.0.0.1:8080/healthz
podman exec scrip /scrip ban list
podman stop --time 45 scrip
```

`/healthz` checks HTTP liveness, not database writes. Allow 45 seconds when
stopping so active requests can drain and SQLite can checkpoint its WAL.
The shared smoke check exercises the actual image, including uploads,
frontend assets, persistent storage, and shutdown:

```sh
CONTAINER_ENGINE=podman scripts/container-smoke.sh localhost/scrip:dev
# Or:
CONTAINER_ENGINE=docker scripts/container-smoke.sh localhost/scrip:dev
```

## Configuration

Default config at `/etc/scrip/scrip.toml`:
```toml
base_url = "https://paste.example.com"
db_path = "/var/lib/scrip/scrip.db"
listen_http = ["127.0.0.1:8080"]
```

Adjust `base_url` for your site. Auto-bans are enabled by default. These
settings control them; the root README has the full configuration reference:

```toml
autoban_threshold = 20        # rate refusals in the window that earn a ban
autoban_window_secs = 60
autoban_minutes = 30          # doubles per repeat (autoban_factor), capped
autoban_max_minutes = 1440    # at one day; strikes reset after
autoban_forget_days = 7       # a quiet week; 0 keeps them forever
max_pastes_per_source = 100   # live pastes per /32 (v4) or /64 (v6)
```

Auto-bans appear in `scrip ban list` with reason `auto: rate abuse`.
`scrip ban rm` lifts one early. Users behind the same NAT share a /32 and can
reach these limits together; adjust the settings for your users.

## Reverse proxy

Run scrip on loopback behind a reverse proxy (nginx, Caddy, etc.) that handles TLS.
Append `X-Forwarded-For` to requests so scrip sees client IPs for rate limiting.

## Logging

scrip logs to stdout, captured by journald under systemd or by the container
runtime. The `log_pastes` knob (`"url"` default, `"full"`,
`"off"`) controls whether created paste URLs and author IPs are logged.
IP-attributed logs are personal data: bound retention with `MaxRetentionSec=`
in a drop-in under `/etc/systemd/journald.conf.d/`.

## Management

Run as root, ban changes also reload the firewall:
```bash
sudo scrip rm https://paste.example.com/SLUG
sudo scrip ban list
sudo scrip ban rm 203.0.113.9
```

Health check:
```bash
curl -sf http://127.0.0.1:8080/healthz
```

## Operations

Back up through SQLite, not `cp`: committed data lives in `scrip.db-wal` until
a checkpoint, and copying the files one at a time catches them at different
instants, so a plain file copy of a live database can be torn.

```bash
install -d -m 700 /var/backups/scrip
umask 077
sqlite3 /var/lib/scrip/scrip.db "VACUUM INTO '/var/backups/scrip/$(date +%F-%H%M).db'"
```

`VACUUM INTO` refuses to overwrite an existing file. The filename includes the
time so you can make multiple backups per day. Pastes written without
`encrypt_at_rest` remain plaintext in the backup; `umask` and mode `700`
restrict access to it.

Restore: stop scrip, put the backup at `/var/lib/scrip/scrip.db`, delete any
leftover `scrip.db-wal` and `scrip.db-shm`, `chown scrip:scrip`, start again.

Upgrade:
```bash
systemctl stop scrip
install -d -m 700 /var/backups/scrip
(umask 077; sqlite3 /var/lib/scrip/scrip.db \
  "VACUUM INTO '/var/backups/scrip/$(date +%F-%H%M).db'")
apt install ./scrip_*.deb
systemctl restart scrip-firewall
systemctl start scrip
systemctl status scrip-firewall scrip
```
