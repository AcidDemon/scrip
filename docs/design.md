# Design

scrip is a public, anonymous pastebin in the termbin style. Pipe bytes to a TCP
port, get a URL back, open the URL and read the paste with syntax highlighting.

scrip was written in Rust to replace fiche, whose slug scheme was predictable,
concurrency was unbounded, and documented banlist was never implemented.

What it does:

- `cat file | nc scrip.example.com 9999` returns a URL
- that URL serves a viewer page with client side highlighting
- `/raw/<slug>` serves the exact bytes as `text/plain`
- `curl --data-binary @file https://scrip.example.com` is the TLS write path
- both listeners enforce rate limits, connection caps, size caps, a quota,
  a banlist, and expiry
- IPv4 and IPv6 on both listeners
- one static binary, one SQLite file, one config file

There is no built-in TLS, account system, paste editing, URL shortening,
metrics, web upload form, search, or server-side highlighting.

Encryption at rest is opt-in through
`encrypt_at_rest`: XChaCha20-Poly1305 under a key derived from the paste's own
URL, with the row keyed by a hash of that URL. The server still receives
plaintext and derives the key on every read.

## Structure

One binary with subcommands: `scrip run`, `scrip ban`, `scrip rm`, `scrip gc`.

```
        :9999 raw TCP ──► intake ──┐
   (nc, /dev/tcp, bash)            │
                                   ├──► policy ──► store (SQLite)
   :8080 HTTP ────────► http ──────┘                  │
   (loopback, behind proxy)                       reaper (tokio interval)
```

| module | job |
| --- | --- |
| `intake` | raw TCP listener, read loop, reply writer |
| `http` | axum router: viewer, raw, POST, assets, healthz |
| `policy` | ban check, rate limit, connection caps |
| `store` | SQLite access and schema |
| `config` | TOML file plus flags, flags win |

Both upload paths go through `intake::store_paste`, which runs the quota check
and the insert. There is no code path that stores a paste without passing the
ban check, the rate limiter, the size cap, and the quota, in that order. The TCP
path also runs the probe check, between the size cap and the quota.

## Wire protocol

fiche uses `MSG_WAITALL` and `SO_RCVTIMEO` to end a read after an idle period,
which lets `cat f | nc host 9999` finish without an explicit EOF. scrip's read
loop has these rules:

- Idle timeout, 5s. Silence ends the read, and what arrived is the paste.
- Total deadline, 30s from accept, whatever the drip rate. Both timeouts
  are needed. An idle timeout on its own lets one connection send a byte every
  4.9 seconds forever, which is the hole fiche has.
- Size cap, 512 KiB by default. Going over stores nothing and replies with
  an error line.
- EOF, the client shutting down its write side, ends the read normally.

On success the server writes `<base_url>/<slug>\n` with no trailing NUL (fiche
sends one), shuts down its write side, drains whatever the client is still
sending, and closes. Draining matters: closing with unread bytes in the socket
makes the kernel send RST instead of FIN, and an RST discards the reply that is
still in flight. A read of zero bytes, or of whitespace alone, stores nothing
and gets no reply.

Scanners connect, send a probe and wait for an answer. Stored as is, every
probe would become a paste, so the TCP path refuses a body that is one of:

- a first line holding NUL or a C0 control that text never uses (anything
  but BEL, BS, TAB, VT, FF, CR, SO, SI and ESC), which covers TLS and SSLv2
  ClientHellos and nearly every binary service probe, nmap's included
- a request line ending in CRLF, `METHOD target HTTP/x.y` or the same with
  `RTSP/` or `SIP/`, which covers browsers, the HTTP/2 preface, and nmap's
  HTTP, RTSP and SIP probes
- an SSH version line with nothing after it
- nmap's `HELP\r\n`

The reply is `scrip: refused <kind> probe; prepend a line to paste it anyway`,
and the log line names the kind and the source, never the bytes. Every rule
reads only the first line, so any line in front of the body, even an empty
one, gets it through. The binary rule allows the controls that ANSI color,
terminfo resets, terminal titles, overstrike and progress bars use, and it
does not check UTF-8, so Latin-1 text passes. It does refuse most binary
files, such as gzip or ELF, along with UTF-16 text, NUL-separated output
like `git status -z`, and IRC logs that keep mIRC color codes in the first
line. Raw reads serve `text/plain; charset=utf-8` anyway, and the HTTP path
takes all of these. The request-line rule wants CRLF because a terminal sends LF. A refusal adds no auto-ban strike, and there is no setting
for the check. The HTTP path has none of this: a POST body that looks like a
request is ordinary content there.

## Storage

SQLite in WAL mode, `synchronous=FULL`, `auto_vacuum=INCREMENTAL`,
`secure_delete=ON`, through rusqlite with the bundled feature so there is no
system SQLite dependency.

FULL fsyncs each paste before the server returns its URL. Under NORMAL, a
commit is not fsynced until the next checkpoint, so a power cut could lose
pastes whose URLs have already been returned. The TCP protocol has no way to
notify those clients afterwards. Each paste costs one fsync, with a default
limit of six pastes per minute per source.

```sql
CREATE TABLE paste (
  slug       TEXT    PRIMARY KEY,
  body       BLOB    NOT NULL,
  size       INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  source_ip  TEXT,
  source_key TEXT,             -- the /32 or /64 source_ip keys as
  burn       INTEGER NOT NULL DEFAULT 0,
  delete_token_hash BLOB       -- SHA-256 of the token handed to the uploader
) STRICT;

CREATE TABLE ban (
  cidr   TEXT PRIMARY KEY,
  reason TEXT,
  until  INTEGER          -- NULL = permanent
) STRICT;
```

The PRIMARY KEY prevents duplicate slugs. An INSERT conflict regenerates the
slug once; a second conflict fails the upload. This avoids fiche's
generate-retry-mkdir loop, which contained a use-after-free bug. The slug
space has 36^8 possible values.

When the quota is full, expired rows are evicted first regardless of age,
followed by live pastes older than half their retention period. Newer live
pastes are protected from eviction, so filling the quota cannot delete them.
An upload is refused if it could not fit in an empty store or if eligible
evictions cannot free enough space.

Every paste gets `expires_at = created_at + retention`, 30 days by default. The
reaper deletes expired rows on an interval and runs `PRAGMA incremental_vacuum`
after a large delete. The read path filters on `expires_at` too, so nothing is
served in the window between expiry and the next sweep.

## Slugs

Eight characters from `a-z0-9`, drawn from the OS CSPRNG through `getrandom`,
rejection sampled so the modulo does not bias the distribution. That is 36^8,
about 2.8e12 keys.

Production uses the OS RNG without a seed or process-global RNG state. Tests
that need deterministic slugs inject a generator to force collisions.

## Limits

- A global connection semaphore across both listeners, 1024 permits by default.
- A per source token bucket for paste creation, held in memory, idle buckets
  evicted on a timer.
- A separate token bucket for reads allows a higher rate than uploads. It
  limits slug probing without making browsing consume upload tokens.
- A per source concurrent connection cap, 12 by default, drawn from one
  counter shared by TCP and HTTP. The allowance covers a viewer page and its
  subresources, including browsers that open up to six connections per host.

The source key is the address for IPv4 and the /64 for IPv6, never the /128. A
residential IPv6 customer holds 2^64 addresses, so per-address limiting on IPv6
is ineffective. IPv6 sources also share a budget per /48 at
`AGGREGATE_FACTOR` (8) times the per-/64 allowance, for rate, burst, live paste
count, and auto-ban threshold. A routed /48 contains 65,536 /64s, which would
each receive a separate allowance without the aggregate limit.

For HTTP, the source is `client_ip`, which trusts `X-Forwarded-For` only
from loopback. A source that still resolves to loopback is the proxy itself (or
a local client) and is exempt from the connection cap, and is never a ban
target: a missing forwarded header would otherwise cap the whole site at one
source's budget, or ban the proxy on its own behalf. Its strikes are still
recorded, so a misconfigured proxy is visible in the journal and in the
`offense` table.

## Banlist

Rows live in the `ban` table and are matched by CIDR containment, checked at
accept time before a single byte is read from the client. A linear scan is fine
to about 10k rows; a prefix trie is the upgrade past that. The daemon re-reads
the table every `ban_reload_secs`, so bans apply without a restart.

`scrip ban export` emits the list as nftables set elements, which pushes
enforcement into the kernel and off the accept path.

## Listeners

`listen_tcp` and `listen_http` are lists of socket addresses. IPv4 and IPv6 use
separate sockets, with `IPV6_V6ONLY` set on each IPv6 socket for portability.
HTTP binds loopback by default, since the reverse proxy handles TLS and the
public interface.

## HTTP surface

```
GET  /              landing page
GET  /<slug>        viewer shell, text/html
GET  /raw/<slug>    text/plain; charset=utf-8
POST /              body is the paste, returns the URL and X-Delete-Token
DELETE /<slug>      X-Delete-Token authorizes; a wrong token is a 404
GET  /assets/*      embedded static files, ban-checked but not rate-limited
GET  /healthz       200, no body
```

Slug path parameters are checked against `^[a-z0-9]{1,16}$`, or exactly the
26-character encryption token, before anything touches the store. Everything
else is a 404. The stored id of an encrypted row is 64 hex characters, longer
than either, so ciphertext can never be addressed by its id from a URL.

This origin serves anonymous hostile content, so the viewer is built defensively:

- `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'`
  on every HTML response
- `Referrer-Policy: no-referrer` on every response: under `encrypt_at_rest` the
  URL path is the decryption key, and a default policy would hand it to every
  host a paste links out to
- `X-Content-Type-Options: nosniff` on every response, no exceptions
- raw responses are always `text/plain; charset=utf-8`
- paste bytes enter the DOM through `textContent` and nothing else, then
  highlight.js runs on the element. `innerHTML` never sees paste bytes.

highlight.js and its themes are embedded in the binary with `include_str!`, so
the viewer pulls nothing from a CDN and the CSP can stay this tight.

One constraint for the future: if this origin ever gains cookies or auth,
pastes have to move to a separate origin first.

## Operations

- SIGTERM stops the accept loops, drains in-flight connections against a 10
  second deadline, and exits 0.
- Any startup failure, whether bind, config, or DB open, exits nonzero so
  `Restart=on-failure` fires.
- No privilege dropping in process. `User=` in the systemd unit does it, the
  kernel drops before exec, and a failure there is a hard unit failure.
- `tracing` writes one line per event to stdout for journald.

`deploy/` ships the hardened unit and an nftables sample where the per source
connection cap is ordered before the accept rule.

## Dependencies

axum, tokio, rusqlite (bundled), ipnet, serde and toml, tracing, clap,
getrandom. Anything beyond that needs a reason recorded in the commit that adds
it.

## Tests

| layer | what it covers |
| --- | --- |
| unit | slug charset and length, token bucket arithmetic, CIDR matching, config precedence, ban expiry, scanner probe classification |
| property (proptest) | any chunking reassembles byte-identical, slug distribution passes chi-square, the bucket never exceeds burst or goes negative, CIDR containment agrees with a reference implementation, a leading line always disarms the probe check |
| integration | store against a temp DB: concurrent inserts on the PRIMARY KEY, quota refusal at the boundary, the reaper deleting exactly the expired rows |
| API contract | the router on an ephemeral port: status codes, content types, CSP and nosniff on every response, the slug gate, 413 on oversize bodies |
| end-to-end | the release binary as a child process, driven over real sockets, including misbehaving clients, SIGTERM mid-connection, and every startup failure mode |
| security | traversal and injection slugs, ban enforcement timing, rate limits per /32 and per /64, slowloris, and an assertion that paste bytes never reach a `text/html` body |
| fuzz | cargo-fuzz over the read loop, slug routing, the TOML loader, duration parsing, and X-Forwarded-For |
| load | the release binary under 500 concurrent pastes and 1000 HTTP reads, asserting p99 and RSS |
| soak | ten minutes of mixed load, asserting no fd or RSS growth and a clean SIGTERM |

Load and soak thresholds live in `thresholds.toml`. Review threshold changes
alongside performance results. Commit a regression test for each fuzz crash
before merging the fix.
