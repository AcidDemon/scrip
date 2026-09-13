use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    port: u16,
    http_port: u16,
    _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the real binary with the given config body (listen_tcp is appended,
/// bound to port 0) and parse the actual port from the startup log line.
fn start(extra_config: &str) -> Server {
    start_with(extra_config, &[])
}

/// Same as `start`, plus extra CLI args appended after `--config <path>`.
fn start_with(extra_config: &str, extra_args: &[&str]) -> Server {
    start_raw(
        &format!("base_url = \"https://e2e.local\"\n{extra_config}"),
        extra_args,
        &[],
    )
}

/// Same as `start_with`, plus extra env vars set on the child (e.g. the
/// SCRIP_TEST_* timeout hooks).
fn start_with_env(extra_config: &str, extra_args: &[&str], envs: &[(&str, &str)]) -> Server {
    start_raw(
        &format!("base_url = \"https://e2e.local\"\n{extra_config}"),
        extra_args,
        envs,
    )
}

/// Start the real binary with a fully-explicit config body (no base_url
/// injected), used to exercise the config-level default.
fn start_raw(config_body: &str, extra_args: &[&str], envs: &[(&str, &str)]) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("scrip.toml");
    let db = dir.path().join("e2e.db");
    std::fs::write(
        &cfg,
        format!(
            "db_path = \"{}\"\nlisten_tcp = [\"127.0.0.1:0\"]\nlisten_http = [\"127.0.0.1:0\"]\n{config_body}",
            db.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_scrip"))
        .args(["run", "--config"])
        .arg(&cfg)
        .args(extra_args)
        .envs(envs.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            // Send may fail once the receiver gives up waiting; keep
            // draining regardless so the child's stdout pipe never fills.
            let _ = tx.send(line);
        }
    });
    // Guard constructed before the port is known so a panic below still
    // kills the child instead of leaking it.
    let mut sv = Server {
        child,
        port: 0,
        http_port: 0,
        _dir: dir,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    // Two startup lines to catch: "http listening on 127.0.0.1:PORT" and
    // "listening on 127.0.0.1:PORT". Check the http-prefixed pattern first,
    // since the plain TCP pattern is a substring of the HTTP line.
    while sv.port == 0 || sv.http_port == 0 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = rx
            .recv_timeout(remaining)
            .expect("server never reported listening");
        if let Some(rest) = line.split("http listening on 127.0.0.1:").nth(1) {
            sv.http_port = rest.trim().parse().unwrap();
        } else if let Some(rest) = line.split("listening on 127.0.0.1:").nth(1) {
            sv.port = rest.trim().parse().unwrap();
        }
    }
    sv
}

fn connect(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    s
}

/// A banned/closed-early server can reset the connection mid-write rather
/// than accepting it and going silent, so every step here is best-effort:
/// any failure just means fewer bytes made it onto the wire before the
/// reset, which is exactly the "silent close" this helper reports as "".
fn paste(port: u16, body: &[u8]) -> String {
    let mut s = connect(port);
    let _ = s.write_all(body);
    let _ = s.shutdown(Shutdown::Write);
    let mut reply = String::new();
    let _ = s.read_to_string(&mut reply);
    reply
}

fn slug_of(reply: &str) -> &str {
    reply.trim().rsplit('/').next().unwrap()
}

/// Minimal HTTP/1.0 GET client. e2e stays black-box, so it links neither the
/// lib nor tests/support.
fn http_get(port: u16, path: &str) -> (u16, String, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: e2e.local\r\n\r\n").as_bytes())
        .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let status = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, head.to_ascii_lowercase(), buf[split + 4..].to_vec())
}

/// Same, with an X-Forwarded-For line. scrip trusts the header from loopback,
/// which is the only way a black-box test can present itself as a routable
/// client rather than as 127.0.0.1.
fn http_get_as(port: u16, path: &str, client: &str) -> u16 {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.0\r\nHost: e2e.local\r\nX-Forwarded-For: {client}\r\n\r\n")
            .as_bytes(),
    )
    .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

fn db_body(server: &Server, slug: &str) -> Option<Vec<u8>> {
    let db = server._dir.path().join("e2e.db");
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.query_row("SELECT body FROM paste WHERE slug = ?1", [slug], |r| {
        r.get(0)
    })
    .ok()
}

/// Run `cmd`, polling instead of blocking on `.output()`, so a binary that
/// hangs fails the test instead of hanging the whole CI run.
fn output_with_timeout(cmd: &mut Command, timeout: Duration) -> std::process::Output {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + timeout;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child did not exit within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn paste_roundtrip_returns_url_and_stores_exact_bytes() {
    let sv = start("");
    let body = b"fn main() {}\n\x00binary too\xff";
    let reply = paste(sv.port, body);
    assert!(reply.starts_with("https://e2e.local/"), "reply: {reply:?}");
    assert!(reply.ends_with('\n'));
    assert!(
        !reply.contains('\0'),
        "no trailing NUL on the wire (fiche sent one)"
    );
    let slug = slug_of(&reply);
    assert_eq!(slug.len(), 8);
    assert!(slug
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
    assert_eq!(db_body(&sv, slug).unwrap(), body);
}

#[test]
fn empty_paste_stores_nothing() {
    let sv = start("");
    let reply = paste(sv.port, b"");
    assert_eq!(reply, "");
    let conn = rusqlite::Connection::open(sv._dir.path().join("e2e.db")).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM paste", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn oversize_paste_is_refused_and_not_stored() {
    let sv = start("max_paste_bytes = 100\nquota_bytes = 1000\n");
    let reply = paste(sv.port, &[7u8; 200]);
    assert!(reply.contains("too large"), "reply: {reply:?}");
    let conn = rusqlite::Connection::open(sv._dir.path().join("e2e.db")).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM paste", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn idle_client_gets_its_partial_paste_after_the_idle_timeout() {
    let sv = start("idle_timeout_secs = 1\ntotal_deadline_secs = 5\n");
    let mut s = connect(sv.port);
    s.write_all(b"partial data").unwrap();
    // no shutdown: just go quiet
    let t0 = Instant::now();
    let mut reply = String::new();
    s.read_to_string(&mut reply).unwrap();
    assert!(t0.elapsed() >= Duration::from_millis(900));
    assert!(t0.elapsed() < Duration::from_secs(4));
    assert!(reply.starts_with("https://e2e.local/"));
    assert_eq!(db_body(&sv, slug_of(&reply)).unwrap(), b"partial data");
}

#[test]
fn dripper_is_cut_at_the_total_deadline() {
    let sv = start("idle_timeout_secs = 2\ntotal_deadline_secs = 3\n");
    let mut s = connect(sv.port);
    let t0 = Instant::now();
    // drip below the idle threshold; only the total deadline can stop this
    let mut reply = Vec::new();
    loop {
        if s.write_all(b"x").is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
        if t0.elapsed() > Duration::from_secs(20) {
            panic!("server never cut the dripper");
        }
        let mut buf = [0u8; 256];
        s.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                reply.extend_from_slice(&buf[..n]);
                break;
            }
            Err(_) => {} // nothing yet
        }
    }
    assert!(t0.elapsed() >= Duration::from_secs(2), "cut too early");
    assert!(
        t0.elapsed() < Duration::from_secs(15),
        "deadline did not fire"
    );
}

#[test]
fn rate_limit_kicks_in_after_burst() {
    let sv = start("rate_burst = 2\nrate_per_minute = 0.6\n");
    assert!(paste(sv.port, b"one").starts_with("https://"));
    assert!(paste(sv.port, b"two").starts_with("https://"));
    let third = paste(sv.port, b"three");
    assert!(third.contains("rate limited"), "reply: {third:?}");
}

#[test]
fn quota_full_refuses_with_message() {
    // Reject a paste whose body plus 128-byte row overhead exceeds the quota.
    // Otherwise, eviction can make room by deleting pastes older than half
    // their retention while preserving fresh ones.
    let sv = start("max_paste_bytes = 400\nquota_bytes = 500\n");
    let reply = paste(sv.port, &[1u8; 400]); // needs 528 bytes, quota is 500
    assert!(reply.contains("storage full"), "reply: {reply:?}");
    // seed one old paste (created_at far past retention/2) behind the
    // server's back, the way a long-lived deployment accumulates them
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let conn = rusqlite::Connection::open(sv._dir.path().join("e2e.db")).unwrap();
    conn.execute(
        "INSERT INTO paste (slug, body, size, created_at, expires_at, source_ip, source_key)
         VALUES ('old00001', zeroblob(100), 100, 100, ?1, '203.0.113.7', '203.0.113.7')",
        [now + 86_400],
    )
    .unwrap();
    drop(conn);
    // 228 (old) + 228 fresh fit the 500 quota; the second fresh paste must
    // evict the old one rather than refuse
    let first = paste(sv.port, &[1u8; 100]);
    assert!(first.starts_with("https://"), "reply: {first:?}");
    let second = paste(sv.port, &[2u8; 100]);
    assert!(second.starts_with("https://"), "reply: {second:?}");
    assert!(
        db_body(&sv, "old00001").is_none(),
        "the old paste must be evicted"
    );
    assert!(
        db_body(&sv, slug_of(&first)).is_some(),
        "only the old paste should go"
    );
    // nothing old remains: the next paste is refused, the fresh ones survive
    let third = paste(sv.port, &[3u8; 100]);
    assert!(third.contains("storage full"), "reply: {third:?}");
    assert!(
        db_body(&sv, slug_of(&first)).is_some(),
        "fresh pastes must never be evicted"
    );
    assert!(db_body(&sv, slug_of(&second)).is_some());
}

#[test]
fn flag_overrides_config_file_base_url() {
    // config file says e2e.local; --base-url must win
    let sv = start_with("", &["--base-url", "https://from-flag.local"]);
    let reply = paste(sv.port, b"x");
    assert!(
        reply.starts_with("https://from-flag.local/"),
        "reply: {reply:?}"
    );
}

#[test]
fn default_base_url_yields_openable_link() {
    // No base_url line: default must be a real, openable scheme+port, not a
    // dead "https://localhost/<slug>" link. Only
    // the reply's string shape is asserted: the default port (8080) differs
    // from the test's ephemeral port, so GETting this URL would hit nothing
    // real.
    let sv = start_raw("", &[], &[]);
    let reply = paste(sv.port, b"x");
    assert!(
        reply.starts_with("http://localhost:8080/"),
        "reply: {reply:?}"
    );
}

#[test]
fn occupied_port_exits_nonzero_with_diagnostic() {
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = blocker.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scrip"));
    cmd.args(["run", "--db"])
        .arg(dir.path().join("unused-e2e.db"))
        .arg("--listen-tcp")
        .arg(format!("127.0.0.1:{port}"));
    let out = output_with_timeout(&mut cmd, Duration::from_secs(10));
    assert!(
        !out.status.success(),
        "bind conflict must be a nonzero exit (fiche exits 0)"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("bind"));
}

#[test]
fn invalid_config_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("bad.toml");
    std::fs::write(&cfg, "this is not [ toml").unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scrip"));
    cmd.args(["run", "--config"]).arg(&cfg);
    let out = output_with_timeout(&mut cmd, Duration::from_secs(10));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("parse config"));
}

#[test]
fn sigterm_exits_zero_promptly() {
    let sv = start("");
    let pid = sv.child.id().to_string();
    let t0 = Instant::now();
    Command::new("kill").args(["-TERM", &pid]).status().unwrap();
    // poll for exit; Drop's kill() is the failure backstop
    let mut sv = sv;
    let status = loop {
        if let Some(st) = sv.child.try_wait().unwrap() {
            break st;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(15),
            "did not exit after SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(
        status.success(),
        "SIGTERM must be a clean zero exit, got {status:?}"
    );
}

#[test]
fn ban_takes_effect_after_reload_without_restart() {
    let sv = start("ban_reload_secs = 1\n");

    let first = paste(sv.port, b"before ban");
    assert!(first.starts_with("https://"), "reply: {first:?}");

    // Insert a ban row directly.
    let db = sv._dir.path().join("e2e.db");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "INSERT INTO ban (cidr, reason, until) VALUES (?1, ?2, ?3)",
        rusqlite::params!["127.0.0.1/32", "e2e test", Option::<i64>::None],
    )
    .unwrap();
    let n_before: i64 = conn
        .query_row("SELECT COUNT(*) FROM paste", [], |r| r.get(0))
        .unwrap();

    // ban_reload_secs = 1, so 2.5s covers at least one reload tick.
    std::thread::sleep(Duration::from_millis(2500));

    let mut s = connect(sv.port);
    // A banned source gets silence: the server may close before the client
    // even finishes writing, which surfaces here as a reset rather than a
    // clean EOF. Either way, no reply is the point.
    let _ = s.write_all(b"after ban");
    let _ = s.shutdown(Shutdown::Write);
    let mut reply = String::new();
    let _ = s.read_to_string(&mut reply);
    assert!(
        !reply.contains("https://"),
        "banned source must not get a paste URL, got: {reply:?}"
    );

    let n_after: i64 = conn
        .query_row("SELECT COUNT(*) FROM paste", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n_after, n_before, "banned paste must not be stored");
}

#[test]
fn cli_ban_takes_effect_on_a_running_server() {
    let sv = start("ban_reload_secs = 1\n");
    assert!(paste(sv.port, b"before").starts_with("https://"));
    let db = sv._dir.path().join("e2e.db");
    let out = Command::new(env!("CARGO_BIN_EXE_scrip"))
        .args(["ban", "add", "127.0.0.1/32", "--reason", "test"])
        .arg("--db")
        .arg(&db)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // poll until enforced (reload tick ~1s; banned = silent close, empty reply)
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if paste(sv.port, b"after").is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ban never enforced on the live server"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// `scrip ban list` against the server's own database.
fn ban_listing(sv: &Server) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_scrip"))
        .args(["ban", "list"])
        .arg("--db")
        .arg(sv._dir.path().join("e2e.db"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

const AUTOBAN_CONFIG: &str = "read_burst = 1\nread_rate_per_min = 0.6\n\
     autoban_threshold = 3\nautoban_window_secs = 60\nautoban_minutes = 1\n";

#[test]
fn rate_refusals_trigger_an_auto_ban_with_reason() {
    let sv = start(AUTOBAN_CONFIG);

    // The 1st read consumes the burst token; every read after that is rate
    // limited (429) until the 3rd refusal crosses the threshold, at which
    // point BanList::insert applies the ban immediately and the same request
    // starts answering 403.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let st = http_get_as(sv.http_port, "/aaaa", "203.0.113.9");
        if st == 403 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "never auto-banned, last status: {st}"
        );
    }

    let listing = ban_listing(&sv);
    assert!(listing.contains("203.0.113.9/32"), "{listing}");
    assert!(listing.contains("auto"), "{listing}");
}

#[test]
fn tcp_door_rate_refusals_reach_the_autoban_tracker() {
    // This TCP client appears as loopback and cannot be banned. Check its
    // recorded strike to verify that intake::handle calls note_rate_refusal.
    let sv = start(
        "rate_burst = 1\nrate_per_minute = 0.6\n\
         autoban_threshold = 2\nautoban_window_secs = 60\nautoban_minutes = 1\n",
    );

    // The first paste spends the burst token; the next two are refused, and
    // the second refusal crosses the threshold of 2. note_rate_refusal is
    // awaited before the reply is written, so the row is committed by the
    // time we see this.
    let first = paste(sv.port, b"x");
    assert!(first.starts_with("http"), "reply: {first:?}");
    for _ in 0..2 {
        assert_eq!(
            paste(sv.port, b"x"),
            "scrip: rate limited, try again later\n"
        );
    }

    let conn = rusqlite::Connection::open(sv._dir.path().join("e2e.db")).unwrap();
    let (key, strikes): (String, i64) = conn
        .query_row("SELECT source_key, strikes FROM offense", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .expect("the TCP door's rate refusal never reached note_rate_refusal");
    assert_eq!(key, "127.0.0.1/32");
    assert!(strikes >= 1, "strikes: {strikes}");

    // The strike is on record; the ban is not, because the source is loopback.
    assert_eq!(ban_listing(&sv).trim(), "");
}

#[test]
fn loopback_sources_are_never_auto_banned() {
    // Without a forwarded header the client_ip of an HTTP request from a
    // local proxy is the loopback address. Auto-banning it would 403 every
    // reader on the box and export a kernel rule against our own proxy, so
    // refusals from loopback must rate-limit forever and never escalate.
    let sv = start(AUTOBAN_CONFIG);

    let mut saw_429 = false;
    for _ in 0..12 {
        let (st, _, _) = http_get(sv.http_port, "/aaaa");
        saw_429 |= st == 429;
        assert_ne!(st, 403, "a loopback source must never be auto-banned");
    }
    assert!(
        saw_429,
        "the read limiter never refused, test proves nothing"
    );
    assert_eq!(ban_listing(&sv).trim(), "");
}

#[test]
fn per_source_cap_refuses_the_extra_connection_with_a_reply() {
    let sv = start("max_conns_per_source = 2\nidle_timeout_secs = 5\ntotal_deadline_secs = 30\n");

    // Two connections fill the per-source cap; each writes a byte and then
    // parks in the read loop waiting on the idle timeout (no shutdown yet).
    let mut c1 = connect(sv.port);
    c1.write_all(b"a").unwrap();
    let mut c2 = connect(sv.port);
    c2.write_all(b"b").unwrap();
    std::thread::sleep(Duration::from_millis(500)); // let the server register both

    // A 3rd connection is over the cap: refused immediately, before any read.
    let mut c3 = connect(sv.port);
    c3.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    c3.write_all(b"c").unwrap();
    let mut reply3 = String::new();
    c3.read_to_string(&mut reply3).unwrap();
    assert_eq!(reply3, "scrip: too many connections\n");

    // The first two are still healthy: shut down and drain them for a URL each.
    c1.shutdown(Shutdown::Write).unwrap();
    let mut r1 = String::new();
    c1.read_to_string(&mut r1).unwrap();
    assert!(r1.starts_with("https://"), "reply: {r1:?}");

    c2.shutdown(Shutdown::Write).unwrap();
    let mut r2 = String::new();
    c2.read_to_string(&mut r2).unwrap();
    assert!(r2.starts_with("https://"), "reply: {r2:?}");
}

#[test]
fn global_cap_drops_the_extra_connection_without_a_reply() {
    let sv = start("max_conns = 2\nmax_conns_per_source = 5\nidle_timeout_secs = 5\ntotal_deadline_secs = 30\n");

    let mut c1 = connect(sv.port);
    c1.write_all(b"a").unwrap();
    let mut c2 = connect(sv.port);
    c2.write_all(b"b").unwrap();
    std::thread::sleep(Duration::from_millis(500)); // let the server hold both permits

    // A 3rd connection is over the global cap: the accept loop never spawns
    // a task for it, so it gets no protocol reply: EOF or a reset, either
    // way never the start of a URL.
    let mut c3 = connect(sv.port);
    c3.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = c3.write_all(b"c"); // may itself fail if the reset races the write
    let mut buf = [0u8; 16];
    match c3.read(&mut buf) {
        Ok(0) => {}
        Err(_) => {}
        Ok(n) => panic!(
            "3rd connection over the global cap got a reply: {:?}",
            &buf[..n]
        ),
    }

    c1.shutdown(Shutdown::Write).unwrap();
    let mut r1 = String::new();
    c1.read_to_string(&mut r1).unwrap();
    assert!(r1.starts_with("https://"), "reply: {r1:?}");

    c2.shutdown(Shutdown::Write).unwrap();
    let mut r2 = String::new();
    c2.read_to_string(&mut r2).unwrap();
    assert!(r2.starts_with("https://"), "reply: {r2:?}");
}

#[test]
fn unwritable_db_path_exits_nonzero_with_diagnostic() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_scrip"));
    cmd.args(["run", "--db", "/proc/nonexistent/x.db"]);
    let out = output_with_timeout(&mut cmd, Duration::from_secs(10));
    assert!(
        !out.status.success(),
        "unwritable db path must exit nonzero"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("open db"));
}

#[test]
fn full_journey_tcp_paste_to_browser_view() {
    let sv = start("");
    let payload = b"fn main() { println!(\"hi\"); }\n";
    let reply = paste(sv.port, payload);
    assert!(reply.starts_with("https://"), "paste failed: {reply:?}");
    let slug = slug_of(&reply).to_string();

    // viewer page: real 200, html, CSP present, paste bytes ABSENT
    let (st, head, page) = http_get(sv.http_port, &format!("/{slug}"));
    assert_eq!(st, 200);
    assert!(head.contains("content-security-policy"));
    assert!(head.contains("x-content-type-options: nosniff"));
    assert!(
        !String::from_utf8_lossy(&page).contains("println"),
        "paste bytes in HTML"
    );

    // raw: byte-exact
    let (st, head, raw) = http_get(sv.http_port, &format!("/raw/{slug}"));
    assert_eq!(st, 200);
    assert!(head.contains("content-type: text/plain; charset=utf-8"));
    assert_eq!(raw, payload);

    // assets the viewer needs actually resolve
    for a in [
        "/assets/hl.js",
        "/assets/view.js",
        "/assets/view.css",
        // The default theme linked by view.html.
        "/assets/theme-github-dark.css",
    ] {
        let (st, _, body) = http_get(sv.http_port, a);
        assert_eq!(st, 200, "{a}");
        assert!(!body.is_empty(), "{a} empty");
    }
}

#[test]
fn http_post_is_a_full_write_path() {
    let sv = start("");
    let mut s = TcpStream::connect(("127.0.0.1", sv.http_port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let body = b"posted via curl path";
    s.write_all(
        format!(
            "POST / HTTP/1.0\r\nHost: e2e.local\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )
    .unwrap();
    s.write_all(body).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf);
    assert!(text.contains("https://e2e.local/"), "{text}");
    let slug = text.trim_end().rsplit('/').next().unwrap().to_string();
    // wrote through the same store the TCP door reads
    assert_eq!(db_body(&sv, &slug).unwrap(), body);
}

#[test]
fn http_slow_header_client_is_cut_by_the_header_timeout() {
    let sv = start("");
    let mut s = TcpStream::connect(("127.0.0.1", sv.http_port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: e2e.local\r\n")
        .unwrap(); // never finishes headers
    let t0 = Instant::now();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf); // server must close the connection
    assert!(
        t0.elapsed() >= Duration::from_secs(5),
        "closed too fast to be the header timeout"
    );
    assert!(
        t0.elapsed() < Duration::from_secs(15),
        "header timeout never fired"
    );
}

#[test]
fn request_timeout_returns_504() {
    let sv = start_with_env("", &[], &[("SCRIP_TEST_REQUEST_TIMEOUT_SECS", "1")]);
    let mut s = TcpStream::connect(("127.0.0.1", sv.http_port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(b"POST / HTTP/1.1\r\nHost: e2e.local\r\nContent-Length: 100\r\n\r\n")
        .unwrap();
    s.write_all(&[b'x'; 10]).unwrap(); // only 10 of the promised 100 bytes; hold the rest
    let t0 = Instant::now();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "504 never arrived within the shortened request timeout window"
    );
    let head = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 504"), "response: {head:?}");
    assert!(
        head.contains("x-content-type-options: nosniff"),
        "response: {head:?}"
    );
}

/// Checks the drain deadline by trickling bytes without closing the client's
/// write side. The ~30-byte reply is too small to exercise a stalled write;
/// this test covers only the drain portion of `reply_and_close`.
#[test]
fn reply_deadline_drains_and_closes_within_the_deadline() {
    let sv = start_with_env(
        "idle_timeout_secs = 1\ntotal_deadline_secs = 30\n",
        &[],
        &[("SCRIP_TEST_REPLY_DEADLINE_SECS", "1")],
    );
    let mut s = connect(sv.port);
    let t0 = Instant::now();
    s.write_all(b"partial paste, no shutdown").unwrap();

    // The trickle waits 1300ms, past idle_timeout_secs, so the read really
    // idles out first; a constant stream would just keep extending it. After
    // that it runs forever without shutting down the write side, which keeps
    // the server's post-reply drain busy until the reply deadline cuts it off.
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let mut w = s.try_clone().unwrap();
        let stop = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1300));
            while !stop.load(Ordering::Relaxed) {
                if w.write_all(b"x").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
    };

    let mut reply = Vec::new();
    s.read_to_end(&mut reply).unwrap(); // blocks until the server drops the connection
    let elapsed = t0.elapsed();
    stop.store(true, Ordering::Relaxed);
    let _ = writer.join();

    assert!(
        String::from_utf8_lossy(&reply).starts_with("https://"),
        "reply: {reply:?}"
    );
    // idle_timeout (1s) elapses before the reply is even written, then the
    // reply deadline (1s) bounds the drain: deadline + idle + slack (widened
    // for loaded-runner headroom).
    assert!(
        elapsed < Duration::from_secs(6),
        "connection stayed open {elapsed:?} past deadline + idle + slack"
    );
}

#[test]
fn h2c_preface_is_rejected_not_hung() {
    let sv = start("");
    let mut s = TcpStream::connect(("127.0.0.1", sv.http_port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    let t0 = Instant::now();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf); // server must close the connection, not upgrade to h2
    assert!(
        t0.elapsed() < Duration::from_secs(15),
        "h2c preface was not rejected promptly"
    );
}

#[test]
fn reaper_removes_expired_rows_while_running() {
    let sv = start("gc_interval_secs = 1\n");
    // a live paste through the front door
    let reply = paste(sv.port, b"live");
    assert!(reply.starts_with("https://"), "paste failed: {reply:?}");
    let live = slug_of(&reply).to_string();
    // an already-expired row planted behind the server's back
    {
        let conn = rusqlite::Connection::open(sv._dir.path().join("e2e.db")).unwrap();
        conn.execute(
            "INSERT INTO paste (slug, body, size, created_at, expires_at, source_ip)
             VALUES ('dead0000', x'00', 1, 1, 2, '::1')",
            [],
        )
        .unwrap();
    }
    // Poll for the reaper tick until the deadline.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let conn = rusqlite::Connection::open(sv._dir.path().join("e2e.db")).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM paste WHERE slug = 'dead0000'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        if n == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "reaper never removed the expired row"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    // the live paste survived
    assert_eq!(db_body(&sv, &live).unwrap(), b"live");
}

#[test]
fn encrypted_nc_paste_replies_one_token_line_and_reads_back() {
    let sv = start("encrypt_at_rest = true\n");
    let reply = paste(sv.port, b"enc over nc");
    assert_eq!(reply.lines().count(), 1, "nc reply stays one line");
    let token = slug_of(&reply);
    assert_eq!(token.len(), 26);
    let (st, _, body) = http_get(sv.http_port, &format!("/raw/{token}"));
    assert_eq!(st, 200);
    assert_eq!(body, b"enc over nc");
}
