use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use scrip::config::Config;
use scrip::intake::{accept_loop, bind_tcp, note_rate_refusal, now_epoch, Ctx};
use scrip::policy::Admit;
use scrip::store::Store;

mod support;
use support::{get, post, serve};

#[tokio::test(flavor = "multi_thread")]
async fn traversal_and_injection_slugs_never_reach_anything() {
    let sv = serve(|_| {}).await;
    let hostile = [
        "/raw/../../etc/passwd",
        "/raw/..%2f..%2fetc%2fpasswd",
        "/raw/%2e%2e",
        "/raw/a%00b",
        "/raw/a'or'1'='1",
        "/raw/a;DROP%20TABLE%20paste",
        "/raw/AAAAAAAA",
        "/raw/aaaaaaaaaaaaaaaaa",
        "/../../etc/passwd",
        "/%2e%2e%2f%2e%2e",
    ];
    for path in hostile {
        let (st, _, body) = get(sv.port, path);
        assert!(
            st == 404 || st == 400,
            "{path} returned {st}: {:?}",
            String::from_utf8_lossy(&body[..body.len().min(120)])
        );
        let text = String::from_utf8_lossy(&body);
        assert!(!text.contains("root:"), "{path} leaked a file");
        assert!(!text.contains("SQL"), "{path} leaked an SQL error");
        assert!(!text.contains("rusqlite"), "{path} leaked an SQL error");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn paste_bytes_never_enter_html() {
    let sv = serve(|_| {}).await;
    let marker = b"<script>alert(1)</script><!--XSSMARKER7f3a-->";
    let (st, _, body) = post(sv.port, marker, "");
    assert_eq!(st, 200);
    let slug = String::from_utf8(body)
        .unwrap()
        .trim()
        .rsplit('/')
        .next()
        .unwrap()
        .to_string();

    // /raw may echo the hostile bytes back verbatim only because text/plain
    // plus nosniff defuses them.
    let (st, h, page) = get(sv.port, &format!("/{slug}"));
    assert_eq!(st, 200);
    assert!(h["content-type"].starts_with("text/html"));
    assert!(
        !String::from_utf8_lossy(&page).contains("XSSMARKER7f3a"),
        "paste bytes leaked into HTML"
    );

    let (st, h, raw) = get(sv.port, &format!("/raw/{slug}"));
    assert_eq!(st, 200);
    assert_eq!(h["content-type"], "text/plain; charset=utf-8");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(raw, marker);
}

#[tokio::test(flavor = "multi_thread")]
async fn csp_and_nosniff_asserted_here_too() {
    // Duplicated from tests/http_api.rs so a refactor of src/http.rs cannot
    // silently drop the security headers.
    let sv = serve(|_| {}).await;
    let (_, h, _) = get(sv.port, "/");
    assert_eq!(
        h["content-security-policy"],
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
         frame-ancestors 'none'; base-uri 'none'"
    );
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["x-content-type-options"], "nosniff");
}

#[tokio::test(flavor = "multi_thread")]
async fn spoofed_xff_from_non_loopback_is_ignored() {
    // In-process the peer is loopback, so this asserts the inverse property
    // reachable from here: garbage XFF falls back to the peer instead of
    // being trusted.
    let sv = serve(|c| {
        c.rate_burst = 1.0;
        c.rate_per_minute = 0.6;
    })
    .await;
    let (st, _, _) = post(sv.port, b"a", "X-Forwarded-For: not, an, ip\r\n");
    assert_eq!(st, 200);
    // same fallback bucket (the loopback peer) => limited
    let (st, _, _) = post(sv.port, b"b", "X-Forwarded-For: also-garbage\r\n");
    assert_eq!(st, 429);
}

#[tokio::test(flavor = "multi_thread")]
async fn banned_client_cannot_bypass_via_extra_leading_xff_line() {
    // HAProxy/Traefik append a new X-Forwarded-For header line rather than
    // editing one the client supplied. An attacker who supplies their own
    // first line must not be able to hide the proxy-appended (real) IP.
    let sv = serve(|_| {}).await;
    sv.ctx
        .bans
        .replace(vec![("203.0.113.0/24".parse().unwrap(), None)]);
    let (st, _, _) = post(
        sv.port,
        b"x",
        "X-Forwarded-For: 198.51.100.9\r\nX-Forwarded-For: 203.0.113.9\r\n",
    );
    assert_eq!(st, 403, "last XFF line (the banned IP) must win");
}

#[tokio::test(flavor = "multi_thread")]
async fn view_page_of_missing_paste_carries_no_reflection() {
    let sv = serve(|_| {}).await;
    // slug is valid-shaped but absent; 404 page must be the static page,
    // not anything echoing the request
    let (st, _, body) = get(sv.port, "/qqqqqqqq");
    assert_eq!(st, 404);
    assert!(!String::from_utf8_lossy(&body).contains("qqqqqqqq"));
}

/// Binds `src:0` before connecting so the accept side sees `src` as the peer
/// address instead of the outbound interface's own address.
fn connect_from(src: &str, port: u16) -> TcpStream {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    s.bind(
        &format!("{src}:0")
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
    )
    .unwrap();
    s.connect(
        &format!("127.0.0.1:{port}")
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
    )
    .unwrap();
    s.into()
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread")]
async fn dripping_sources_cannot_starve_a_compliant_client() {
    // Binding a source address other than 127.0.0.1 relies on 127/8 routing
    // entirely to lo, which holds on Linux (the deployment target) but not
    // reliably elsewhere. Skip rather than fail on a runner that can't do it.
    {
        use socket2::{Domain, Protocol, Socket, Type};
        let probe = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        let addr: std::net::SocketAddr = "127.0.0.2:0".parse().unwrap();
        if probe.bind(&addr.into()).is_err() {
            eprintln!(
                "skipping dripping_sources_cannot_starve_a_compliant_client: \
                 cannot bind 127.0.0.2 as a source address (non-Linux runner?)"
            );
            return;
        }
    }

    // This test drives the TCP intake door directly (not the HTTP door
    // `serve()` above wires up), so it builds its own Ctx the way
    // tests/integration_intake.rs does.
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        db_path: dir.path().join("t.db"),
        base_url: "https://t.local".into(),
        max_conns: 25,
        max_conns_per_source: 5,
        idle_timeout_secs: 2,
        total_deadline_secs: 4,
        rate_burst: 50.0, // generous: the property under test is the conn cap, not the rate limit
        ..Default::default()
    };
    let store = Store::open(&config.db_path).unwrap();
    let ctx = Arc::new(Ctx::new(config, store));

    let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(accept_loop(listener, ctx.clone(), rx));

    // 4 hostile sources x 5 connections fill 20 of 25 permits; the compliant
    // client from a 5th source must still be served. TCP door only.
    let drippers = tokio::task::spawn_blocking(move || {
        let mut drippers = Vec::new();
        for i in 2..=5 {
            for _ in 0..5 {
                let mut c = connect_from(&format!("127.0.0.{i}"), port);
                c.write_all(b"x").unwrap(); // 1 byte, then silence: parked in the read loop
                drippers.push(c);
            }
        }
        // let the accept loop register every dripper before the compliant
        // client arrives. Permits are taken in the accept task, not at
        // connect()
        std::thread::sleep(Duration::from_millis(500));

        // 127.0.0.2 is now at its per-source cap (5/5); a 6th connection from
        // the same source must be refused immediately with the cap reply,
        // not parked. This is what would fail if the per-source cap regressed
        // to a no-op.
        let mut refused = connect_from("127.0.0.2", port);
        refused
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        refused.write_all(b"y").unwrap();
        let mut refused_reply = String::new();
        refused.read_to_string(&mut refused_reply).unwrap();
        assert_eq!(refused_reply, "scrip: too many connections\n");

        drippers
    })
    .await
    .unwrap();

    // compliant client from yet another source
    let reply = tokio::task::spawn_blocking(move || {
        let mut ok = connect_from("127.0.0.6", port);
        ok.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        ok.write_all(b"hello").unwrap();
        ok.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        ok.read_to_string(&mut reply).unwrap();
        reply
    })
    .await
    .unwrap();

    assert!(
        reply.starts_with("https://"),
        "compliant client starved: {reply:?}"
    );
    drop(drippers); // idle timeout would have stored their 1-byte pastes; irrelevant
}

#[tokio::test(flavor = "multi_thread")]
async fn four_sibling_autobans_escalate_the_fifth_to_a_48_ban() {
    // With 4 sibling /64s inside one /48 already holding active auto-bans,
    // the next auto-ban in that /48 must land on the covering /48 rather
    // than a fifth /64 row. note_rate_refusal is the whole path under test,
    // so no listener is needed.
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        db_path: dir.path().join("t.db"),
        base_url: "https://t.local".into(),
        autoban_threshold: 1, // the first refusal trips
        autoban_window_secs: 60,
        autoban_minutes: 30,
        ..Default::default()
    };
    let store = Store::open(&config.db_path).unwrap();
    let ctx = Arc::new(Ctx::new(config, store));

    let until = now_epoch() + 3600;
    for i in 1..=4 {
        ctx.store
            .extend_ban(
                &format!("2001:db8:1:{i}::/64"),
                Some("auto: rate abuse"),
                Some(until),
            )
            .unwrap();
    }

    // a refusal from a fifth /64 in the same /48 crosses threshold 1. The
    // source tier is what refused here: the /64 spent its own budget.
    note_rate_refusal(
        &ctx,
        "2001:db8:1:5::9".parse().unwrap(),
        Admit::RefusedSource,
    )
    .await;

    let rows = ctx.store.ban_rows().unwrap();
    assert!(
        rows.iter().any(|(cidr, _, _)| cidr == "2001:db8:1::/48"),
        "expected a /48 ban, got {rows:?}"
    );
    assert!(
        !rows.iter().any(|(cidr, _, _)| cidr == "2001:db8:1:5::/64"),
        "the /48 ban must replace the fifth /64 row, got {rows:?}"
    );
    // and the in-memory list blocks the whole /48 immediately
    assert!(ctx
        .bans
        .is_banned("2001:db8:1:aaaa::1".parse().unwrap(), now_epoch()));
}

#[tokio::test(flavor = "multi_thread")]
async fn only_rate_limit_refusals_feed_the_autoban_tracker() {
    // "too many connections" (the per-source connection cap) and "rate
    // limited" are both refusals a client can see, but only the rate
    // limiter's own refusal is wired to note_rate_refusal. With
    // autoban_threshold = 1, repeatedly tripping the connection cap must
    // never produce a ban row; a single real rate-limit refusal must, once
    // it comes from an address that is a legitimate ban target.
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        db_path: dir.path().join("t.db"),
        base_url: "https://t.local".into(),
        max_conns_per_source: 1,
        // burst 2: the held connection itself consumes a token on accept
        // (try_acquire runs before the read loop), leaving exactly one for
        // the "first" paste below and none for the "second".
        rate_burst: 2.0,
        rate_per_minute: 0.6,
        autoban_threshold: 1,
        autoban_window_secs: 60,
        autoban_minutes: 30,
        idle_timeout_secs: 5,
        total_deadline_secs: 10,
        ..Default::default()
    };
    let store = Store::open(&config.db_path).unwrap();
    let ctx = Arc::new(Ctx::new(config, store));

    let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(accept_loop(listener, ctx.clone(), rx));

    // Hold one connection open (parked mid-read) to occupy the per-source
    // cap of 1, then repeatedly trip "too many connections" from the same
    // source. None of this is a rate-limit refusal.
    let held = tokio::task::spawn_blocking(move || {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.write_all(b"x").unwrap(); // 1 byte, then parks
        c
    })
    .await
    .unwrap();
    // let the accept loop register the held connection (and its per_source
    // slot) before the cap-refusal connections race in behind it.
    tokio::time::sleep(Duration::from_millis(500)).await;

    tokio::task::spawn_blocking(move || {
        for _ in 0..5 {
            let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut reply = String::new();
            c.read_to_string(&mut reply).unwrap();
            assert_eq!(reply, "scrip: too many connections\n");
        }
    })
    .await
    .unwrap();

    assert!(
        ctx.store.ban_rows().unwrap().is_empty(),
        "connection-cap refusals must not feed the auto-ban tracker"
    );

    drop(held); // free the per-source slot
    tokio::time::sleep(Duration::from_millis(200)).await; // let the server notice the close

    // Consume the single rate-limit burst token with a real paste.
    let first = tokio::task::spawn_blocking(move || {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(b"a").unwrap();
        c.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        c.read_to_string(&mut reply).unwrap();
        reply
    })
    .await
    .unwrap();
    assert!(first.starts_with("https://"), "reply: {first:?}");

    // The very next paste is genuinely rate-limited: with threshold = 1
    // this single refusal must trip the ban immediately.
    let second = tokio::task::spawn_blocking(move || {
        let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.write_all(b"b").unwrap();
        c.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        c.read_to_string(&mut reply).unwrap();
        reply
    })
    .await
    .unwrap();
    assert_eq!(second, "scrip: rate limited, try again later\n");

    // That refusal reached note_rate_refusal and crossed the threshold, but
    // the source is 127.0.0.1 and loopback is never a ban target: banning it
    // would 403 every local reader and export a kernel rule against our own proxy.
    assert!(
        ctx.store.ban_rows().unwrap().is_empty(),
        "loopback must never be auto-banned"
    );

    // The same refusal from a routable source does write the ban row.
    note_rate_refusal(
        &ctx,
        "203.0.113.9".parse().unwrap(),
        scrip::policy::Admit::RefusedSource,
    )
    .await;
    let rows = ctx.store.ban_rows().unwrap();
    assert_eq!(rows.len(), 1, "one real rate-limit refusal must ban");
    assert_eq!(rows[0].0, "203.0.113.9/32");
    assert!(rows[0].1.as_deref().unwrap_or("").contains("auto"));
}

#[tokio::test(flavor = "multi_thread")]
async fn rotating_64s_inside_one_48_still_earns_a_ban() {
    // The aggregate tier is what refuses an attacker who rotates /64s: each
    // fresh /64 draws a full bucket of its own, so the /48 budget is the one
    // that runs out. Those refusals have to be recorded against the /48, or
    // they scatter across 65,536 keys that never reach the threshold and the
    // attacker is refused forever at no cost.
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        db_path: dir.path().join("t.db"),
        base_url: "https://t.local".into(),
        autoban_threshold: 1, // the /48 bar is AGGREGATE_FACTOR x this
        autoban_window_secs: 60,
        autoban_minutes: 30,
        ..Default::default()
    };
    let store = Store::open(&config.db_path).unwrap();
    let ctx = Arc::new(Ctx::new(config, store));

    // one short of the bar, each refusal from a different /64
    let bar = scrip::policy::AGGREGATE_FACTOR;
    for i in 1..bar {
        let ip = format!("2001:db8:7:{i}::9").parse().unwrap();
        note_rate_refusal(&ctx, ip, Admit::RefusedAggregate).await;
    }
    assert!(
        ctx.store.ban_rows().unwrap().is_empty(),
        "under the /48 bar nothing should be banned yet"
    );

    // the one that crosses it lands on the /48, not a /64
    note_rate_refusal(
        &ctx,
        format!("2001:db8:7:{bar}::9").parse().unwrap(),
        Admit::RefusedAggregate,
    )
    .await;
    let rows = ctx.store.ban_rows().unwrap();
    assert!(
        rows.iter().any(|(cidr, _, _)| cidr == "2001:db8:7::/48"),
        "expected the /48 to be banned, got {rows:?}"
    );
    assert!(
        !rows.iter().any(|(cidr, _, _)| cidr.ends_with("/64")),
        "no individual /64 should be banned, got {rows:?}"
    );
    assert!(
        ctx.bans
            .is_banned("2001:db8:7:99::1".parse().unwrap(), now_epoch()),
        "an unused /64 inside the banned /48 must be covered in memory too"
    );
}
