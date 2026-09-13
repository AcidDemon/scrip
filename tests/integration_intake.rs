use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use scrip::config::Config;
use scrip::intake::{accept_loop, bind_tcp, Ctx};
use scrip::store::Store;

/// Deterministic slug source cycling through a fixed list, then repeating the
/// last entry forever. Tests substitute this rather than ever seeding the
/// production RNG; it owns its own counter, so the two tests in this binary
/// cannot interfere with each other.
fn fixed_slugs(slugs: Vec<&'static str>) -> Box<dyn Fn() -> String + Send + Sync> {
    let i = AtomicUsize::new(0);
    Box::new(move || {
        let n = i.fetch_add(1, Ordering::Relaxed);
        slugs[n.min(slugs.len() - 1)].to_string()
    })
}

fn paste(port: u16, body: &[u8]) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(body).unwrap();
    s.shutdown(Shutdown::Write).unwrap();
    let mut reply = String::new();
    s.read_to_string(&mut reply).unwrap();
    reply
}

#[tokio::test(flavor = "multi_thread")]
async fn slug_conflict_regenerates_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        db_path: dir.path().join("t.db"),
        base_url: "https://t.local".into(),
        ..Default::default()
    };
    let store = Store::open(&config.db_path).unwrap();

    // First generate() call (paste 1) yields "aaaaaaaa". Second call (paste 2,
    // attempt 0) yields "aaaaaaaa" again, a PK conflict. Third call (paste 2,
    // attempt 1, the single regeneration) yields "bbbbbbbb".
    let ctx = Arc::new(Ctx {
        slugs: fixed_slugs(vec!["aaaaaaaa", "aaaaaaaa", "bbbbbbbb"]),
        ..Ctx::new(config, store)
    });

    let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(accept_loop(listener, ctx.clone(), rx));

    let r1 = tokio::task::spawn_blocking(move || paste(port, b"one"))
        .await
        .unwrap();
    assert_eq!(r1, "https://t.local/aaaaaaaa\n");

    let r2 = tokio::task::spawn_blocking(move || paste(port, b"two"))
        .await
        .unwrap();
    assert_eq!(r2, "https://t.local/bbbbbbbb\n", "conflict must regenerate");

    assert_eq!(ctx.store.get_paste("aaaaaaaa").unwrap().unwrap(), b"one");
    assert_eq!(ctx.store.get_paste("bbbbbbbb").unwrap().unwrap(), b"two");
}

#[tokio::test(flavor = "multi_thread")]
async fn second_conflict_gives_up_instead_of_looping() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        db_path: dir.path().join("t.db"),
        base_url: "https://t.local".into(),
        ..Default::default()
    };
    let store = Store::open(&config.db_path).unwrap();

    // gen yields "aaaaaaaa" forever: paste 1 takes it; paste 2's attempt 0
    // collides, its single regeneration collides again -> must reply
    // "scrip: internal error" rather than retrying forever.
    let ctx = Arc::new(Ctx {
        slugs: fixed_slugs(vec!["aaaaaaaa", "aaaaaaaa", "aaaaaaaa"]),
        ..Ctx::new(config, store)
    });

    let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    tokio::spawn(accept_loop(listener, ctx.clone(), rx));

    let r1 = tokio::task::spawn_blocking(move || paste(port, b"one"))
        .await
        .unwrap();
    assert_eq!(r1, "https://t.local/aaaaaaaa\n");

    let r2 = tokio::task::spawn_blocking(move || paste(port, b"two"))
        .await
        .unwrap();
    assert_eq!(r2, "scrip: internal error\n");

    // and nothing extra stored
    assert_eq!(ctx.store.get_paste("aaaaaaaa").unwrap().unwrap(), b"one");
}
