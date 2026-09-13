#![allow(dead_code)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use scrip::config::Config;
use scrip::intake::Ctx;
use scrip::store::Store;

pub struct TestServer {
    pub port: u16,
    pub ctx: Arc<Ctx>,
    pub _dir: tempfile::TempDir,
    // Keeps the http::serve accept loop alive: dropping the sender resolves
    // the receiver's `changed()` (with an error) same as sending `true`,
    // which would shut the loop down as soon as `serve()` returns.
    _shutdown_tx: tokio::sync::watch::Sender<bool>,
}

pub async fn serve(mut mutate: impl FnMut(&mut Config)) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config {
        db_path: dir.path().join("t.db"),
        base_url: "https://t.local".into(),
        ..Default::default()
    };
    mutate(&mut config);
    let store = Store::open(&config.db_path).unwrap();
    let ctx = Arc::new(Ctx::new(config, store));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    scrip::http::serve(listener, ctx.clone(), shutdown_rx);
    TestServer {
        port,
        ctx,
        _dir: dir,
        _shutdown_tx: shutdown_tx,
    }
}

/// Minimal HTTP/1.0 client: 1.0 means the server closes and never chunks,
/// so read-to-EOF then split at the header boundary.
pub fn request(port: u16, raw: &str, body: &[u8]) -> (u16, HashMap<String, String>, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("no header boundary");
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let payload = buf[split + 4..].to_vec();
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect();
    (status, headers, payload)
}

pub fn get(port: u16, path: &str) -> (u16, HashMap<String, String>, Vec<u8>) {
    request(
        port,
        &format!("GET {path} HTTP/1.0\r\nHost: t.local\r\n\r\n"),
        b"",
    )
}

pub fn post(port: u16, body: &[u8], extra: &str) -> (u16, HashMap<String, String>, Vec<u8>) {
    request(
        port,
        &format!(
            "POST / HTTP/1.0\r\nHost: t.local\r\n{extra}Content-Length: {}\r\n\r\n",
            body.len()
        ),
        body,
    )
}

pub fn far() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 86_400
}
