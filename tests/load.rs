//! Load smoke and soak harness. Both tests are `#[ignore]`d: they build and
//! run the real binary under sustained load, so they only run on request:
//!
//!   cargo test --release --test load -- --ignored load_smoke
//!   SCRIP_SOAK_MINUTES=1 cargo test --release --test load -- --ignored soak_ten_minutes
//!
//! `CARGO_BIN_EXE_scrip` resolves to the binary of the profile under test.
//! CI runs these with `--release`, so run them that way locally too or the
//! thresholds (tuned against a release build) won't mean much.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(serde::Deserialize)]
struct Thresholds {
    load_smoke: LoadSmoke,
    soak: Soak,
}

#[derive(serde::Deserialize)]
struct LoadSmoke {
    paste_connections: usize,
    http_reads: usize,
    p99_ms: u64,
    max_rss_mib: u64,
}

#[derive(serde::Deserialize)]
struct Soak {
    minutes: u64,
    max_rss_growth_mib: u64,
    max_fd_growth: i64,
}

fn thresholds() -> Thresholds {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/thresholds.toml");
    let text = std::fs::read_to_string(path).expect("read thresholds.toml");
    toml::from_str(&text).expect("parse thresholds.toml")
}

/// Crank policy limits so the load itself never gets throttled: every
/// connection in these tests comes from 127.0.0.1, i.e. a single source.
const CRANKED_CONFIG: &str =
    "rate_per_minute = 100000\nrate_burst = 10000\nread_rate_per_min = 100000\nread_burst = 10000\nmax_conns_per_source = 600\nmax_pastes_per_source = 0\n";

struct Server {
    child: Child,
    pid: u32,
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

/// Start the real binary and parse its startup log for the bound port.
fn start(extra_config: &str) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("scrip.toml");
    let db = dir.path().join("load.db");
    std::fs::write(
        &cfg,
        format!(
            "base_url = \"https://load.local\"\ndb_path = \"{}\"\nlisten_tcp = [\"127.0.0.1:0\"]\nlisten_http = [\"127.0.0.1:0\"]\n{extra_config}",
            db.display()
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_scrip"))
        .args(["run", "--config"])
        .arg(&cfg)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let mut sv = Server {
        child,
        pid,
        port: 0,
        http_port: 0,
        _dir: dir,
    };
    let deadline = Instant::now() + Duration::from_secs(10);
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

fn paste(port: u16, body: &[u8]) -> std::io::Result<String> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.write_all(body)?;
    s.shutdown(Shutdown::Write)?;
    let mut reply = String::new();
    s.read_to_string(&mut reply)?;
    Ok(reply)
}

/// Minimal HTTP/1.0 GET: returns the status code.
fn http_get(port: u16, path: &str) -> std::io::Result<u16> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    s.write_all(format!("GET {path} HTTP/1.0\r\nHost: load.local\r\n\r\n").as_bytes())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf)?;
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("no header terminator"))?;
    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    head.lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| std::io::Error::other("no status code"))
}

fn rss_mib(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read status");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .expect("parse VmRSS");
            return kb / 1024;
        }
    }
    panic!("VmRSS not found in /proc/{pid}/status");
}

fn fd_count(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("read fd dir")
        .count()
}

/// Run `items` units of work across `threads` workers, each claiming the next
/// index off a shared counter.
fn run_pool<F>(threads: usize, items: usize, f: F)
where
    F: Fn(usize) + Send + Sync,
{
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            let f = &f;
            let next = &next;
            scope.spawn(move || loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= items {
                    break;
                }
                f(i);
            });
        }
    });
}

#[test]
#[ignore]
fn load_smoke() {
    let t = thresholds();
    let sv = start(CRANKED_CONFIG);
    let port = sv.port;
    let http_port = sv.http_port;

    // seed one paste so the HTTP reads have a slug to hit
    let seed = paste(port, b"load smoke seed paste").expect("seed paste");
    assert!(seed.starts_with("https://"), "seed paste failed: {seed:?}");
    let slug = seed.trim().rsplit('/').next().unwrap().to_string();

    // Separate distributions against the same p99_ms threshold: one door's
    // regression must not hide in the other's margin.
    let paste_latencies = Arc::new(Mutex::new(Vec::<u128>::new()));
    let http_latencies = Arc::new(Mutex::new(Vec::<u128>::new()));
    let errors = Arc::new(AtomicUsize::new(0));

    run_pool(50, t.load_smoke.paste_connections, {
        let latencies = Arc::clone(&paste_latencies);
        let errors = Arc::clone(&errors);
        move |i| {
            let mut body = format!("load smoke paste {i} ").into_bytes();
            body.resize(1024, b'x');
            let t0 = Instant::now();
            match paste(port, &body) {
                Ok(reply) if reply.starts_with("https://") => {
                    latencies.lock().unwrap().push(t0.elapsed().as_millis());
                }
                _ => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });

    run_pool(50, t.load_smoke.http_reads, {
        let latencies = Arc::clone(&http_latencies);
        let errors = Arc::clone(&errors);
        let slug = slug.clone();
        move |_| {
            let t0 = Instant::now();
            match http_get(http_port, &format!("/{slug}")) {
                Ok(200) => latencies.lock().unwrap().push(t0.elapsed().as_millis()),
                _ => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });

    let errs = errors.load(Ordering::Relaxed);
    assert_eq!(errs, 0, "load_smoke saw {errs} failed requests");

    let p99_of = |latencies: &Mutex<Vec<u128>>| -> u128 {
        let mut lat = latencies.lock().unwrap().clone();
        lat.sort_unstable();
        lat[lat.len() * 99 / 100]
    };
    let paste_p99 = p99_of(&paste_latencies);
    assert!(
        paste_p99 <= t.load_smoke.p99_ms as u128,
        "paste p99 latency {paste_p99}ms exceeds threshold {}ms",
        t.load_smoke.p99_ms
    );
    let http_p99 = p99_of(&http_latencies);
    assert!(
        http_p99 <= t.load_smoke.p99_ms as u128,
        "http p99 latency {http_p99}ms exceeds threshold {}ms",
        t.load_smoke.p99_ms
    );

    let rss = rss_mib(sv.pid);
    assert!(
        rss <= t.load_smoke.max_rss_mib,
        "RSS {rss}MiB exceeds threshold {}MiB",
        t.load_smoke.max_rss_mib
    );
}

#[test]
#[ignore]
fn soak_ten_minutes() {
    let t = thresholds();
    let minutes: u64 = std::env::var("SCRIP_SOAK_MINUTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(t.soak.minutes);

    let mut sv = start(CRANKED_CONFIG);
    let port = sv.port;
    let http_port = sv.http_port;

    let seed = paste(port, b"soak seed paste").expect("seed paste");
    assert!(seed.starts_with("https://"), "seed paste failed: {seed:?}");
    let slug = seed.trim().rsplit('/').next().unwrap().to_string();

    // let the server settle from startup before taking the baseline
    std::thread::sleep(Duration::from_millis(500));
    let rss_start = rss_mib(sv.pid);
    let fd_start = fd_count(sv.pid);

    let mut errors = 0u64;
    let mut i = 0usize;
    let deadline = Instant::now() + Duration::from_secs(minutes * 60);
    while Instant::now() < deadline {
        let mut body = format!("soak paste {i} ").into_bytes();
        body.resize(1024, b'x');
        match paste(port, &body) {
            Ok(reply) if reply.starts_with("https://") => {}
            _ => errors += 1,
        }
        match http_get(http_port, &format!("/{slug}")) {
            Ok(200) => {}
            _ => errors += 1,
        }
        i += 1;
        // Stop on the first error; the test requires zero errors to pass.
        if errors > 0 {
            break;
        }
    }
    assert_eq!(
        errors, 0,
        "soak saw {errors} failed requests over {i} iterations"
    );

    let rss_end = rss_mib(sv.pid);
    let fd_end = fd_count(sv.pid);

    let rss_growth = rss_end.saturating_sub(rss_start);
    assert!(
        rss_growth <= t.soak.max_rss_growth_mib,
        "RSS grew {rss_growth}MiB ({rss_start}MiB -> {rss_end}MiB), threshold {}MiB",
        t.soak.max_rss_growth_mib
    );

    let fd_growth = fd_end as i64 - fd_start as i64;
    assert!(
        fd_growth <= t.soak.max_fd_growth,
        "fd count grew by {fd_growth} ({fd_start} -> {fd_end}), threshold {}",
        t.soak.max_fd_growth
    );

    // clean shutdown must exit 0
    Command::new("kill")
        .args(["-TERM", &sv.pid.to_string()])
        .status()
        .unwrap();
    let t0 = Instant::now();
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
