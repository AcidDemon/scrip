use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::{timeout_at, Instant};

#[derive(Debug, PartialEq)]
pub enum ReadOutcome {
    Complete(Vec<u8>),
    TooLarge,
    Empty,
}

/// EOF, idle timeout, or the total deadline returns the bytes received so far.
/// Exceeding the size cap aborts. The total deadline prevents a client from
/// keeping the connection open indefinitely by sending just before each idle
/// timeout.
pub async fn read_paste<R: AsyncRead + Unpin>(
    stream: &mut R,
    cap: usize,
    idle: Duration,
    total: Duration,
) -> std::io::Result<ReadOutcome> {
    let deadline = Instant::now() + total;
    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let next = (Instant::now() + idle).min(deadline);
        match timeout_at(next, stream.read(&mut buf)).await {
            Err(_) => break,    // idle timeout or total deadline: what arrived is the paste
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                if data.len() + n > cap {
                    return Ok(ReadOutcome::TooLarge);
                }
                data.extend_from_slice(&buf[..n]);
            }
            Ok(Err(e)) => return Err(e),
        }
    }
    if data.is_empty() {
        Ok(ReadOutcome::Empty)
    } else {
        Ok(ReadOutcome::Complete(data))
    }
}

/// Every rule reads only the first line, so any leading line lets a body
/// through.
pub fn probe_kind(body: &[u8]) -> Option<&'static str> {
    let first = body.split(|&c| c == b'\n').next().unwrap_or_default();
    // Text never holds NUL or these C0 controls; terminal output keeps BEL,
    // BS, TAB, VT, FF, CR, SO, SI (tput sgr0 under tmux and screen ends in
    // SI) and ESC. This catches TLS and nearly every binary service probe,
    // nmap's included.
    let binary = first
        .iter()
        .any(|&c| matches!(c, 0x00..=0x06 | 0x10..=0x1a | 0x1c..=0x1f));
    let ssh = (body.starts_with(b"SSH-2.0-") || body.starts_with(b"SSH-1."))
        && body.len() <= 255
        && body.iter().position(|&c| c == b'\n') == Some(body.len() - 1);
    if binary {
        Some("binary")
    } else if ssh {
        Some("SSH")
    } else if body == b"HELP\r\n" {
        Some("scanner") // nmap's one text probe the other rules miss
    } else {
        request_line(body)
    }
}

/// CRLF only: a terminal sends LF, so typed text never matches.
fn request_line(body: &[u8]) -> Option<&'static str> {
    let end = body.iter().position(|&c| c == b'\n')?;
    let line = body[..end].strip_suffix(b"\r")?;
    let mut parts = line.splitn(3, |&c| c == b' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if !(3..=10).contains(&method.len())
        || !method.iter().all(u8::is_ascii_uppercase)
        || target.is_empty()
        || target.contains(&b'\r')
    {
        return None;
    }
    ["HTTP", "RTSP", "SIP"].into_iter().find(|proto| {
        matches!(
            version.strip_prefix(proto.as_bytes()),
            Some([b'/', major, b'.', minor]) if major.is_ascii_digit() && minor.is_ascii_digit()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    const LONG: Duration = Duration::from_secs(30);

    #[tokio::test]
    async fn eof_completes_with_all_bytes() {
        let (mut w, mut r) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            w.write_all(b"hello world").await.unwrap();
            // dropping w = EOF
        });
        let out = read_paste(&mut r, 1024, LONG, LONG).await.unwrap();
        writer.await.unwrap();
        assert_eq!(out, ReadOutcome::Complete(b"hello world".to_vec()));
    }

    #[tokio::test]
    async fn zero_bytes_is_empty() {
        let (w, mut r) = tokio::io::duplex(64);
        drop(w);
        let out = read_paste(&mut r, 1024, LONG, LONG).await.unwrap();
        assert_eq!(out, ReadOutcome::Empty);
    }

    #[tokio::test]
    async fn over_cap_is_too_large() {
        let (mut w, mut r) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            let _ = w.write_all(&[7u8; 200]).await;
        });
        let out = read_paste(&mut r, 100, LONG, LONG).await.unwrap();
        writer.abort();
        assert_eq!(out, ReadOutcome::TooLarge);
    }

    #[tokio::test]
    async fn exactly_cap_is_complete() {
        let (mut w, mut r) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            w.write_all(&[7u8; 100]).await.unwrap();
        });
        let out = read_paste(&mut r, 100, LONG, LONG).await.unwrap();
        writer.await.unwrap();
        assert_eq!(out, ReadOutcome::Complete(vec![7u8; 100]));
    }

    #[tokio::test]
    async fn idle_timeout_ends_read_with_data_so_far() {
        let (mut w, mut r) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            w.write_all(b"partial").await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await; // never finishes
            drop(w);
        });
        let start = std::time::Instant::now();
        let out = read_paste(&mut r, 1024, Duration::from_millis(200), LONG)
            .await
            .unwrap();
        writer.abort();
        assert_eq!(out, ReadOutcome::Complete(b"partial".to_vec()));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn total_deadline_stops_a_dripper() {
        let (mut w, mut r) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            loop {
                if w.write_all(b"x").await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await; // stays under idle
            }
        });
        let start = std::time::Instant::now();
        let out = read_paste(
            &mut r,
            100_000,
            Duration::from_millis(200),
            Duration::from_millis(700),
        )
        .await
        .unwrap();
        writer.abort();
        // deadline fired near 700ms, well before the dripper could ever stop on its own
        assert!(start.elapsed() >= Duration::from_millis(600));
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(matches!(out, ReadOutcome::Complete(_)));
    }

    #[test]
    fn probe_gate() {
        let chrome = b"GET / HTTP/1.1\r\nHost: 203.0.113.5:9999\r\nConnection: keep-alive\r\n\
            User-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0.0.0 Safari/537.36\r\n\r\n";
        let probes: &[(&[u8], &str)] = &[
            (b"GET / HTTP/1.0\r\n\r\n", "HTTP"),
            (b"OPTIONS / HTTP/1.0\r\n\r\n", "HTTP"),
            (
                b"GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0\r\n\r\n",
                "HTTP",
            ),
            (chrome, "HTTP"),
            (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "HTTP"),
            (b"OPTIONS / RTSP/1.0\r\n\r\n", "RTSP"),
            (
                b"OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/TCP nm;branch=foo\r\n",
                "SIP",
            ),
            // TLS, SSLv2, SSLv2-compatible TLS ClientHellos
            (b"\x16\x03\0\0S\x01\0\0O\x03\0", "binary"),
            (b"\x16\x03\x01\x06\xc0\x01\0\x06\xbc\x03\x03", "binary"),
            (b"\x80\x2e\x01\0\x02\0\x15", "binary"),
            (b"\x80\x9e\x01\x03\x01\0u", "binary"),
            // nmap RPCCheck, LPDString, JRMI, GIOP
            (b"\x80\0\0(r\xfe\x1d\x13\0\0\0\0\0\0\0\x02", "binary"),
            (b"\x01default\n", "binary"),
            (b"JRMI\0\x02K", "binary"),
            (b"GIOP\x01\0\x01\0$\0\0\0", "binary"),
            // seen on a live door: TP-Link Kasa, PostgreSQL, Modbus, libp2p
            (
                b"\0\0\0\x1d\xd0\xf2\x81\xf8\x8b\xff\x9a\xf7\xd5\xef",
                "binary",
            ),
            (b"\0\0\0\x09\0\x03\0\0\0", "binary"),
            (b"\x04\xab\0\0\0\x05\x01+\x0e\x01\0", "binary"),
            (b"\x13/multistream/1.0.0\n", "binary"),
            // binary files too; the HTTP door takes those
            (b"\x1f\x8b\x08\0\0\0\0\0\0\x03", "binary"),
            (b"\x7fELF\x02\x01\x01\0", "binary"),
            (b"SSH-2.0-OpenSSH_9.6\r\n", "SSH"),
            (b"SSH-2.0-Go\r\n", "SSH"),
            (b"HELP\r\n", "scanner"),
        ];
        for (body, kind) in probes {
            assert_eq!(probe_kind(body), Some(*kind), "{body:?}");
        }
        for body in [
            &b"GET /api HTTP/1.1\n"[..],
            b"GET / HTTP/1.0\nHost: x\n\nnotes\n",
            b"get / http/1.0\r\n\r\n",
            b"GET / HTTP/1.0 \r\n",
            b"GET /\r\n",
            b"# notes\n\n- *one*\n",
            b"fn main() {}\n\x00binary too\xff",
            b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR",
            "äöü\n".as_bytes(),
            "日本語\n".as_bytes(),
            // Latin-1, CRLF, color, an OSC title, overstrike, a progress bar, a form feed
            b"Gr\xfc\xdfe aus K\xf6ln\n",
            b"line one\r\nline two\r\n",
            b"\x1b[1;32mok\x1b[0m test\n",
            b"\x1b[32mPASS\x1b[m\x0f build ok\n",
            b"\x1b]0;user@host:~\x07$ ls\r\n",
            b"N\x08NA\x08AM\x08ME\x08E\n",
            b"  10%\r  50%\r 100%\n",
            b"\x0cpage 2\x0b\n",
            b"SSH-2.0-OpenSSH_9.6\r\nmore\n",
            b"SSH-2.0-OpenSSH_9.6",
            b"SSH-Zugang: ssh -p 2222 admin@10.0.0.5\n",
            b"SSH-agent forwarding broken on bastion\n",
            b"HELP\n",
        ] {
            assert_eq!(probe_kind(body), None, "{body:?}");
        }
    }

    proptest! {
        #[test]
        fn a_leading_line_disarms_the_probe_gate(
            body in proptest::collection::vec(any::<u8>(), 0..512),
        ) {
            let _ = probe_kind(&body);
            for line in [&b"\n"[..], b"# note\n"] {
                let mut armed = line.to_vec();
                armed.extend_from_slice(&body);
                assert_eq!(probe_kind(&armed), None);
            }
        }

        /// Any payload under the cap, split at any chunk boundaries, comes
        /// out byte-identical. The duplex buffer is smaller than most
        /// payloads, so backpressure forces real interleaving.
        #[test]
        fn reassembles_any_chunking(
            data in proptest::collection::vec(any::<u8>(), 1..20_000),
            cut_points in proptest::collection::vec(any::<prop::sample::Index>(), 0..16),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            rt.block_on(async {
                let mut cuts: Vec<usize> = cut_points.iter().map(|i| i.index(data.len())).collect();
                cuts.push(0);
                cuts.push(data.len());
                cuts.sort_unstable();
                cuts.dedup();

                let (mut w, mut r) = tokio::io::duplex(1024);
                let chunks: Vec<Vec<u8>> = cuts.windows(2).map(|p| data[p[0]..p[1]].to_vec()).collect();
                let writer = tokio::spawn(async move {
                    for c in chunks {
                        w.write_all(&c).await.unwrap();
                    }
                });
                let out = read_paste(&mut r, 20_000, LONG, LONG).await.unwrap();
                writer.await.unwrap();
                assert_eq!(out, ReadOutcome::Complete(data));
            });
        }
    }
}
