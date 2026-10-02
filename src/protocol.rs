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

/// Names the scanner probe `body` is, if it is one. Scanners open a port,
/// send a fixed request and wait for an answer; stored, each one would be a
/// paste. Every rule is anchored at the first byte, so one line in front of
/// the body, even an empty one, disarms all of them.
pub fn probe_kind(body: &[u8]) -> Option<&'static str> {
    // A TLS record carrying a ClientHello, or an SSLv2-compatible hello: a
    // length with the high bit set, CLIENT-HELLO, then version 2.0 or 3.x.
    // The hello is sent alone, so its length must cover the body exactly;
    // five fixed bytes on their own also match UTF-16 text and CBOR.
    let tls = match body {
        [0x16, 0x03, 0x00..=0x04, _, _, 0x01, ..] => true,
        [hi @ 0x80..=0xff, lo, 0x01, 0x00, 0x02, ..]
        | [hi @ 0x80..=0xff, lo, 0x01, 0x03, 0x00..=0x04, ..] => {
            (usize::from(hi & 0x7f) << 8 | usize::from(*lo)) + 2 == body.len()
        }
        _ => false,
    };
    // An SSH client's version line, sent alone while it waits for the server's.
    let ssh = (body.starts_with(b"SSH-2.0-") || body.starts_with(b"SSH-1."))
        && body.len() <= 255
        && body.iter().position(|&c| c == b'\n') == Some(body.len() - 1);
    if tls {
        Some("TLS")
    } else if ssh {
        Some("SSH")
    } else if NMAP_PROBES.contains(&body) {
        Some("scanner")
    } else {
        request_line(body)
    }
}

/// `METHOD target PROTO/d.d` and CRLF, as HTTP, RTSP and SIP clients send it.
/// A terminal ends lines with a bare LF, so text typed or pasted there never
/// matches.
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

/// nmap's default-intensity TCP probes (rarity 7 or less in
/// nmap-service-probes) that the rules above miss, byte for byte. Its blank
/// GenericLines probe never gets here: intake drops whitespace-only bodies.
const NMAP_PROBES: &[&[u8]] = &[
    // RPCCheck
    b"\x80\0\0(r\xfe\x1d\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xa0\0\x01\x97|\0\0\0\0\0\0\0\0\0\0\0\
        \0\0\0\0\0\0\0\0\0",
    // DNSVersionBindReqTCP
    b"\0\x1e\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\x04bind\0\0\x10\0\x03",
    // DNSStatusRequestTCP
    b"\0\x0c\0\0\x10\0\0\0\0\0\0\0\0\0",
    // Help
    b"HELP\r\n",
    // TerminalServerCookie
    b"\x03\0\0*%\xe0\0\0\0\0\0Cookie: mstshash=nmap\r\n\x01\0\x08\0\x03\0\0\0",
    // Kerberos
    b"\0\0\0qj\x81n0\x81k\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\n\xa4\x81^0\\\xa0\x07\x03\x05\0P\
        \x80\0\x10\xa2\x04\x1b\x02NM\xa3\x170\x15\xa0\x03\x02\x01\0\xa1\x0e0\x0c\x1b\x06krbtgt\
        \x1b\x02NM\xa5\x11\x18\x0f19700101000000Z\xa7\x06\x02\x04\x1f\x1e\xb9\xd9\xa8\x170\x15\
        \x02\x01\x12\x02\x01\x11\x02\x01\x10\x02\x01\x17\x02\x01\x01\x02\x01\x03\x02\x01\x02",
    // SMBProgNeg
    b"\0\0\0\xa4\xffSMBr\0\0\0\0\x08\x01@\0\0\0\0\0\0\0\0\0\0\0\0\0\0@\x06\0\0\x01\0\0\x81\0\
        \x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\
        \x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0",
    // X11Probe
    b"l\0\x0b\0\0\0\0\0\0\0\0\0",
    // LPDString
    b"\x01default\n",
    // LDAPSearchReq
    b"0\x84\0\0\0-\x02\x01\x07c\x84\0\0\0$\x04\0\n\x01\0\n\x01\0\x02\x01\0\x02\x01d\x01\x01\0\
        \x87\x0bobjectClass0\x84\0\0\0\0",
    // LDAPBindReq
    b"0\x0c\x02\x01\x01`\x07\x02\x01\x02\x04\0\x80\0",
    // LANDesk-RC
    b"TNMP\x04\0\0\0TNME\0\0\x04\0",
    // TerminalServer
    b"\x03\0\0\x0b\x06\xe0\0\0\0\0\0",
    // NCP
    b"DmdT\0\0\0\x17\0\0\0\x01\0\0\0\0\x11\x11\0\xff\x01\xff\x13",
    // NotesRPC
    b":\0\0\0/\0\0\0\x02\0\0@\x02\x0f\0\x01\0=\x05\0\0\0\0\0\0\0\0\0\0\0\0/\0\0\0\0\0\0\0\0\0@\
        \x1f\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    // JavaRMI
    b"JRMI\0\x02K",
    // WMSRequest
    b"\x01\0\0\xfd\xce\xfa\x0b\xb0\xa0\0\0\0MMS\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x12\0\0\0\
        \x01\0\x03\0\xf0\xf0\xf0\xf0\x0b\0\x04\0\x1c\0\x03\0N\0S\0P\0l\0a\0y\0e\0r\0/\x009\0.\
        \x000\0.\x000\0.\x002\x009\x008\x000\0;\0 \0{\x000\x000\x000\x000\0A\0A\x000\x000\0-\
        \x000\0A\x000\x000\0-\x000\x000\0a\x000\0-\0A\0A\x000\0A\0-\x000\x000\x000\x000\0A\x000\
        \0A\0A\x000\0A\0A\x000\0}\0\0\0\xe0m\xdf_",
    // oracle-tns
    b"\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7f\xff\x7f\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\
        \0\0\0\0\0\0\x004\xe6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))",
    // ms-sql-s
    b"\x12\x01\x004\0\0\0\0\0\0\x15\0\x06\x01\0\x1b\0\x01\x02\0\x1c\0\x0c\x03\0(\0\x04\xff\x08\
        \0\x01U\0\0\0MSSQLServer\0H\x0f\0\0",
    // afp
    b"\0\x03\0\x01\0\0\0\0\0\0\0\x02\0\0\0\0\x0f\0",
    // giop
    b"GIOP\x01\0\x01\0$\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\0abcdef\0\0\x04\0\0\0get\0\0\
        \0\0\0",
];

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
        // SSLv2, then nmap's SSLv23SessionReq, each as long as its header says
        let mut sslv2 = b"\x80\x2e\x01\0\x02\0\x15".to_vec();
        sslv2.resize(0x2e + 2, 0);
        let mut sslv23 = b"\x80\x9e\x01\x03\x01\0u".to_vec();
        sslv23.resize(0x9e + 2, 0);
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
            // nmap's SSLSessionReq and TLSSessionReq heads, then TLS 1.2 and 1.3
            (b"\x16\x03\0\0S\x01\0\0O\x03\0", "TLS"),
            (b"\x16\x03\0\0i\x01\0\0e\x03\x03", "TLS"),
            (b"\x16\x03\x01\x02\0\x01\0\x01\xfc\x03\x03", "TLS"),
            (b"\x16\x03\x01\x06\xc0\x01\0\x06\xbc\x03\x03", "TLS"),
            (&sslv2[..], "TLS"),
            (&sslv23[..], "TLS"),
            (b"SSH-2.0-OpenSSH_9.6\r\n", "SSH"),
            (b"SSH-2.0-Go\r\n", "SSH"),
        ];
        for (body, kind) in probes {
            assert_eq!(probe_kind(body), Some(*kind), "{body:?}");
        }
        for body in NMAP_PROBES {
            assert_eq!(probe_kind(body), Some("scanner"), "{body:?}");
        }
        for body in [
            // a terminal sends LF
            &b"GET /api HTTP/1.1\n"[..],
            b"GET / HTTP/1.0\nHost: x\n\nnotes\n",
            b"get / http/1.0\r\n\r\n",
            b"GET / HTTP/1.0 \r\n",
            b"GET /\r\n",
            b"# notes\n\n- *one*\n",
            b"fn main() {}\n\x00binary too\xff",
            b"\x1f\x8b\x08\0\0\0\0\0\0\x03",
            b"\x7fELF\x02\x01\x01\0",
            // high bit set, but [2] is not CLIENT-HELLO; nor is it in UTF-8 text
            b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR",
            "äöü\n".as_bytes(),
            "日本語\n".as_bytes(),
            // an SSLv2 hello head shorter than its length says, UTF-16BE "ăn c"
            // with a BOM, CBOR [0, 1, 0, 2], msgpack {0: 1, 3: 0}
            b"\x80\x2e\x01\0\x02\0\x15",
            b"\xfe\xff\x01\x03\0n\0 \0c",
            b"\x84\0\x01\0\x02",
            b"\x82\0\x01\x03\0",
            b"SSH-2.0-OpenSSH_9.6\r\nmore\n",
            b"SSH-2.0-OpenSSH_9.6",
            b"SSH-Zugang: ssh -p 2222 admin@10.0.0.5\n",
            b"SSH-agent forwarding broken on bastion\n",
            b"HELP\n",
            b"JRMI\0\x02K\n",
        ] {
            assert_eq!(probe_kind(body), None, "{body:?}");
        }
    }

    proptest! {
        /// The refusal tells a human to prepend a line. That has to work
        /// whatever follows, and the gate must not panic on any input.
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
