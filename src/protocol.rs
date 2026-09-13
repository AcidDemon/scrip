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

    proptest! {
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
