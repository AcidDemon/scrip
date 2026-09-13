#![no_main]
use libfuzzer_sys::fuzz_target;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    data: Vec<u8>,
    cuts: Vec<u16>,
    cap: u16,
}

fuzz_target!(|input: Input| {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    rt.block_on(async {
        let (mut w, mut r) = tokio::io::duplex(257); // odd size: force splits
        let data = input.data.clone();
        let mut cuts: Vec<usize> = input
            .cuts
            .iter()
            .map(|&c| c as usize % (data.len() + 1))
            .collect();
        cuts.push(0);
        cuts.push(data.len());
        cuts.sort_unstable();
        cuts.dedup();
        let chunks: Vec<Vec<u8>> = cuts.windows(2).map(|p| data[p[0]..p[1]].to_vec()).collect();
        let writer = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            for c in chunks {
                if w.write_all(&c).await.is_err() {
                    return;
                }
            }
        });
        let cap = input.cap as usize;
        let out = match scrip::protocol::read_paste(
            &mut r,
            cap,
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(30),
        )
        .await
        {
            Ok(o) => o,
            Err(_) => return, // an IO error out of duplex() is not a finding
        };
        writer.abort();
        // Prefix, not equality: a timeout can legitimately truncate. Under
        // the cap it must not.
        if let scrip::protocol::ReadOutcome::Complete(v) = out {
            assert!(v.len() <= cap);
            assert_eq!(&v[..], &input.data[..v.len()]);
            if input.data.len() <= cap {
                assert_eq!(v.len(), input.data.len());
            }
        }
    });
});
