#![no_main]
use libfuzzer_sys::fuzz_target;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use http::{HeaderMap, HeaderValue};

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    v6: bool,
    octets: [u8; 16],
    values: Vec<Vec<u8>>,
}

fuzz_target!(|input: Input| {
    let peer: IpAddr = if input.v6 {
        Ipv6Addr::from(input.octets).into()
    } else {
        Ipv4Addr::new(
            input.octets[0],
            input.octets[1],
            input.octets[2],
            input.octets[3],
        )
        .into()
    };

    let mut headers = HeaderMap::new();
    for v in &input.values {
        if let Ok(hv) = HeaderValue::from_bytes(v) {
            headers.append("x-forwarded-for", hv);
        }
    }

    // Invariant: client_ip never panics on arbitrary input (implicit: the
    // fuzzer catches a panic here as a crash).
    let result = scrip::http::client_ip(peer, &headers);

    // Both invariants below are about the canonical peer: client_ip maps
    // ::ffff:a.b.c.d to a.b.c.d, so a mapped v4 peer neither equals the raw
    // peer on the way out nor answers is_loopback() honestly on the way in.
    let peer = peer.to_canonical();

    // Invariant: a non-loopback peer is never overridden by the header.
    if !peer.is_loopback() {
        assert_eq!(result, peer);
        return;
    }

    // Invariant: a loopback peer with no X-Forwarded-For headers at all
    // falls back to peer.
    if headers.get_all("x-forwarded-for").iter().next().is_none() {
        assert_eq!(result, peer);
    }
});
