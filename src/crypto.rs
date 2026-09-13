//! At-rest encryption for pastes, keyed by the URL itself.
//!
//! The URL token is the only key material. A row stores the token's hashed
//! id as its slug and `nonce || XChaCha20-Poly1305 ciphertext` as its body;
//! the token is not stored. Two domain-separated SHA-256 calls derive the
//! id and content key from the token's ~134 bits of OS-generated randomness.
//!
//! This is encryption at rest, not end to end: the server holds the
//! plaintext at write time and derives the key from the URL on every read.
//! Encrypted bodies in the database, backups, and WAL require the URLs to read.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};

/// 26 base36 chars, about 134 bits: enough to be an unguessable URL and a
/// 128-bit-class content key at the same time. The length also tells the
/// read path which lookup to use, so it must never equal a plain slug
/// length (plain slugs are 8, `valid_slug` caps legacy ones at 16).
pub const TOKEN_LEN: usize = 26;

const NONCE_LEN: usize = 24;

/// Bytes `seal` adds on top of the plaintext (nonce + AEAD tag), so quota
/// accounting can charge for what actually lands in the row.
pub const SEAL_OVERHEAD: u64 = (NONCE_LEN + 16) as u64;

pub fn token() -> String {
    crate::slug::random_base36(TOKEN_LEN)
}

fn hash(domain: &[u8], token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(token.as_bytes());
    h.finalize().into()
}

/// The database slug for a token: 64 hex chars, domain-separated from the
/// content key. Longer than `valid_slug` allows in a URL, so ciphertext can
/// never be fetched by its id directly.
pub fn token_id(token: &str) -> String {
    hash(b"scrip id v1", token)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `nonce || ciphertext`. The key is unique per paste, but the nonce is
/// still random so a leaked token plus an old backup never lines two
/// ciphertexts up under one (key, nonce) pair.
pub fn seal(token: &str, plain: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("OS RNG unavailable");
    let cipher = XChaCha20Poly1305::new((&hash(b"scrip key v1", token)).into());
    let mut out = nonce.to_vec();
    out.extend(
        cipher
            .encrypt(XNonce::from_slice(&nonce), plain)
            .expect("XChaCha20-Poly1305 encryption is infallible"),
    );
    out
}

/// None = tampered or corrupted blob. A wrong token cannot get here: it
/// hashes to a different id and the lookup already missed.
pub fn open(token: &str, sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new((&hash(b"scrip key v1", token)).into());
    cipher.decrypt(XNonce::from_slice(nonce), ct).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let t = token();
        assert_eq!(t.len(), TOKEN_LEN);
        let sealed = seal(&t, b"hello \x00 world");
        assert_ne!(&sealed, b"hello \x00 world");
        assert_eq!(
            sealed.len() as u64,
            b"hello \x00 world".len() as u64 + SEAL_OVERHEAD
        );
        assert_eq!(open(&t, &sealed).unwrap(), b"hello \x00 world");
    }

    #[test]
    fn tampering_and_truncation_fail_closed() {
        let t = token();
        let mut sealed = seal(&t, b"payload");
        *sealed.last_mut().unwrap() ^= 1;
        assert_eq!(open(&t, &sealed), None);
        assert_eq!(open(&t, &[]), None);
        assert_eq!(open(&t, &[0u8; NONCE_LEN - 1]), None);
    }

    #[test]
    fn wrong_token_cannot_open() {
        let sealed = seal(&token(), b"payload");
        assert_eq!(open(&token(), &sealed), None);
    }

    #[test]
    fn id_is_stable_and_unlike_the_key() {
        let t = token();
        let id = token_id(&t);
        assert_eq!(id, token_id(&t));
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        // domain separation: the id bytes are not the content key
        assert_ne!(hex_bytes(&id), hash(b"scrip key v1", &t).to_vec());
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn nonces_differ_between_seals() {
        let t = token();
        let a = seal(&t, b"x");
        let b = seal(&t, b"x");
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    }
}
