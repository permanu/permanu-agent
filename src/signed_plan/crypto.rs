//! Digests, key ids and ES256-raw verification (signed-plan.md section 2.1).

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub(crate) const PLAN_PREFIX: &[u8] = b"permanu-plan-v1\n";
pub(crate) const RULE_PREFIX: &[u8] = b"permanu-rule-v1\n";
pub(crate) const SPEC_PREFIX: &[u8] = b"permanu-spec-v1\n";
pub(crate) const KEY_ADD_PREFIX: &[u8] = b"permanu-key-add-v1\n";
pub(crate) const KEY_REVOKE_PREFIX: &[u8] = b"permanu-key-revoke-v1\n";

/// DER prefix of a P-256 `SubjectPublicKeyInfo` with an uncompressed point.
const SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];
const SPKI_LENGTH: usize = 91;

pub(crate) fn prefixed_digest(prefix: &[u8], canonical: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(canonical.as_bytes());
    hasher.finalize().into()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}

/// Canonical base64url without padding (RFC 4648 §5).
pub(crate) fn b64url_decode(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).ok()
}

pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A parsed trusted P-256 key.
#[derive(Debug, Clone)]
pub(crate) struct PublicKey {
    key: VerifyingKey,
    pub(crate) key_id: String,
}

/// Parses the standard-base64 SPKI DER of a trusted key: exactly the
/// uncompressed P-256 encoding, on the curve.
pub(crate) fn parse_spki_base64(value: &str) -> Option<PublicKey> {
    let der = STANDARD.decode(value).ok()?;
    if der.len() != SPKI_LENGTH || der[..SPKI_PREFIX.len()] != SPKI_PREFIX {
        return None;
    }
    let point = &der[SPKI_PREFIX.len()..];
    if point.first() != Some(&0x04) {
        return None;
    }
    let key = VerifyingKey::from_sec1_bytes(point).ok()?;
    let digest: [u8; 32] = Sha256::digest(&der).into();
    Some(PublicKey {
        key,
        key_id: b64url_encode(&digest[..16]),
    })
}

impl PublicKey {
    /// Verifies a raw `r || s` signature over a precomputed SHA-256 digest.
    /// High-S signatures are accepted; zero or out-of-range scalars are not.
    pub(crate) fn verify_prehash(&self, digest: &[u8; 32], raw_signature: &[u8]) -> bool {
        if raw_signature.len() != 64 {
            return false;
        }
        let Ok(signature) = Signature::from_slice(raw_signature) else {
            return false;
        };
        self.key.verify_prehash(digest, &signature).is_ok()
    }
}
