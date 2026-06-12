//! SDK helpers for LP-0005 balance attestation clients.

pub use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

/// Sign the attestation message: (context_id || merkle_root || threshold_n || nullifier).
pub fn sign_attestation(
    sk: &SigningKey,
    context_id: &[u8; 32],
    merkle_root: &[u8; 32],
    threshold_n: u128,
    nullifier: &[u8; 32],
) -> [u8; 64] {
    let mut message = Vec::with_capacity(32 + 32 + 16 + 32);
    message.extend_from_slice(context_id);
    message.extend_from_slice(merkle_root);
    message.extend_from_slice(&threshold_n.to_le_bytes());
    message.extend_from_slice(nullifier);
    sk.sign(&message).to_bytes()
}
