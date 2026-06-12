//! Off-chain verifier library for LP-0005 balance attestation proofs.
//!
//! ```rust,no_run
//! use balance_attestation_verifier::{verify_attestation, BalanceAttestation};
//!
//! # fn run(receipt_bytes: &[u8], presenter_sig: [u8; 64]) -> anyhow::Result<()> {
//! # let MY_CONTEXT_ID = [0u8; 32];
//! # let MY_PRESENTER_PK = [0u8; 32];
//! let image_id: [u32; 8] = balance_attestation_verifier::IMAGE_ID;
//! let attestation = verify_attestation(
//!     receipt_bytes,
//!     image_id,
//!     &MY_CONTEXT_ID,
//!     1000u128, // minimum threshold
//!     &MY_PRESENTER_PK,
//!     &presenter_sig,
//! )?;
//! println!("balance >= {}", attestation.threshold_n);
//! # Ok(())
//! # }
//! ```

use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};

/// Attestation guest image ID. Must match `BALANCE_ATTESTATION_GUEST_ID` in
/// `circuit/host/src/methods.rs` (regenerated whenever the guest is rebuilt).
pub const IMAGE_ID: [u32; 8] = [
    0xa467ec7f, 0xecb63d04, 0xdec5c62b, 0xfee3e100,
    0x278f0e6f, 0x3e1a8fc2, 0x200c856c, 0xd931e6b0,
];

/// Public journal committed by the guest circuit.
/// Field order must match `BalanceAttestation` in `circuit/guest/src/main.rs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceAttestation {
    pub merkle_root: [u8; 32],
    pub threshold_n: u128,
    pub context_id: [u8; 32],
    pub presenter_pk: [u8; 32],
    /// One-shot nullifier: SHA256("balance-attest/v1" || nsk || context_id || use_nonce).
    /// Recipients must track spent nullifiers to prevent proof replay.
    pub nullifier: [u8; 32],
}

/// Verify a balance attestation receipt.
///
/// Checks:
///   1. Receipt verifies against the guest image ID.
///   2. Journal deserialises into `BalanceAttestation`.
///   3. `attestation.context_id == expected_context_id` (replay prevention across gates).
///   4. `attestation.threshold_n >= expected_threshold` (gating).
///   5. `presenter_sig` is a valid Ed25519 signature over
///      `context_id || merkle_root || threshold_n || nullifier` under
///      `attestation.presenter_pk` (forwarding prevention).
///
/// The caller is responsible for nullifier bookkeeping: store
/// `attestation.nullifier` after a successful verification and reject any
/// future attestation carrying the same value.
///
/// # Errors
///
/// Returns an error if any check fails.
pub fn verify_attestation(
    receipt_bytes: &[u8],
    image_id: [u32; 8],
    expected_context_id: &[u8; 32],
    expected_threshold: u128,
    expected_presenter_pk: &[u8; 32],
    presenter_sig: &[u8; 64],
) -> Result<BalanceAttestation> {
    let words: Vec<u32> = receipt_bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect();
    let receipt: Receipt = risc0_zkvm::serde::from_slice(&words)?;
    receipt.verify(image_id)?;

    let attestation: BalanceAttestation = receipt.journal.decode()?;

    if &attestation.context_id != expected_context_id {
        bail!(
            "context_id mismatch: proof was generated for a different gate"
        );
    }
    if attestation.threshold_n < expected_threshold {
        bail!(
            "threshold not met: proof shows balance >= {} but gate requires >= {}",
            attestation.threshold_n,
            expected_threshold
        );
    }
    if &attestation.presenter_pk != expected_presenter_pk {
        bail!("presenter_pk in proof does not match expected key");
    }

    // Verify presenter signature over (context_id || merkle_root || threshold_n || nullifier).
    // Must match the signing message in sdk/src/lib.rs::sign_attestation.
    let mut message = Vec::with_capacity(32 + 32 + 16 + 32);
    message.extend_from_slice(&attestation.context_id);
    message.extend_from_slice(&attestation.merkle_root);
    message.extend_from_slice(&attestation.threshold_n.to_le_bytes());
    message.extend_from_slice(&attestation.nullifier);

    let vk = VerifyingKey::from_bytes(expected_presenter_pk)
        .map_err(|e| anyhow::anyhow!("invalid presenter_pk: {e}"))?;
    let sig = Signature::from_bytes(presenter_sig);
    vk.verify(&message, &sig)
        .map_err(|_| anyhow::anyhow!("presenter signature invalid"))?;

    Ok(attestation)
}
