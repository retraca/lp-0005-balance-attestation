//! Off-chain verifier library for LP-0005 balance attestation proofs.
//!
//! ```rust,no_run
//! use balance_attestation_verifier::{verify_attestation, BalanceAttestation};
//!
//! # fn run(receipt_bytes: &[u8], presenter_sig: [u8; 64]) -> anyhow::Result<()> {
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

// IMAGE_ID is set by the build system from the compiled guest ELF.
// Replace with the actual value after building the circuit.
pub const IMAGE_ID: [u32; 8] = [0u32; 8]; // set at build time

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceAttestation {
    pub merkle_root: [u8; 32],
    pub threshold_n: u128,
    pub context_id: [u8; 32],
    pub presenter_pk: [u8; 32],
}

/// Verify a balance attestation receipt.
///
/// Checks:
///   1. Receipt verifies against the guest image ID.
///   2. Journal deserialises into `BalanceAttestation`.
///   3. `attestation.context_id == expected_context_id` (replay prevention).
///   4. `attestation.threshold_n >= expected_threshold` (gating).
///   5. `presenter_sig` is a valid Ed25519 signature over
///      `context_id || merkle_root || threshold_n` under `attestation.presenter_pk`
///      (forwarding prevention).
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
    let receipt: Receipt = risc0_zkvm::serde::from_slice(receipt_bytes)?;
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

    // Verify presenter signature over (context_id || merkle_root || threshold_n).
    let mut message = Vec::with_capacity(32 + 32 + 16);
    message.extend_from_slice(&attestation.context_id);
    message.extend_from_slice(&attestation.merkle_root);
    message.extend_from_slice(&attestation.threshold_n.to_le_bytes());

    let vk = VerifyingKey::from_bytes(expected_presenter_pk)
        .map_err(|e| anyhow::anyhow!("invalid presenter_pk: {e}"))?;
    let sig = Signature::from_bytes(presenter_sig);
    vk.verify(&message, &sig)
        .map_err(|_| anyhow::anyhow!("presenter signature invalid"))?;

    Ok(attestation)
}
