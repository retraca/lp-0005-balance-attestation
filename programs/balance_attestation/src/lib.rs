//! Core logic for LP-0005 balance attestation gate program.

use borsh::{BorshDeserialize, BorshSerialize};
use spel_framework::error::SpelError;

pub const ERR_PROOF_INVALID: u32 = 5001;
pub const ERR_CONTEXT_MISMATCH: u32 = 5002;
pub const ERR_THRESHOLD_NOT_MET: u32 = 5003;
pub const ERR_SIGNATURE_INVALID: u32 = 5004;
pub const ERR_STALE_ROOT: u32 = 5005;
pub const ERR_NULLIFIER_SPENT: u32 = 5006;

/// Gate state persisted on-chain.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct GateState {
    pub accepted_root: [u8; 32],
    pub spent_nullifiers: Vec<[u8; 32]>,
}

/// Journal committed by the circuit guest (borsh-serializable; matches risc0-serde for fixed-size fields).
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct AttestationJournal {
    pub merkle_root: [u8; 32],
    pub threshold_n: u128,
    pub context_id: [u8; 32],
    pub presenter_pk: [u8; 32],
    pub nullifier: [u8; 32],
}

/// Verify a balance attestation journal against gate state.
///
/// Called from the SPEL entry after `env::verify` confirms the receipt assumption.
/// `context_id` is this program's own account ID (passed from main.rs, not from the caller).
pub fn apply_attestation(
    state: &mut GateState,
    journal: &AttestationJournal,
    context_id: [u8; 32],
    presenter_sig: [u8; 64],
    expected_threshold: u128,
) -> Result<(), SpelError> {
    if journal.context_id != context_id {
        return Err(SpelError::Custom {
            code: ERR_CONTEXT_MISMATCH,
            message: "context_id mismatch".to_string(),
        });
    }

    if journal.threshold_n < expected_threshold {
        return Err(SpelError::Custom {
            code: ERR_THRESHOLD_NOT_MET,
            message: "balance below expected threshold".to_string(),
        });
    }

    if journal.merkle_root != state.accepted_root {
        return Err(SpelError::Custom {
            code: ERR_STALE_ROOT,
            message: "merkle root mismatch".to_string(),
        });
    }

    if state.spent_nullifiers.contains(&journal.nullifier) {
        return Err(SpelError::Custom {
            code: ERR_NULLIFIER_SPENT,
            message: "nullifier already spent".to_string(),
        });
    }

    // Verify presenter signature over (context_id || merkle_root || threshold_n || nullifier).
    let mut message = Vec::with_capacity(32 + 32 + 16 + 32);
    message.extend_from_slice(&journal.context_id);
    message.extend_from_slice(&journal.merkle_root);
    message.extend_from_slice(&journal.threshold_n.to_le_bytes());
    message.extend_from_slice(&journal.nullifier);

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&journal.presenter_pk).map_err(|_| SpelError::Custom {
        code: ERR_SIGNATURE_INVALID,
        message: "invalid presenter public key".to_string(),
    })?;
    let sig = Signature::from_bytes(&presenter_sig);
    vk.verify(&message, &sig).map_err(|_| SpelError::Custom {
        code: ERR_SIGNATURE_INVALID,
        message: "presenter signature invalid".to_string(),
    })?;

    state.spent_nullifiers.push(journal.nullifier);
    Ok(())
}
