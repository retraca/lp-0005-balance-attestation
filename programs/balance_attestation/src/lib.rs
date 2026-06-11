//! On-chain verifier program for LP-0005 balance attestation.
//! Receives a RISC0 receipt + presenter signature, verifies both, then
//! gates execution of a downstream action.

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::account::{AccountWithMetadata, AccountPostState};
use spel_framework::error::SpelError;

// IMAGE_ID is injected by the build system via risc0-build; never ship [0u32; 8].
// The const_assert below prevents deploying a zero placeholder.
include!(concat!(env!("OUT_DIR"), "/methods.rs"));
use BALANCE_ATTESTATION_GUEST_ID as IMAGE_ID;
const _: () = assert!(
    IMAGE_ID[0] != 0 || IMAGE_ID[1] != 0 || IMAGE_ID[2] != 0 || IMAGE_ID[3] != 0,
    "IMAGE_ID is all-zero; build the guest circuit before deploying"
);

pub const ERR_PROOF_INVALID: u32 = 5001;
pub const ERR_CONTEXT_MISMATCH: u32 = 5002;
pub const ERR_THRESHOLD_NOT_MET: u32 = 5003;
pub const ERR_SIGNATURE_INVALID: u32 = 5004;
pub const ERR_STALE_ROOT: u32 = 5005;
pub const ERR_NULLIFIER_SPENT: u32 = 5006;

/// Gate state: tracks spent nullifiers and the accepted Merkle root.
///
/// Stored as the gating_account's on-chain data.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct GateState {
    /// The current commitment-tree root this gate accepts.
    /// Updated by the program operator via `update_root`.
    pub accepted_root: [u8; 32],
    /// One-shot nullifiers: `SHA256(nsk || context_id || tx_nonce)` values that have been consumed.
    pub spent_nullifiers: Vec<[u8; 32]>,
}

/// Gate instruction: verify a balance attestation and allow the caller to proceed.
///
/// Inputs:
///   - `gating_account`: holds `GateState` (accepted_root + spent nullifiers)
///   - `receipt_bytes`: serialised RISC0 receipt (from the prover)
///   - `presenter_sig`: 64-byte Ed25519 signature over `(context_id || merkle_root || threshold_n || nullifier)`
///   - `expected_threshold`: minimum balance the caller requires
///
/// The program verifies:
///   1. Receipt is valid for `IMAGE_ID`
///   2. `journal.context_id` matches this program's account ID
///   3. `journal.threshold_n >= expected_threshold`
///   4. `journal.merkle_root == gate_state.accepted_root` (freshness)
///   5. `journal.nullifier` not in `gate_state.spent_nullifiers` (anti-replay; nullifier is circuit-bound to nsk)
///   6. `presenter_sig` is valid under `journal.presenter_pk`
///
/// On success: appends `journal.nullifier` to spent set, returns updated `AccountPostState`.
/// On failure: returns `SpelError::Custom(ERR_*)`.
pub fn verify_attestation(
    gating_account: AccountWithMetadata,
    receipt_bytes: Vec<u8>,
    presenter_sig: [u8; 64],
    expected_threshold: u128,
) -> Result<Vec<AccountPostState>, SpelError> {
    let mut gate_state = GateState::try_from_slice(&gating_account.account.data.0)
        .map_err(|_| SpelError::Custom { code: ERR_PROOF_INVALID })?;

    let receipt: risc0_zkvm::Receipt = risc0_zkvm::serde::from_slice(&receipt_bytes)
        .map_err(|_| SpelError::Custom { code: ERR_PROOF_INVALID })?;

    receipt.verify(IMAGE_ID)
        .map_err(|_| SpelError::Custom { code: ERR_PROOF_INVALID })?;

    #[derive(serde::Deserialize)]
    struct Journal {
        merkle_root: [u8; 32],
        threshold_n: u128,
        context_id: [u8; 32],
        presenter_pk: [u8; 32],
        /// Circuit-computed nullifier bound to the prover's nsk -- cannot be forged.
        nullifier: [u8; 32],
    }

    let journal: Journal = receipt.journal.decode()
        .map_err(|_| SpelError::Custom { code: ERR_PROOF_INVALID })?;

    // context_id must match this program's own account ID
    let program_id_bytes: [u8; 32] = gating_account.account_id.to_bytes();
    if journal.context_id != program_id_bytes {
        return Err(SpelError::Custom { code: ERR_CONTEXT_MISMATCH });
    }

    if journal.threshold_n < expected_threshold {
        return Err(SpelError::Custom { code: ERR_THRESHOLD_NOT_MET });
    }

    // Freshness: merkle_root in the proof must match the gate's accepted root.
    if journal.merkle_root != gate_state.accepted_root {
        return Err(SpelError::Custom { code: ERR_STALE_ROOT });
    }

    // Anti-replay: nullifier is circuit-bound to nsk; check it has not been spent.
    if gate_state.spent_nullifiers.contains(&journal.nullifier) {
        return Err(SpelError::Custom { code: ERR_NULLIFIER_SPENT });
    }

    // Verify presenter signature over (context_id || merkle_root || threshold_n || nullifier).
    let mut message = Vec::with_capacity(32 + 32 + 16 + 32);
    message.extend_from_slice(&journal.context_id);
    message.extend_from_slice(&journal.merkle_root);
    message.extend_from_slice(&journal.threshold_n.to_le_bytes());
    message.extend_from_slice(&journal.nullifier);

    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let vk = VerifyingKey::from_bytes(&journal.presenter_pk)
        .map_err(|_| SpelError::Custom { code: ERR_SIGNATURE_INVALID })?;
    let sig = Signature::from_bytes(&presenter_sig);
    vk.verify(&message, &sig)
        .map_err(|_| SpelError::Custom { code: ERR_SIGNATURE_INVALID })?;

    // Gate passed: consume the nullifier (circuit-bound to nsk) and persist updated state.
    gate_state.spent_nullifiers.push(journal.nullifier);
    let mut account = gating_account.account;
    account.data = nssa_core::account::Data::from_borsh(&gate_state);
    Ok(vec![AccountPostState::new(account)])
}
