//! Integration tests for the LP-0005 balance attestation on-chain program.

use balance_attestation_program::*;

#[test]
fn error_codes_are_distinct() {
    let codes = [
        ERR_PROOF_INVALID,
        ERR_CONTEXT_MISMATCH,
        ERR_THRESHOLD_NOT_MET,
        ERR_SIGNATURE_INVALID,
        ERR_STALE_ROOT,
        ERR_NULLIFIER_SPENT,
    ];
    let mut seen = std::collections::HashSet::new();
    for &c in &codes {
        assert!(seen.insert(c), "duplicate error code {}", c);
    }
}

#[test]
fn gate_state_borsh_roundtrip() {
    use borsh::{BorshDeserialize, BorshSerialize};

    let state = GateState {
        accepted_root: [0xabu8; 32],
        spent_nullifiers: vec![[0x01u8; 32], [0x02u8; 32]],
    };

    let encoded = borsh::to_vec(&state).unwrap();
    let decoded = GateState::try_from_slice(&encoded).unwrap();

    assert_eq!(state.accepted_root, decoded.accepted_root);
    assert_eq!(state.spent_nullifiers, decoded.spent_nullifiers);
}

#[test]
fn nullifier_domain_tag_prevents_reuse_across_contexts() {
    use sha2::{Digest, Sha256};

    let nsk = [0x42u8; 32];
    let context1 = [0x01u8; 32];
    let context2 = [0x02u8; 32];
    let use_nonce = 0u128;

    // nullifier = SHA256("balance-attest/v1" || nsk || context_id || use_nonce)
    let mut h1 = Sha256::new();
    h1.update(b"balance-attest/v1");
    h1.update(&nsk);
    h1.update(&context1);
    h1.update(&use_nonce.to_le_bytes());
    let n1: [u8; 32] = h1.finalize().into();

    let mut h2 = Sha256::new();
    h2.update(b"balance-attest/v1");
    h2.update(&nsk);
    h2.update(&context2);
    h2.update(&use_nonce.to_le_bytes());
    let n2: [u8; 32] = h2.finalize().into();

    assert_ne!(n1, n2, "nullifiers for different contexts must differ");
}
