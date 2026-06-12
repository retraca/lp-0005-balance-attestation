//! Integration tests for the LP-0005 balance attestation gate program.
//! Tests run against `apply_attestation` directly -- no LEZ sequencer or
//! RISC0 receipt needed. The ZK proof path is tested separately via `demo.sh`.

use balance_attestation_program::*;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use spel_framework::error::SpelError;

const CONTEXT_ID: [u8; 32] = [0xcc_u8; 32];
const MERKLE_ROOT: [u8; 32] = [0xaa_u8; 32];

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42u8; 32])
}

fn make_journal(context_id: [u8; 32], threshold_n: u128, nullifier: [u8; 32]) -> (AttestationJournal, [u8; 64]) {
    let sk = signing_key();
    let presenter_pk: [u8; 32] = sk.verifying_key().to_bytes();

    let mut message = Vec::with_capacity(32 + 32 + 16 + 32);
    message.extend_from_slice(&context_id);
    message.extend_from_slice(&MERKLE_ROOT);
    message.extend_from_slice(&threshold_n.to_le_bytes());
    message.extend_from_slice(&nullifier);

    let sig: [u8; 64] = sk.sign(&message).to_bytes();

    let journal = AttestationJournal {
        merkle_root: MERKLE_ROOT,
        threshold_n,
        context_id,
        presenter_pk,
        nullifier,
    };
    (journal, sig)
}

fn base_state() -> GateState {
    GateState {
        accepted_root: MERKLE_ROOT,
        spent_nullifiers: vec![],
    }
}

#[test]
fn successful_attestation_consumes_nullifier() {
    let mut state = base_state();
    let nullifier = [0x01u8; 32];
    let (journal, sig) = make_journal(CONTEXT_ID, 100, nullifier);

    apply_attestation(&mut state, &journal, CONTEXT_ID, sig, 100).unwrap();

    assert!(state.spent_nullifiers.contains(&nullifier));
}

#[test]
fn nullifier_spent_rejected() {
    let mut state = base_state();
    let nullifier = [0x01u8; 32];
    let (journal, sig) = make_journal(CONTEXT_ID, 100, nullifier);

    apply_attestation(&mut state, &journal, CONTEXT_ID, sig, 100).unwrap();

    let (journal2, sig2) = make_journal(CONTEXT_ID, 100, nullifier);
    let err = apply_attestation(&mut state, &journal2, CONTEXT_ID, sig2, 100).unwrap_err();
    let SpelError::Custom { code, .. } = err else { panic!("wrong error type") };
    assert_eq!(code, ERR_NULLIFIER_SPENT, "wrong error code");
}

#[test]
fn context_mismatch_rejected() {
    let mut state = base_state();
    let wrong_context = [0xffu8; 32];
    let (journal, sig) = make_journal(wrong_context, 100, [0x01u8; 32]);

    let err = apply_attestation(&mut state, &journal, CONTEXT_ID, sig, 100).unwrap_err();
    let SpelError::Custom { code, .. } = err else { panic!("wrong error type") };
    assert_eq!(code, ERR_CONTEXT_MISMATCH, "wrong error code");
    assert!(state.spent_nullifiers.is_empty(), "nullifier must not be consumed on failure");
}

#[test]
fn threshold_not_met_rejected() {
    let mut state = base_state();
    let (journal, sig) = make_journal(CONTEXT_ID, 50, [0x01u8; 32]);

    let err = apply_attestation(&mut state, &journal, CONTEXT_ID, sig, 100).unwrap_err();
    let SpelError::Custom { code, .. } = err else { panic!("wrong error type") };
    assert_eq!(code, ERR_THRESHOLD_NOT_MET, "wrong error code");
    assert!(state.spent_nullifiers.is_empty(), "nullifier must not be consumed on failure");
}

#[test]
fn threshold_met_exactly_succeeds() {
    let mut state = base_state();
    let (journal, sig) = make_journal(CONTEXT_ID, 100, [0x01u8; 32]);

    apply_attestation(&mut state, &journal, CONTEXT_ID, sig, 100).unwrap();
}

#[test]
fn stale_root_rejected() {
    let mut state = GateState {
        accepted_root: [0xbbu8; 32],
        spent_nullifiers: vec![],
    };
    let (journal, sig) = make_journal(CONTEXT_ID, 100, [0x01u8; 32]);

    let err = apply_attestation(&mut state, &journal, CONTEXT_ID, sig, 100).unwrap_err();
    let SpelError::Custom { code, .. } = err else { panic!("wrong error type") };
    assert_eq!(code, ERR_STALE_ROOT, "wrong error code");
    assert!(state.spent_nullifiers.is_empty(), "nullifier must not be consumed on failure");
}

#[test]
fn invalid_signature_rejected() {
    let mut state = base_state();
    let (journal, _) = make_journal(CONTEXT_ID, 100, [0x01u8; 32]);
    let bad_sig = [0u8; 64];

    let err = apply_attestation(&mut state, &journal, CONTEXT_ID, bad_sig, 100).unwrap_err();
    let SpelError::Custom { code, .. } = err else { panic!("wrong error type") };
    assert_eq!(code, ERR_SIGNATURE_INVALID, "wrong error code");
    assert!(state.spent_nullifiers.is_empty(), "nullifier must not be consumed on failure");
}

#[test]
fn two_distinct_attestations_both_succeed() {
    let mut state = base_state();

    let (j1, s1) = make_journal(CONTEXT_ID, 100, [0x01u8; 32]);
    apply_attestation(&mut state, &j1, CONTEXT_ID, s1, 100).unwrap();

    let (j2, s2) = make_journal(CONTEXT_ID, 200, [0x02u8; 32]);
    apply_attestation(&mut state, &j2, CONTEXT_ID, s2, 50).unwrap();

    assert_eq!(state.spent_nullifiers.len(), 2);
}

#[test]
fn gate_state_borsh_roundtrip() {
    use borsh::BorshDeserialize;

    let state = GateState {
        accepted_root: [0xab_u8; 32],
        spent_nullifiers: vec![[0x01u8; 32], [0x02u8; 32]],
    };

    let encoded = borsh::to_vec(&state).unwrap();
    let decoded = GateState::try_from_slice(&encoded).unwrap();

    assert_eq!(state.accepted_root, decoded.accepted_root);
    assert_eq!(state.spent_nullifiers, decoded.spent_nullifiers);
}

#[test]
fn nullifier_domain_tag_prevents_reuse_across_contexts() {
    let nsk = [0x42u8; 32];
    let context1 = [0x01u8; 32];
    let context2 = [0x02u8; 32];
    let use_nonce = 0u128;

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
