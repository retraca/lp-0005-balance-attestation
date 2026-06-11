//! RISC0 guest: private balance attestation for LP-0005.
//!
//! Proves: "I hold a shielded LEZ account with balance >= threshold_n,
//! and that account is a leaf in the public commitment Merkle tree."
//!
//! Private inputs (never leave the prover):
//!   - nsk: nullifier secret key
//!   - account: program_owner, balance, data, nonce
//!   - membership_proof: (leaf_index, sibling_nodes)
//!
//! Public outputs (journal, visible to verifier):
//!   - merkle_root: CommitmentSetDigest from chain
//!   - threshold_n: the minimum balance the prover claims
//!   - context_id: gate identifier (prevents proof replay across different gates)
//!   - presenter_pk: ed25519 public key bound into the proof (prevents forwarding)

#![no_std]
#![no_main]

use risc0_zkvm::guest::env;
use risc0_zkvm::sha::{Impl as ShaImpl, Sha256 as _};

risc0_zkvm::guest::entry!(main);

// ── Input types (must match host) ─────────────────────────────────────────

#[derive(serde::Deserialize)]
struct GuestInput {
    nsk: [u8; 32],
    program_owner: [u32; 8],
    balance: u128,
    data: alloc::vec::Vec<u8>,
    /// Account nonce -- part of the commitment preimage (the balance account's nonce field).
    nonce: u128,
    merkle_root: [u8; 32],
    threshold_n: u128,
    context_id: [u8; 32],
    presenter_pk: [u8; 32],
    leaf_index: usize,
    sibling_nodes: alloc::vec::Vec<[u8; 32]>,
    /// Per-use nonce for the nullifier (prevents two proofs with the same nsk being identical).
    /// The host must pick a fresh random value per proof generation.
    use_nonce: u128,
}

// ── Journal (public output) ───────────────────────────────────────────────

#[derive(serde::Serialize)]
struct BalanceAttestation {
    merkle_root: [u8; 32],
    threshold_n: u128,
    context_id: [u8; 32],
    presenter_pk: [u8; 32],
    /// One-shot nullifier: SHA256("balance-attest/v1" || nsk || context_id || nonce).
    /// Bound to the prover's nsk -- cannot be replayed without the original nsk.
    nullifier: [u8; 32],
}

pub fn main() {
    let input: GuestInput = env::read();

    // 1. Derive NPK from NSK.
    // npk = SHA256("LEE/keys" || nsk || 0x07 || [0;23])
    let npk = {
        let mut preimage = alloc::vec::Vec::with_capacity(8 + 32 + 1 + 23);
        preimage.extend_from_slice(b"LEE/keys");
        preimage.extend_from_slice(&input.nsk);
        preimage.push(0x07);
        preimage.extend_from_slice(&[0u8; 23]);
        ShaImpl::hash_bytes(&preimage).as_bytes().try_into().unwrap()
    };

    // 2. Recompute commitment.
    // SHA256(PREFIX || npk || program_owner_le || balance_le || nonce_le || SHA256(data))
    let commitment = {
        const PREFIX: &[u8; 32] = b"/LEE/v0.3/Commitment/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let hashed_data: [u8; 32] = ShaImpl::hash_bytes(&input.data).as_bytes().try_into().unwrap();
        let mut bytes = alloc::vec::Vec::with_capacity(32 + 32 + 32 + 16 + 16 + 32);
        bytes.extend_from_slice(PREFIX);
        bytes.extend_from_slice(&npk);
        for word in &input.program_owner {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes.extend_from_slice(&input.balance.to_le_bytes());
        bytes.extend_from_slice(&input.nonce.to_le_bytes());
        bytes.extend_from_slice(&hashed_data);
        ShaImpl::hash_bytes(&bytes).as_bytes().try_into::<[u8; 32]>().unwrap()
    };

    // 3. Verify Merkle membership.
    // Replicate compute_digest_for_path from nssa/core/src/commitment.rs.
    let computed_root = {
        let mut result: [u8; 32] = ShaImpl::hash_bytes(&commitment).as_bytes().try_into().unwrap();
        let mut level_index = input.leaf_index;
        for node in &input.sibling_nodes {
            let mut pair = [0u8; 64];
            if level_index & 1 == 0 {
                pair[..32].copy_from_slice(&result);
                pair[32..].copy_from_slice(node);
            } else {
                pair[..32].copy_from_slice(node);
                pair[32..].copy_from_slice(&result);
            }
            result = ShaImpl::hash_bytes(&pair).as_bytes().try_into().unwrap();
            level_index >>= 1;
        }
        result
    };

    // 4. Assert Merkle root matches the public root from the chain.
    assert_eq!(computed_root, input.merkle_root, "Merkle root mismatch");

    // 5. Assert balance satisfies the threshold.
    assert!(input.balance >= input.threshold_n, "balance below threshold");

    // 6. Compute nullifier = SHA256("balance-attest/v1" || nsk || context_id || nonce).
    // Bound to nsk: cannot be replayed without the prover's secret key.
    let nullifier = {
        let mut preimage = alloc::vec::Vec::with_capacity(16 + 32 + 32 + 16);
        preimage.extend_from_slice(b"balance-attest/v1");
        preimage.extend_from_slice(&input.nsk);
        preimage.extend_from_slice(&input.context_id);
        preimage.extend_from_slice(&input.use_nonce.to_le_bytes());
        ShaImpl::hash_bytes(&preimage).as_bytes().try_into::<[u8; 32]>().unwrap()
    };

    // 7. Write journal.
    env::commit(&BalanceAttestation {
        merkle_root: input.merkle_root,
        threshold_n: input.threshold_n,
        context_id: input.context_id,
        presenter_pk: input.presenter_pk,
        nullifier,
    });
}

extern crate alloc;
