//! Guest binary entry point for LP-0005 balance attestation gate program.
//! Deploy with: cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf
//!              wallet deploy-program target/riscv32im-risc0-zkvm-elf/release/balance_attestation
//!
//! The balance-attestation circuit receipt is passed as a zkVM assumption.
//! The gate instruction calls env::verify(IMAGE_ID, journal_words) to bind the
//! proof to this specific circuit -- the LEZ-native pattern (see LP-0002, LP-0003).

#![no_main]

use borsh::BorshDeserialize;
use nssa_core::account::{AccountWithMetadata, Data};
use balance_attestation_program::{
    apply_attestation, AttestationJournal, GateState,
    ERR_PROOF_INVALID,
};
use risc0_zkvm::guest::env;
use spel_framework::prelude::*;

include!(concat!(env!("OUT_DIR"), "/methods.rs"));
use BALANCE_ATTESTATION_GUEST_ID as IMAGE_ID;

risc0_zkvm::guest::entry!(main);

#[lez_program]
mod attestation {

    /// Initialize a new gate with an accepted Merkle root.
    #[instruction]
    pub fn initialize(
        #[account(init)] mut gate_account: AccountWithMetadata,
        initial_root: [u8; 32],
    ) -> SpelResult {
        let state = GateState {
            accepted_root: initial_root,
            spent_nullifiers: Vec::new(),
        };
        gate_account.account.data =
            Data::try_from(borsh::to_vec(&state).map_err(|e| SpelError::SerializationError {
                message: e.to_string(),
            })?)
            .map_err(|e| SpelError::SerializationError {
                message: format!("state too large: {e:?}"),
            })?;
        Ok(SpelOutput::execute(vec![gate_account], vec![]))
    }

    /// Verify a balance attestation proof and consume the one-shot nullifier.
    ///
    /// The circuit receipt must be submitted as a zkVM assumption before calling.
    /// `journal_bytes` is borsh-serialized AttestationJournal:
    ///   [u8;32] merkle_root, u128 threshold_n, [u8;32] context_id,
    ///   [u8;32] presenter_pk, [u8;32] nullifier
    /// `presenter_sig_bytes` is the 64-byte Ed25519 signature (Vec<u8> to work around
    /// serde's [T; N > 32] limitation in the instruction macro).
    #[instruction]
    pub fn gate(
        #[account(mut)] mut gate_account: AccountWithMetadata,
        journal_bytes: Vec<u8>,
        presenter_sig_bytes: Vec<u8>,
        expected_threshold: u128,
    ) -> SpelResult {
        if presenter_sig_bytes.len() != 64 {
            return Err(SpelError::Custom {
                code: ERR_PROOF_INVALID,
                message: "presenter_sig must be 64 bytes".to_string(),
            });
        }
        let presenter_sig: [u8; 64] = presenter_sig_bytes.try_into().unwrap();
        let mut state =
            GateState::try_from_slice(gate_account.account.data.as_ref())
                .map_err(|_| SpelError::Custom {
                    code: ERR_PROOF_INVALID,
                    message: "state deserialise failed".to_string(),
                })?;

        let journal_words: Vec<u32> =
            risc0_zkvm::serde::to_vec(&journal_bytes).map_err(|_| SpelError::Custom {
                code: ERR_PROOF_INVALID,
                message: "journal serialise failed".to_string(),
            })?;
        env::verify(IMAGE_ID, &journal_words).map_err(|_| SpelError::Custom {
            code: ERR_PROOF_INVALID,
            message: "assumption verification failed".to_string(),
        })?;

        let journal =
            AttestationJournal::try_from_slice(&journal_bytes).map_err(|_| SpelError::Custom {
                code: ERR_PROOF_INVALID,
                message: "journal decode failed".to_string(),
            })?;

        let context_id: [u8; 32] = *gate_account.account_id.value();

        apply_attestation(&mut state, &journal, context_id, presenter_sig, expected_threshold)?;

        gate_account.account.data =
            Data::try_from(borsh::to_vec(&state).map_err(|e| SpelError::SerializationError {
                message: e.to_string(),
            })?)
            .map_err(|e| SpelError::SerializationError {
                message: format!("state too large: {e:?}"),
            })?;
        Ok(SpelOutput::execute(vec![gate_account], vec![]))
    }
}
