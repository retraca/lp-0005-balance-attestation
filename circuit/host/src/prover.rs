//! Host prover for LP-0005 balance attestation.
//! Fetches the account from the chain, builds the Merkle proof, and runs the RISC0 prover.

use anyhow::Result;
use risc0_zkvm::{ExecutorEnv, ProverOpts, Receipt};
use serde::{Deserialize, Serialize};

use crate::methods::BALANCE_ATTESTATION_GUEST_ELF;

/// The full input to the guest circuit (serialised and passed as private input).
#[derive(Serialize, Deserialize)]
pub struct ProverInput {
    pub nsk: [u8; 32],
    pub program_owner: [u32; 8],
    pub balance: u128,
    pub data: Vec<u8>,
    pub nonce: u128,
    pub merkle_root: [u8; 32],
    pub threshold_n: u128,
    pub context_id: [u8; 32],
    pub presenter_pk: [u8; 32],
    pub leaf_index: usize,
    pub sibling_nodes: Vec<[u8; 32]>,
    pub use_nonce: u128,
}

/// Generate a balance attestation proof.
///
/// `input.nsk` is the nullifier secret key (kept private by the guest).
/// `input.merkle_root` must be fetched from the chain before calling.
/// `input.sibling_nodes` comes from `getProofForCommitment` RPC.
///
/// # Errors
///
/// Returns an error if the prover fails or the balance is below the threshold.
pub fn prove(input: ProverInput) -> Result<Receipt> {
    let env = ExecutorEnv::builder()
        .write(&input)?
        .build()?;
    let prover = risc0_zkvm::default_prover();
    let receipt = prover.prove_with_opts(
        env,
        BALANCE_ATTESTATION_GUEST_ELF,
        &ProverOpts::groth16(),
    )?.receipt;
    Ok(receipt)
}

/// Fetch the Merkle proof for an account from the sequencer.
/// Returns `(merkle_root, leaf_index, sibling_nodes)`.
pub async fn fetch_membership_proof(
    sequencer_url: &str,
    commitment: &[u8; 32],
) -> Result<([u8; 32], usize, Vec<[u8; 32]>)> {
    let client = reqwest::Client::new();
    let resp: serde_json::Value = client
        .post(sequencer_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "getProofForCommitment",
            "params": { "commitment": hex::encode(commitment) },
            "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;

    let result = resp["result"]
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("missing result"))?;
    let root_hex = result["merkle_root"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing merkle_root"))?;
    let leaf_index_u64 = result["leaf_index"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing leaf_index"))?;
    let siblings: Vec<[u8; 32]> = result["sibling_nodes"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("missing sibling_nodes"))?
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let s = v.as_str()
                .ok_or_else(|| anyhow::anyhow!("sibling_nodes[{i}] is not a string"))?;
            if s.len() != 64 {
                anyhow::bail!("sibling_nodes[{i}] is {} hex chars, expected 64", s.len());
            }
            let bytes = hex::decode(s)
                .map_err(|e| anyhow::anyhow!("sibling_nodes[{i}] invalid hex: {e}"))?;
            <[u8; 32]>::try_from(bytes.as_slice())
                .map_err(|_| anyhow::anyhow!("sibling_nodes[{i}] wrong length after decode"))
        })
        .collect::<Result<_>>()?;
    let root_bytes = hex::decode(root_hex)
        .map_err(|e| anyhow::anyhow!("merkle_root invalid hex: {e}"))?;
    let root = <[u8; 32]>::try_from(root_bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("merkle_root is not 32 bytes"))?;
    let leaf_index = usize::try_from(leaf_index_u64)
        .map_err(|_| anyhow::anyhow!("leaf_index overflows usize"))?;
    Ok((root, leaf_index, siblings))

}
