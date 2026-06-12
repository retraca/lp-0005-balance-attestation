use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use hex::FromHex;
use std::path::PathBuf;

mod methods;
mod prover;
use methods::BALANCE_ATTESTATION_GUEST_ID;
use prover::{fetch_membership_proof, prove, ProverInput};

#[derive(Parser)]
#[command(name = "balance-attest", about = "LP-0005 balance attestation CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a balance attestation proof.
    Prove {
        /// Nullifier secret key (64-char hex).
        #[arg(long)]
        nsk: String,
        /// Program owner account ID (64-char hex).
        #[arg(long)]
        program_owner: String,
        /// Account balance (u128).
        #[arg(long)]
        balance: u128,
        /// Minimum balance threshold to prove (u128).
        #[arg(long)]
        threshold: u128,
        /// Context ID (64-char hex) -- the gating program's account ID.
        #[arg(long)]
        context_id: String,
        /// Presenter Ed25519 signing key (64-char hex, seed).
        #[arg(long)]
        presenter_sk: String,
        /// Sequencer JSON-RPC URL.
        #[arg(long, default_value = "http://127.0.0.1:9090")]
        sequencer: String,
        /// Optional arbitrary data committed to the proof (hex).
        #[arg(long, default_value = "")]
        data: String,
        /// Write receipt bytes to this file (default: receipt.bin).
        #[arg(long, default_value = "receipt.bin")]
        out: PathBuf,
        /// Offline mode: Merkle root (64-char hex). Skips the sequencer fetch
        /// when --merkle-root, --leaf-index, and --merkle-path are all given.
        #[arg(long)]
        merkle_root: Option<String>,
        /// Offline mode: leaf index in the commitment tree.
        #[arg(long)]
        leaf_index: Option<usize>,
        /// Offline mode: sibling nodes from leaf to root (comma-separated hex).
        #[arg(long)]
        merkle_path: Option<String>,
    },
    /// Verify a receipt offline (no chain access needed).
    Verify {
        /// Path to receipt file produced by `prove`.
        #[arg(long)]
        receipt: PathBuf,
        /// Context ID the proof was generated for (64-char hex).
        #[arg(long)]
        context_id: String,
        /// Minimum threshold to check against (u128).
        #[arg(long)]
        threshold: u128,
        /// Presenter Ed25519 public key (64-char hex).
        #[arg(long)]
        presenter_pk: String,
        /// Presenter signature over (context_id || merkle_root || threshold_n || nullifier) (128-char hex).
        #[arg(long)]
        sig: String,
    },
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = Vec::from_hex(s).context("invalid hex")?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", bytes.len()))
}

fn parse_hex64(s: &str) -> Result<[u8; 64]> {
    let bytes = Vec::from_hex(s).context("invalid hex")?;
    <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| anyhow::anyhow!("expected 64 bytes, got {}", bytes.len()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Prove { nsk, program_owner, balance, threshold, context_id, presenter_sk, sequencer, data, out, merkle_root, leaf_index, merkle_path } => {
            let nsk_bytes = parse_hex32(&nsk)?;
            let po_bytes = parse_hex32(&program_owner)?;
            let ctx_bytes = parse_hex32(&context_id)?;
            let sk_seed = parse_hex32(&presenter_sk)?;
            let data_bytes = if data.is_empty() {
                vec![]
            } else {
                Vec::from_hex(&data).context("invalid data hex")?
            };

            // Derive presenter keypair from seed.
            use ed25519_dalek::{SigningKey, Signer};
            let signing_key = SigningKey::from_bytes(&sk_seed);
            let presenter_pk: [u8; 32] = signing_key.verifying_key().to_bytes();

            // Compute the commitment to look up in the Merkle tree.
            let commitment = compute_commitment(&nsk_bytes, &po_bytes, balance, &data_bytes, 0u128)?;

            let (merkle_root, leaf_index, sibling_nodes) =
                match (merkle_root, leaf_index, merkle_path) {
                    (Some(root_hex), Some(idx), Some(path)) => {
                        // Offline mode: caller supplies the membership proof directly.
                        let root = parse_hex32(&root_hex)?;
                        let siblings: Result<Vec<[u8; 32]>> =
                            path.split(',').map(|s| parse_hex32(s.trim())).collect();
                        (root, idx, siblings?)
                    }
                    (None, None, None) => {
                        eprintln!("Fetching Merkle proof from {}...", sequencer);
                        fetch_membership_proof(&sequencer, &commitment).await?
                    }
                    _ => bail!(
                        "offline mode requires all of --merkle-root, --leaf-index, --merkle-path"
                    ),
                };
            eprintln!("Merkle root: {}", hex::encode(merkle_root));

            // Convert program_owner bytes to [u32; 8] LE.
            let mut po_words = [0u32; 8];
            for (i, chunk) in po_bytes.chunks_exact(4).enumerate() {
                po_words[i] = u32::from_le_bytes(chunk.try_into().unwrap());
            }

            let input = ProverInput {
                nsk: nsk_bytes,
                program_owner: po_words,
                balance,
                data: data_bytes,
                nonce: 0,
                merkle_root,
                threshold_n: threshold,
                context_id: ctx_bytes,
                presenter_pk,
                leaf_index,
                sibling_nodes,
                use_nonce: 0,
            };

            eprintln!("Running RISC0 prover (this may take several minutes)...");
            let receipt = prove(input)?;

            // Sign (context_id || merkle_root || threshold_n || nullifier) for on-chain verification.
            #[derive(serde::Deserialize)]
            struct Journal {
                merkle_root: [u8; 32],
                threshold_n: u128,
                context_id: [u8; 32],
                #[allow(dead_code)]
                presenter_pk: [u8; 32],
                nullifier: [u8; 32],
            }
            let journal: Journal = receipt.journal.decode()?;
            let mut msg = Vec::with_capacity(112);
            msg.extend_from_slice(&journal.context_id);
            msg.extend_from_slice(&journal.merkle_root);
            msg.extend_from_slice(&journal.threshold_n.to_le_bytes());
            msg.extend_from_slice(&journal.nullifier);
            let sig = signing_key.sign(&msg);

            let receipt_bytes = risc0_zkvm::serde::to_vec(&receipt)
                .map_err(|e| anyhow::anyhow!("serialise receipt: {e}"))?;
            let receipt_bytes: Vec<u8> = bytemuck::cast_slice(&receipt_bytes).to_vec();

            std::fs::write(&out, &receipt_bytes)?;
            eprintln!("Receipt written to {}", out.display());
            println!("presenter_pk:  {}", hex::encode(presenter_pk));
            println!("sig:           {}", hex::encode(sig.to_bytes()));
            println!("nullifier:     {}", hex::encode(journal.nullifier));
        }

        Cmd::Verify { receipt, context_id, threshold, presenter_pk, sig } => {

            let ctx_bytes = parse_hex32(&context_id)?;
            let pk_bytes = parse_hex32(&presenter_pk)?;
            let sig_bytes = parse_hex64(&sig)?;

            let raw = std::fs::read(&receipt)?;
            let words: Vec<u32> = raw.chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                .collect();
            let receipt: risc0_zkvm::Receipt = risc0_zkvm::serde::from_slice(&words)
                .map_err(|e| anyhow::anyhow!("deserialise: {e}"))?;

            receipt.verify(BALANCE_ATTESTATION_GUEST_ID)
                .context("receipt verification failed")?;

            #[derive(serde::Deserialize)]
            struct Journal {
                merkle_root: [u8; 32],
                threshold_n: u128,
                context_id: [u8; 32],
                #[allow(dead_code)]
                presenter_pk: [u8; 32],
                nullifier: [u8; 32],
            }
            let j: Journal = receipt.journal.decode()?;

            if j.context_id != ctx_bytes {
                bail!("context_id mismatch: expected {} got {}",
                    hex::encode(ctx_bytes), hex::encode(j.context_id));
            }
            if j.threshold_n < threshold {
                bail!("threshold not met: proof threshold={} required={}", j.threshold_n, threshold);
            }

            let mut msg = Vec::with_capacity(112);
            msg.extend_from_slice(&j.context_id);
            msg.extend_from_slice(&j.merkle_root);
            msg.extend_from_slice(&j.threshold_n.to_le_bytes());
            msg.extend_from_slice(&j.nullifier);

            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let vk = VerifyingKey::from_bytes(&pk_bytes).context("invalid presenter_pk")?;
            let sig = Signature::from_bytes(&sig_bytes);
            vk.verify(&msg, &sig).context("presenter signature invalid")?;

            println!("OK");
            println!("merkle_root: {}", hex::encode(j.merkle_root));
            println!("nullifier:   {}", hex::encode(j.nullifier));
            println!("threshold:   {}", j.threshold_n);
        }
    }

    Ok(())
}

/// Replicates the commitment hash from `nssa/core/src/commitment.rs` to locate the leaf.
fn compute_commitment(
    nsk: &[u8; 32],
    program_owner: &[u8; 32],
    balance: u128,
    data: &[u8],
    nonce: u128,
) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};

    // NPK = SHA256("LEE/keys" || nsk || 0x07 || [0;23])
    let mut h = Sha256::new();
    h.update(b"LEE/keys");
    h.update(nsk);
    h.update([0x07u8]);
    h.update([0u8; 23]);
    let npk: [u8; 32] = h.finalize().into();

    // data_hash = SHA256(data)
    let data_hash: [u8; 32] = Sha256::digest(data).into();

    // commitment = SHA256(PREFIX || npk || program_owner_le || balance_le || nonce_le || data_hash)
    const PREFIX: &[u8] = b"/LEE/v0.3/Commitment/\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let mut h = Sha256::new();
    h.update(PREFIX);
    h.update(npk);
    // program_owner as [u32; 8] little-endian
    for chunk in program_owner.chunks_exact(4) {
        let word = u32::from_le_bytes(chunk.try_into().unwrap());
        h.update(word.to_le_bytes());
    }
    h.update(balance.to_le_bytes());
    h.update(nonce.to_le_bytes());
    h.update(data_hash);
    Ok(h.finalize().into())
}
