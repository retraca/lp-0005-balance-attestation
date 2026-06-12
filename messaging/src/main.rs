//! Logos Messaging (Waku) transport for LP-0005 balance attestations.
//!
//! Off-chain verification path: a prover transmits their attestation over the
//! Logos Messaging network (Waku relay) and a gatekeeper verifies it locally
//! to grant access to a token-gated chat group. No on-chain transaction.
//!
//! Two roles:
//!   `attest-msg send`       -- publish an attestation to the gate's content
//!                              topic and wait for the admit/deny response.
//!   `attest-msg gatekeeper` -- subscribe to the gate topic, verify each
//!                              incoming attestation with the off-chain
//!                              verifier library, track spent nullifiers, and
//!                              publish admit/deny responses.
//!
//! Both talk to a Waku node's REST API (nwaku, `--rest` flag). The demo
//! script `demo-offchain.sh` runs two relay-connected nwaku nodes so the
//! attestation genuinely crosses the messaging network.

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use balance_attestation_verifier::{verify_attestation, IMAGE_ID};

const ATTEST_TOPIC: &str = "/lp0005/1/attest/json";
const RESPONSE_TOPIC: &str = "/lp0005/1/gate-response/json";
/// Static relay shard used by the demo nodes (`--cluster-id=66 --shard=0`).
const PUBSUB_TOPIC: &str = "/waku/2/rs/66/0";

#[derive(Parser)]
#[command(name = "attest-msg", about = "LP-0005 attestation over Logos Messaging (Waku)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Send an attestation to a gatekeeper over Logos Messaging and await the verdict.
    Send {
        /// Waku node REST API URL.
        #[arg(long, default_value = "http://127.0.0.1:8645")]
        node: String,
        /// Path to the receipt file produced by `balance-attest prove`.
        #[arg(long)]
        receipt: PathBuf,
        /// Presenter Ed25519 public key (64-char hex, printed by `prove`).
        #[arg(long)]
        presenter_pk: String,
        /// Presenter signature (128-char hex, printed by `prove`).
        #[arg(long)]
        sig: String,
        /// Request ID (any string; echoed back in the response).
        #[arg(long, default_value = "req-1")]
        request_id: String,
        /// Seconds to wait for the gatekeeper's response.
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
    /// Run the token-gated group gatekeeper: verify incoming attestations, admit or deny.
    Gatekeeper {
        /// Waku node REST API URL.
        #[arg(long, default_value = "http://127.0.0.1:8645")]
        node: String,
        /// Context ID this gate accepts (64-char hex). Proofs for other gates are denied.
        #[arg(long)]
        context_id: String,
        /// Minimum balance threshold required for admission.
        #[arg(long)]
        threshold: u128,
        /// Name of the token-gated group (returned to admitted members).
        #[arg(long, default_value = "vip-room")]
        group: String,
        /// File for persisting spent nullifiers across restarts.
        #[arg(long, default_value = "gatekeeper-state.json")]
        state: PathBuf,
        /// Exit after handling this many attestations (0 = run forever).
        #[arg(long, default_value = "0")]
        max_messages: u64,
    },
}

/// Envelope published to the attest topic.
#[derive(Serialize, Deserialize)]
struct AttestationEnvelope {
    v: u8,
    request_id: String,
    receipt_hex: String,
    presenter_pk: String,
    sig: String,
}

/// Verdict published to the response topic.
#[derive(Serialize, Deserialize)]
struct GateResponse {
    v: u8,
    request_id: String,
    admitted: bool,
    reason: String,
    /// Present only on admission: the group the presenter was admitted to.
    group: Option<String>,
    /// Present only on admission: nullifier consumed by this admission.
    nullifier: Option<String>,
}

// ── Waku REST helpers (static relay shard) ─────────────────────────────────

async fn waku_publish(
    client: &reqwest::Client,
    node: &str,
    content_topic: &str,
    payload: &[u8],
) -> Result<()> {
    let body = serde_json::json!({
        "contentTopic": content_topic,
        "payload": base64::engine::general_purpose::STANDARD.encode(payload),
    });
    let encoded = urlencoding::encode(PUBSUB_TOPIC);
    let resp = client
        .post(format!("{node}/relay/v1/messages/{encoded}"))
        .json(&body)
        .send()
        .await
        .context("publish request failed")?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!("publish failed: {status} {text}");
    }
    Ok(())
}

async fn waku_subscribe(client: &reqwest::Client, node: &str) -> Result<()> {
    let resp = client
        .post(format!("{node}/relay/v1/subscriptions"))
        .json(&serde_json::json!([PUBSUB_TOPIC]))
        .send()
        .await
        .context("subscribe request failed")?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!("subscribe failed: {status} {text}");
    }
    Ok(())
}

/// Poll the relay cache; return payloads whose contentTopic matches.
async fn waku_poll(client: &reqwest::Client, node: &str, content_topic: &str) -> Result<Vec<Vec<u8>>> {
    let encoded = urlencoding::encode(PUBSUB_TOPIC);
    let resp = client
        .get(format!("{node}/relay/v1/messages/{encoded}"))
        .send()
        .await
        .context("poll request failed")?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        bail!("poll failed: {status} {text}");
    }
    let messages: Vec<serde_json::Value> = resp.json().await.context("poll response not JSON")?;
    let mut out = Vec::new();
    for m in messages {
        if m.get("contentTopic").and_then(|t| t.as_str()) != Some(content_topic) {
            continue;
        }
        if let Some(p) = m.get("payload").and_then(|p| p.as_str()) {
            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(p) {
                out.push(bytes);
            }
        }
    }
    Ok(out)
}

// ── Gatekeeper state ───────────────────────────────────────────────────────

#[derive(Default, Serialize, Deserialize)]
struct GatekeeperState {
    spent_nullifiers: HashSet<String>,
    members: Vec<String>,
}

fn load_state(path: &PathBuf) -> GatekeeperState {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_state(path: &PathBuf, state: &GatekeeperState) -> Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(state)?)?;
    Ok(())
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("invalid hex")?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", bytes.len()))
}

fn parse_hex64(s: &str) -> Result<[u8; 64]> {
    let bytes = hex::decode(s).context("invalid hex")?;
    <[u8; 64]>::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("expected 64 bytes, got {}", bytes.len()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    match cli.cmd {
        Cmd::Send { node, receipt, presenter_pk, sig, request_id, timeout } => {
            // Validate inputs before publishing.
            parse_hex32(&presenter_pk)?;
            parse_hex64(&sig)?;
            let receipt_bytes = std::fs::read(&receipt).context("read receipt file")?;

            let envelope = AttestationEnvelope {
                v: 1,
                request_id: request_id.clone(),
                receipt_hex: hex::encode(&receipt_bytes),
                presenter_pk,
                sig,
            };
            let payload = serde_json::to_vec(&envelope)?;

            // Subscribe to the shard before publishing so the verdict is not missed.
            waku_subscribe(&client, &node).await?;

            eprintln!("Publishing attestation ({} bytes) to {ATTEST_TOPIC}...", payload.len());
            waku_publish(&client, &node, ATTEST_TOPIC, &payload).await?;
            eprintln!("Waiting for gatekeeper verdict (timeout {timeout}s)...");

            let deadline = std::time::Instant::now() + Duration::from_secs(timeout);
            loop {
                if std::time::Instant::now() > deadline {
                    bail!("timed out waiting for gatekeeper response");
                }
                for raw in waku_poll(&client, &node, RESPONSE_TOPIC).await? {
                    let Ok(resp) = serde_json::from_slice::<GateResponse>(&raw) else {
                        continue;
                    };
                    if resp.request_id != request_id {
                        continue;
                    }
                    if resp.admitted {
                        println!("ADMITTED to group: {}", resp.group.as_deref().unwrap_or("?"));
                        println!("nullifier consumed: {}", resp.nullifier.as_deref().unwrap_or("?"));
                        return Ok(());
                    }
                    println!("DENIED: {}", resp.reason);
                    std::process::exit(2);
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        Cmd::Gatekeeper { node, context_id, threshold, group, state, max_messages } => {
            let ctx = parse_hex32(&context_id)?;
            let mut gk_state = load_state(&state);

            waku_subscribe(&client, &node).await?;
            eprintln!("Gatekeeper for group '{group}' listening on {ATTEST_TOPIC}");
            eprintln!("  context_id: {context_id}");
            eprintln!("  threshold:  {threshold}");
            eprintln!("  spent nullifiers loaded: {}", gk_state.spent_nullifiers.len());

            let mut handled = 0u64;
            loop {
                for raw in waku_poll(&client, &node, ATTEST_TOPIC).await? {
                    let Ok(env) = serde_json::from_slice::<AttestationEnvelope>(&raw) else {
                        eprintln!("[skip] non-envelope message on attest topic");
                        continue;
                    };
                    handled += 1;
                    let verdict = handle_attestation(&env, &ctx, threshold, &group, &mut gk_state);
                    if verdict.admitted {
                        save_state(&state, &gk_state)?;
                    }
                    eprintln!(
                        "[{}] request {} -> {}",
                        handled,
                        env.request_id,
                        if verdict.admitted { "ADMITTED".to_string() } else { format!("DENIED ({})", verdict.reason) }
                    );
                    let payload = serde_json::to_vec(&verdict)?;
                    waku_publish(&client, &node, RESPONSE_TOPIC, &payload).await?;

                    if max_messages > 0 && handled >= max_messages {
                        eprintln!("Handled {handled} attestation(s); exiting.");
                        return Ok(());
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

/// Verify one attestation envelope and produce a verdict.
/// Verification failure must not leak private account data -- the reason
/// string contains only the public failure category.
fn handle_attestation(
    env: &AttestationEnvelope,
    expected_context: &[u8; 32],
    threshold: u128,
    group: &str,
    state: &mut GatekeeperState,
) -> GateResponse {
    let deny = |reason: &str| GateResponse {
        v: 1,
        request_id: env.request_id.clone(),
        admitted: false,
        reason: reason.to_string(),
        group: None,
        nullifier: None,
    };

    let Ok(receipt_bytes) = hex::decode(&env.receipt_hex) else {
        return deny("malformed receipt encoding");
    };
    let Ok(pk) = parse_hex32(&env.presenter_pk) else {
        return deny("malformed presenter_pk");
    };
    let Ok(sig) = parse_hex64(&env.sig) else {
        return deny("malformed signature");
    };

    let attestation = match verify_attestation(
        &receipt_bytes,
        IMAGE_ID,
        expected_context,
        threshold,
        &pk,
        &sig,
    ) {
        Ok(a) => a,
        // Pass the verifier's error category through; it never contains
        // private inputs (nsk, balance, account identity).
        Err(e) => return deny(&format!("verification failed: {e}")),
    };

    let nullifier_hex = hex::encode(attestation.nullifier);
    if state.spent_nullifiers.contains(&nullifier_hex) {
        return deny("nullifier already spent: this attestation was used before");
    }

    state.spent_nullifiers.insert(nullifier_hex.clone());
    state.members.push(env.presenter_pk.clone());

    GateResponse {
        v: 1,
        request_id: env.request_id.clone(),
        admitted: true,
        reason: String::new(),
        group: Some(group.to_string()),
        nullifier: Some(nullifier_hex),
    }
}
