# LP-0005 Private Balance Attestation

Zero-knowledge balance attestation for the Logos Execution Zone. Prove that an LEZ account balance exceeds a threshold without revealing the balance, account ID, or nullifier secret key.

## Design

**Commitment replication**: The RISC0 guest replicates `nssa/core/src/commitment.rs`:
```
NPK        = SHA256("LEE/keys" || nsk || 0x07 || [0;23])
data_hash  = SHA256(data)
commitment = SHA256(PREFIX || NPK || program_owner_le || balance_le || nonce_le || data_hash)
```
The recomputed commitment is verified against the on-chain Merkle tree.

**Nullifier (circuit-bound)**: `SHA256("balance-attest/v1" || nsk || context_id || use_nonce)`. Computed inside the zkVM guest -- cannot be forged by the caller. The on-chain verifier reads `journal.nullifier`, not a parameter.

**Freshness**: The gating program stores `accepted_root`. Proofs over stale roots fail with `ERR_STALE_ROOT`.

**Presenter binding**: The caller signs `(context_id || merkle_root || threshold_n || nullifier)` with an Ed25519 key. Prevents relay attacks.

## Components

| Path | Role |
|------|------|
| `circuit/guest` | RISC0 zkVM guest circuit |
| `circuit/host` | CLI: `balance-attest prove / verify` |
| `programs/balance_attestation` | LEZ gating program (on-chain path) |
| `verifier-lib` | Off-chain verifier library (`verify_attestation`) |
| `messaging` | Logos Messaging transport: `attest-msg send / gatekeeper` |
| `sdk` | Client SDK helpers (`sign_attestation`) |

## Quick start

```bash
# Offline: generate a proof and verify it locally
./demo.sh --dev

# Off-chain path: attestation over Logos Messaging (Waku), token-gated
# group admission with replay denial. Requires docker + jq.
./demo-offchain.sh --dev
```

Manual CLI usage:

```bash
balance-attest prove \
  --nsk <hex> \
  --program-owner <hex> \
  --balance 1000 \
  --threshold 500 \
  --context-id <program-account-id> \
  --presenter-sk <hex> \
  --out receipt.bin
# online: --sequencer <url> fetches the Merkle proof from the chain
# offline: --merkle-root <hex> --leaf-index <n> --merkle-path <hex,hex,...>

balance-attest verify \
  --receipt receipt.bin \
  --context-id <hex> \
  --threshold 500 \
  --presenter-pk <hex> \
  --sig <hex>
```

## Off-chain path: Logos Messaging

The proof is a self-contained credential, so it can gate access without any
on-chain transaction. `attest-msg` transmits it over the Waku relay network:

```bash
# Gatekeeper guards a token-gated group, verifying incoming attestations
# locally with verifier-lib and tracking spent nullifiers:
attest-msg gatekeeper --node http://127.0.0.1:8646 \
  --context-id <hex> --threshold 500 --group vip-room

# Prover publishes the attestation and awaits the verdict:
attest-msg send --node http://127.0.0.1:8645 \
  --receipt receipt.bin --presenter-pk <hex> --sig <hex>
```

Content topics: `/lp0005/1/attest/json` (attestations) and
`/lp0005/1/gate-response/json` (verdicts), on relay shard `/waku/2/rs/66/0`.
`demo-offchain.sh` runs the full flow against two relay-connected nwaku nodes,
including the replay-denial case.

## Error codes

| Code | Meaning |
|------|---------|
| 5001 | ERR_PROOF_INVALID |
| 5002 | ERR_CONTEXT_MISMATCH |
| 5003 | ERR_THRESHOLD_NOT_MET |
| 5004 | ERR_SIGNATURE_INVALID |
| 5005 | ERR_STALE_ROOT |
| 5006 | ERR_NULLIFIER_SPENT |

## License

MIT or Apache-2.0
