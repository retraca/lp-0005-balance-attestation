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
| `programs/balance_attestation` | LEZ gating program |

## Quick start

```bash
docker compose up -d

balance-attest prove \
  --nsk <hex> \
  --program-owner <hex> \
  --balance 1000 \
  --threshold 500 \
  --context-id <program-account-id> \
  --presenter-sk <hex> \
  --out receipt.bin

balance-attest verify \
  --receipt receipt.bin \
  --context-id <hex> \
  --threshold 500 \
  --presenter-pk <hex> \
  --sig <hex>
```

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
