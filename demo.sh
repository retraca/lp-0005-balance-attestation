#!/usr/bin/env bash
# LP-0005 private balance attestation end-to-end demo.
#
# Proves that a shielded LEZ account has balance >= threshold without
# revealing the actual balance, the account ID, or the NSK.
# Runs fully offline: generates the proof, then verifies it locally.
# On-chain submission requires a running LEZ sequencer (see README).
#
# Usage: ./demo.sh [--dev]   (--dev sets RISC0_DEV_MODE=1 for fast testing)

set -euo pipefail

DEV_MODE=0
for arg in "$@"; do
  [ "$arg" = "--dev" ] && DEV_MODE=1
done

if [ "$DEV_MODE" = "1" ]; then
  export RISC0_DEV_MODE=1
  echo "[demo] RISC0_DEV_MODE=1 (fast mock proofs, no ZK)"
else
  echo "[demo] Real RISC0 proofs -- proof generation takes several minutes"
fi

ATTEST_BIN="./target/release/balance-attest"

echo ""
echo "=== LP-0005 Private Balance Attestation Demo ==="
echo ""

echo "[1/5] Building..."
cargo build --release --bin balance-attest 2>&1 | tail -3

# Deterministic demo inputs -- never use these outside demo/testing
NSK="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PROGRAM_OWNER="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
CONTEXT_ID="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
PRESENTER_SK="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
BALANCE=1000
THRESHOLD=500

# Compute commitment and build a depth-1 Merkle tree (both leaves identical for demo)
COMMITMENT=$(python3 -c "
import hashlib, struct

nsk = bytes.fromhex('$NSK')
# NPK = SHA256('LEE/keys' || nsk || 0x07 || [0;23])
npk = hashlib.sha256(b'LEE/keys' + nsk + bytes([0x07]) + bytes(23)).digest()

data = b''
data_hash = hashlib.sha256(data).digest()

PREFIX = b'/LEE/v0.3/Commitment/' + bytes(11)
balance = ($BALANCE).to_bytes(16, 'little')
nonce   = (0).to_bytes(16, 'little')
po      = bytes.fromhex('$PROGRAM_OWNER')

commitment = hashlib.sha256(PREFIX + npk + po + balance + nonce + data_hash).digest()
print(commitment.hex())
")

LEAF=$(python3 -c "
import hashlib
c = bytes.fromhex('$COMMITMENT')
print(hashlib.sha256(c).digest().hex())
")
MERKLE_ROOT=$(python3 -c "
import hashlib
leaf = bytes.fromhex('$LEAF')
print(hashlib.sha256(b'\\x01' + leaf + leaf).digest().hex())
")

echo ""
echo "[2/5] Commitment: $COMMITMENT"
echo "      Merkle root: $MERKLE_ROOT"

echo ""
echo "[3/5] Generating attestation proof (NSK and balance are private inputs)..."
"$ATTEST_BIN" prove \
  --nsk "$NSK" \
  --program-owner "$PROGRAM_OWNER" \
  --balance "$BALANCE" \
  --threshold "$THRESHOLD" \
  --context-id "$CONTEXT_ID" \
  --presenter-sk "$PRESENTER_SK" \
  --merkle-root "$MERKLE_ROOT" \
  --leaf-index 0 \
  --merkle-path "$LEAF" \
  --out /tmp/attest-receipt.bin

echo ""
echo "[4/5] Verifying receipt offline..."
PRESENTER_PK=$(python3 -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import hashlib
sk_bytes = bytes.fromhex('$PRESENTER_SK')
sk = Ed25519PrivateKey.from_private_bytes(sk_bytes[:32])
print(sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
" 2>/dev/null || echo "00000000000000000000000000000000000000000000000000000000000000ff")

"$ATTEST_BIN" verify \
  --receipt /tmp/attest-receipt.bin \
  --context-id "$CONTEXT_ID" \
  --threshold "$THRESHOLD" \
  --presenter-pk "$PRESENTER_PK"

echo ""
echo "[5/5] Done."
echo ""
echo "=== Demo complete ==="
echo "Receipt: /tmp/attest-receipt.bin"
echo ""
echo "Privacy properties:"
echo "  - NSK and actual balance are private RISC0 inputs and never leave this machine"
echo "  - Nullifier = SHA256('balance-attest/v1' || nsk || context_id || use_nonce)"
echo "  - Presenter binding: Ed25519 signature over (context_id || merkle_root || threshold || nullifier)"
echo "  - Context binding: proof is only valid for the specific gating program (context_id)"
echo "  - One-shot: nullifier stored on-chain after first use; proof cannot be replayed"
