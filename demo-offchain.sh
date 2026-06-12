#!/usr/bin/env bash
# LP-0005 off-chain verification path: attestation over Logos Messaging (Waku).
#
# Demonstrates token-gated chat group admission with no on-chain transaction:
#   1. Two relay-connected nwaku nodes (docker).
#   2. A gatekeeper subscribes on node B, guarding the group "vip-room".
#   3. A prover generates a balance attestation and publishes it via node A.
#   4. The attestation crosses the Waku relay network; the gatekeeper verifies
#      it locally (verifier-lib) and publishes ADMITTED.
#   5. A replay of the same attestation is DENIED (nullifier spent).
#
# Requirements: docker, jq, python3, cargo.
#
# Usage: ./demo-offchain.sh [--dev]   (--dev sets RISC0_DEV_MODE=1)

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

NWAKU_IMAGE="wakuorg/nwaku:v0.31.0"
NET="lp0005-waku"
NODE_A="lp0005-waku-a"   # prover side, REST on :8645
NODE_B="lp0005-waku-b"   # gatekeeper side, REST on :8646
GK_STATE="/tmp/lp0005-gatekeeper-state.json"

cleanup() {
  docker rm -f "$NODE_A" "$NODE_B" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -f "$GK_STATE"

echo ""
echo "=== LP-0005 Off-Chain Path: Attestation over Logos Messaging ==="
echo ""

echo "[1/7] Building binaries..."
cargo build --release --bin balance-attest --bin attest-msg 2>&1 | tail -2

echo ""
echo "[2/7] Starting two relay-connected Logos Messaging (nwaku) nodes..."
docker network create "$NET" >/dev/null

docker run -d --name "$NODE_A" --network "$NET" -p 8645:8645 "$NWAKU_IMAGE" \
  --relay=true --rest=true --rest-address=0.0.0.0 --rest-port=8645 \
  --cluster-id=66 --shard=0 --listen-address=0.0.0.0 --tcp-port=60000 >/dev/null

# Wait for node A REST to come up, then grab its multiaddr.
for i in $(seq 1 30); do
  curl -sf http://127.0.0.1:8645/debug/v1/info >/dev/null && break
  sleep 1
done
IP_A=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NODE_A")
PEER_A=$(curl -sf http://127.0.0.1:8645/debug/v1/info | jq -r '.listenAddresses[0]' | grep -oE '16U[A-Za-z0-9]+')
MADDR_A="/ip4/$IP_A/tcp/60000/p2p/$PEER_A"
echo "  Node A: $MADDR_A"

docker run -d --name "$NODE_B" --network "$NET" -p 8646:8645 "$NWAKU_IMAGE" \
  --relay=true --rest=true --rest-address=0.0.0.0 --rest-port=8645 \
  --cluster-id=66 --shard=0 --listen-address=0.0.0.0 --tcp-port=60000 \
  --staticnode="$MADDR_A" >/dev/null

for i in $(seq 1 30); do
  curl -sf http://127.0.0.1:8646/debug/v1/info >/dev/null && break
  sleep 1
done
sleep 3   # allow gossipsub mesh to form
echo "  Node B connected to Node A"

# Deterministic demo inputs -- never use these outside demo/testing
NSK="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PROGRAM_OWNER="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
CONTEXT_ID="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
PRESENTER_SK="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
BALANCE=1000
THRESHOLD=500

echo ""
echo "[3/7] Generating balance attestation (NSK and balance never leave this machine)..."
COMMITMENT=$(python3 -c "
import hashlib
nsk = bytes.fromhex('$NSK')
npk = hashlib.sha256(b'LEE/keys' + nsk + bytes([0x07]) + bytes(23)).digest()
data_hash = hashlib.sha256(b'').digest()
PREFIX = b'/LEE/v0.3/Commitment/' + bytes(11)
balance = ($BALANCE).to_bytes(16, 'little')
nonce   = (0).to_bytes(16, 'little')
po      = bytes.fromhex('$PROGRAM_OWNER')
print(hashlib.sha256(PREFIX + npk + po + balance + nonce + data_hash).digest().hex())
")
LEAF=$(python3 -c "
import hashlib
print(hashlib.sha256(bytes.fromhex('$COMMITMENT')).digest().hex())
")
MERKLE_ROOT=$(python3 -c "
import hashlib
leaf = bytes.fromhex('$LEAF')
print(hashlib.sha256(leaf + leaf).digest().hex())
")

PROVE_OUT=$(./target/release/balance-attest prove \
  --nsk "$NSK" \
  --program-owner "$PROGRAM_OWNER" \
  --balance "$BALANCE" \
  --threshold "$THRESHOLD" \
  --context-id "$CONTEXT_ID" \
  --presenter-sk "$PRESENTER_SK" \
  --merkle-root "$MERKLE_ROOT" \
  --leaf-index 0 \
  --merkle-path "$LEAF" \
  --out /tmp/attest-receipt.bin)
PRESENTER_PK=$(echo "$PROVE_OUT" | grep '^presenter_pk:' | awk '{print $2}')
SIG=$(echo "$PROVE_OUT" | grep '^sig:' | awk '{print $2}')
echo "  presenter_pk: $PRESENTER_PK"

echo ""
echo "[4/7] Starting gatekeeper for group 'vip-room' on Node B..."
./target/release/attest-msg gatekeeper \
  --node http://127.0.0.1:8646 \
  --context-id "$CONTEXT_ID" \
  --threshold "$THRESHOLD" \
  --group vip-room \
  --state "$GK_STATE" \
  --max-messages 2 &
GK_PID=$!
sleep 2

echo ""
echo "[5/7] Presenting attestation via Node A (crosses the Waku relay network)..."
./target/release/attest-msg send \
  --node http://127.0.0.1:8645 \
  --receipt /tmp/attest-receipt.bin \
  --presenter-pk "$PRESENTER_PK" \
  --sig "$SIG" \
  --request-id "req-admission-1"

echo ""
echo "[6/7] Replaying the same attestation (must be DENIED: nullifier spent)..."
if ./target/release/attest-msg send \
  --node http://127.0.0.1:8645 \
  --receipt /tmp/attest-receipt.bin \
  --presenter-pk "$PRESENTER_PK" \
  --sig "$SIG" \
  --request-id "req-admission-2"; then
  echo "ERROR: replay was admitted -- nullifier tracking failed"
  kill "$GK_PID" 2>/dev/null || true
  exit 1
else
  echo "  Replay correctly denied."
fi

wait "$GK_PID" 2>/dev/null || true

echo ""
echo "[7/7] Gatekeeper state (persisted members and spent nullifiers):"
cat "$GK_STATE"

echo ""
echo "=== Off-chain demo complete ==="
echo ""
echo "What happened:"
echo "  - The proof was transmitted over the Logos Messaging (Waku) relay network"
echo "  - The gatekeeper verified it locally with verifier-lib -- no on-chain transaction"
echo "  - Admission granted to 'vip-room'; the replay was rejected via nullifier tracking"
echo "  - The gatekeeper learned only: threshold met, context, presenter_pk, nullifier"
echo "  - It never learned the balance, the NSK, or the account identity"
