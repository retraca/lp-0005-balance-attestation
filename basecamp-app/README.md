# LP-0005 Basecamp Mini-App

A Logos Basecamp mini-app for the private balance attestation gating program.

## What it does

Lets you compute the commitment leaf hash and nullifier locally in-browser before
sending inputs to the `balance-attest` CLI for proof generation. Your NSK and
actual balance never leave your device.

## Usage

Open `index.html` in the Logos Basecamp environment, or load it locally:

```
open basecamp-app/index.html
```

Steps:
1. Enter your NSK and account details to compute the commitment hash offline.
2. Verify the commitment is in the public Merkle tree.
3. Use the displayed inputs with `balance-attest prove` to generate the ZK proof.
4. Submit the proof to the on-chain gating program via the LEZ wallet.
