// Pre-built attestation guest binary (R0BF packaged, risc0-zkvm 3.0.5).
// To regenerate:
//   cd circuit/guest && cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf
//   python3 ../../scripts/package_r0bf.py <reference.bin> \
//     ../../target/riscv32im-risc0-zkvm-elf/release/balance-attestation-guest \
//     balance-attestation-guest.bin
//   spel program-id balance-attestation-guest.bin   # update the ID below
// NOTE: this is the attestation circuit guest, NOT the on-chain SPEL program
// (programs/balance_attestation/balance_attestation.bin). The two are
// different binaries with different image IDs; the on-chain program verifies
// attestation receipts against this guest's ID via env::verify.
pub const BALANCE_ATTESTATION_GUEST_ELF: &[u8] =
    include_bytes!("../../guest/balance-attestation-guest.bin");
pub const BALANCE_ATTESTATION_GUEST_ID: [u32; 8] = [
    0xa467ec7f, 0xecb63d04, 0xdec5c62b, 0xfee3e100,
    0x278f0e6f, 0x3e1a8fc2, 0x200c856c, 0xd931e6b0,
];
