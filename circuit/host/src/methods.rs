// Pre-built guest binary (R0BF packaged, risc0-zkvm 3.0.5).
// To regenerate: cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf
// in circuit/guest/, then package with the R0BF tool.
pub const BALANCE_ATTESTATION_GUEST_ELF: &[u8] =
    include_bytes!("../../../programs/balance_attestation/balance_attestation.bin");
pub const BALANCE_ATTESTATION_GUEST_ID: [u32; 8] = [
    0x113f0d87, 0x90f2d7c6, 0xd0c97222, 0xfee00900,
    0x3d397fbe, 0x0a1cf395, 0xdab09bce, 0x19673d11,
];
