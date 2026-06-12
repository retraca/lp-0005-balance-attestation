#!/usr/bin/env python3
"""
package_r0bf.py: package a bare risc0 guest ELF into the deployable R0BF binary
LEZ's ProgramBinary::decode expects, WITHOUT Docker.

Why this exists: `cargo risczero build` runs the guest build inside a Docker
container whose build context is only the guest crate directory. This guest crate
uses a path dependency (`mint-authority = { path = "../.." }`) that lives outside
that context, so `cargo +risc0 fetch` inside the container fails with
`failed to read /Cargo.toml`. (Separately, on arm64 the amd64 risc0 builder image
runs under qemu.) The bare ELF, however, builds fine on the host with
`cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf`.

The R0BF container format (observed in working LEZ sample `.bin`s) is:

    offset 0   : b"R0BF"                 magic
    offset 4   : u32 version (=1)
    offset 8   : u32 (=16)               header field offset
    offset 12  : u32 (=1)
    offset 16  : u32 (=8)
    offset 20  : <padding/string-table> e.g. b"\x00\x00\x05" + b"1.0.0"
    offset 28  : u32 user_elf_len
    offset 32  : user ELF (len = user_elf_len)
    offset 32+user_elf_len : kernel ELF (risc0-zkos v1compat), to EOF

So packaging = take the header (bytes 0..28) and the trailing kernel ELF from a
known-good `.bin`, splice in our own user ELF, and fix the u32 length at offset 28.

Usage:
    package_r0bf.py <reference.bin> <user_guest.elf> <out.bin>

The script self-tests by reconstructing <reference.bin> byte-for-byte before
emitting <out.bin>. Validate the result with `spel program-id <out.bin>`.
"""
import sys
import struct

USER_OFF = 32
LEN_FIELD_OFF = 28


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    ref = open(sys.argv[1], "rb").read()
    user = open(sys.argv[2], "rb").read()
    out_path = sys.argv[3]

    assert ref[:4] == b"R0BF", "reference is not an R0BF binary"
    ref_user_len = struct.unpack_from("<I", ref, LEN_FIELD_OFF)[0]
    kernel_off = USER_OFF + ref_user_len
    header = ref[:LEN_FIELD_OFF]
    kernel = ref[kernel_off:]

    assert ref[USER_OFF:USER_OFF + 4] == b"\x7fELF", "reference user region not ELF"
    assert kernel[:4] == b"\x7fELF", "reference kernel region not ELF"
    assert user[:4] == b"\x7fELF", "user file is not an ELF"

    # self-test: rebuild the reference exactly
    recon = header + struct.pack("<I", ref_user_len) + ref[USER_OFF:kernel_off] + kernel
    assert recon == ref, "self-test failed: reference not reproduced byte-for-byte"

    newbin = header + struct.pack("<I", len(user)) + user + kernel
    open(out_path, "wb").write(newbin)
    print(f"wrote {out_path} ({len(newbin)} bytes); "
          f"user_elf={len(user)} kernel={len(kernel)}")


if __name__ == "__main__":
    main()
