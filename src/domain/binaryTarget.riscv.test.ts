import { describe, expect, it } from "vitest";
import { parseExecutableHeader } from "./binaryTarget.js";

const header = (
  little: boolean,
  bits: 32 | 64 = 32,
  flags = 0x5,
  type = 2,
  machine = 243,
): Buffer => {
  const bytes = Buffer.alloc(bits === 32 ? 52 : 64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, bits === 32 ? 1 : 2, little ? 1 : 2, 1]);
  if (little) {
    bytes.writeUInt16LE(type, 16);
    bytes.writeUInt16LE(machine, 18);
    bytes.writeUInt32LE(1, 20);
    bytes.writeUInt16LE(bits === 32 ? 52 : 64, bits === 32 ? 40 : 52);
    bytes.writeUInt32LE(flags, bits === 32 ? 36 : 48);
  } else {
    bytes.writeUInt16BE(type, 16);
    bytes.writeUInt16BE(machine, 18);
    bytes.writeUInt32BE(1, 20);
    bytes.writeUInt16BE(bits === 32 ? 52 : 64, bits === 32 ? 40 : 52);
    bytes.writeUInt32BE(flags, bits === 32 ? 36 : 48);
  }
  return bytes;
};

describe("RISC-V ELF header boundaries", () => {
  it.each([
    [true, 32],
    [false, 32],
    [true, 64],
    [false, 64],
  ] as const)(
    "retains class, endian, e_type and e_flags (little=%s, class=%s)",
    (little, bits) => {
      const parsed = parseExecutableHeader(header(little, bits), "x64");
      if (!parsed.ok) throw new Error(parsed.error);
      expect(parsed.value).toEqual({
        format: "elf",
        architecture: "riscv",
        availableArchitectures: ["riscv"],
        riscv: {
          elfClass: bits,
          byteOrder: little ? "little" : "big",
          type: 2,
          flags: 0x5,
        },
      });
    },
  );

  it("reads ELF64 flags at their own offset", () => {
    const bytes = header(true, 64);
    bytes.writeUInt32LE(0xdeadbeef, 36);
    bytes.writeUInt32LE(0x00000014, 48);
    const parsed = parseExecutableHeader(bytes, "x64");
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.value).toMatchObject({
      architecture: "riscv",
      riscv: { elfClass: 64, flags: 0x14 },
    });
  });

  it("does not attach ELF metadata to a family that declares none", () => {
    const parsed = parseExecutableHeader(header(true, 64, 0x5, 2, 62), "x64");
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.value).toEqual({
      format: "elf",
      architecture: "x86_64",
      availableArchitectures: ["x86_64"],
    });
  });

  it("rejects a truncated header before reading flags", () => {
    const parsed = parseExecutableHeader(header(true).subarray(0, 39), "x64");
    expect(parsed).toEqual({
      ok: false,
      error:
        "truncated ELF header: an ELF32 header needs 52 bytes; the file has 39",
    });
  });

  it("does not turn invalid byte order into little-endian RISC-V", () => {
    const bytes = header(true);
    bytes[5] = 0;
    expect(parseExecutableHeader(bytes, "x64")).toEqual({
      ok: false,
      error: "unsupported ELF endianness",
    });
  });

  it.each([
    [true, 32],
    [true, 64],
  ] as const)(
    "detects PT_INTERP in program headers for PIE (little=%s, class=%s)",
    (little, bits) => {
      const is64 = bits === 64;
      const hdrSize = is64 ? 64 : 52;
      const phentsize = is64 ? 56 : 32;
      const bytes = Buffer.alloc(hdrSize + phentsize);
      bytes.set([0x7f, 0x45, 0x4c, 0x46, is64 ? 2 : 1, little ? 1 : 2, 1]);
      if (little) {
        bytes.writeUInt16LE(3, 16); // ET_DYN
        bytes.writeUInt16LE(243, 18); // EM_RISCV
        bytes.writeUInt32LE(1, 20);
        bytes.writeUInt16LE(hdrSize, is64 ? 52 : 40);
        bytes.writeUInt32LE(0x5, is64 ? 48 : 36); // e_flags
        if (is64) {
          bytes.writeBigUInt64LE(BigInt(hdrSize), 32); // e_phoff
          bytes.writeUInt16LE(phentsize, 54); // e_phentsize
          bytes.writeUInt16LE(1, 56); // e_phnum
        } else {
          bytes.writeUInt32LE(hdrSize, 28); // e_phoff
          bytes.writeUInt16LE(phentsize, 42); // e_phentsize
          bytes.writeUInt16LE(1, 44); // e_phnum
        }
        bytes.writeUInt32LE(3, hdrSize); // PT_INTERP
      }
      const parsed = parseExecutableHeader(bytes, "x64");
      if (!parsed.ok) throw new Error(parsed.error);
      expect(parsed.value).toEqual({
        format: "elf",
        architecture: "riscv",
        availableArchitectures: ["riscv"],
        riscv: {
          elfClass: bits,
          byteOrder: "little",
          type: 3,
          flags: 0x5,
          hasInterpreter: true,
        },
      });
    },
  );

  it("does not set hasInterpreter when program headers omit PT_INTERP", () => {
    const bytes = header(true, 64, 0x5, 3);
    const parsed = parseExecutableHeader(bytes, "x64");
    if (!parsed.ok) throw new Error(parsed.error);
    expect(parsed.value).toEqual({
      format: "elf",
      architecture: "riscv",
      availableArchitectures: ["riscv"],
      riscv: {
        elfClass: 64,
        byteOrder: "little",
        type: 3,
        flags: 0x5,
      },
    });
  });

  it("keeps an unknown e_machine outside the recognized family set", () => {
    expect(parseExecutableHeader(header(true, 32, 0x5, 2, 244), "x64")).toEqual(
      {
        ok: false,
        error: "unsupported ELF architecture",
      },
    );
  });
});
