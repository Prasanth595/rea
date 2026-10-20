import { Il2cppBinaryFormatFailure } from "./Il2cppBinaryFile.js";

const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const DT_NULL = 0n;
const DT_RELA = 7n;
const DT_RELASZ = 8n;
const DT_RELAENT = 9n;
// Android's packed relocation formats (APS2) are a separate encoding.
const DT_ANDROID_REL = 0x6000000fn;
const DT_ANDROID_RELA = 0x60000011n;

/** R_<machine>_RELATIVE: the slot holds load base plus addend. */
const RELATIVE_TYPES = new Map([
  [183, 1027], // AArch64
  [62, 8], // x86-64
]);

interface LoadSegment {
  readonly address: bigint;
  readonly offset: number;
  readonly fileSize: number;
}

const malformed = (message: string) =>
  new Il2cppBinaryFormatFailure("malformed-container", message);

/**
 * Return a copy of a 64-bit little-endian ELF shared object with every
 * RELATIVE relocation written into its pointer slot, so slots read as the
 * image would at its link-time addresses. Symbol relocations are left as
 * stored: IL2CPP registration tables point only into the image itself. RELR
 * slots already hold their link-time value, so DT_RELR needs no rewriting,
 * and RELATIVE slots outside file data (.bss) are never searched.
 */
export const applyElfRelativeRelocations = (image: Buffer): Buffer => {
  if (image.length < 64) throw malformed("ELF header is truncated");
  const machine = image.readUInt16LE(18);
  const relative = RELATIVE_TYPES.get(machine);
  if (relative === undefined)
    throw new Il2cppBinaryFormatFailure(
      "unsupported-container",
      `ELF machine ${machine} relocations are not decoded; AArch64 and x86-64 are`,
    );
  const phoff = Number(image.readBigUInt64LE(32));
  const phentsize = image.readUInt16LE(54);
  const phnum = image.readUInt16LE(56);
  if (phentsize < 56 || phoff + phnum * phentsize > image.length)
    throw malformed("ELF program headers extend beyond the file");

  const loads: LoadSegment[] = [];
  let dynamic: { offset: number; size: number } | undefined;
  for (let index = 0; index < phnum; index++) {
    const at = phoff + index * phentsize;
    const type = image.readUInt32LE(at);
    const offset = Number(image.readBigUInt64LE(at + 8));
    const address = image.readBigUInt64LE(at + 16);
    const fileSize = Number(image.readBigUInt64LE(at + 32));
    if (type === PT_LOAD) loads.push({ address, offset, fileSize });
    if (type === PT_DYNAMIC) {
      if (dynamic !== undefined)
        throw malformed("multiple PT_DYNAMIC segments");
      dynamic = { offset, size: fileSize };
    }
  }
  if (dynamic === undefined)
    throw new Il2cppBinaryFormatFailure(
      "unsupported-container",
      "ELF image has no PT_DYNAMIC segment, so it is not a shared object",
    );
  if (dynamic.offset + dynamic.size > image.length)
    throw malformed("PT_DYNAMIC extends beyond the file");

  const fileOffset = (address: bigint, size: number): number | null => {
    for (const load of loads) {
      if (address < load.address) continue;
      const delta = address - load.address;
      if (delta + BigInt(size) <= BigInt(load.fileSize))
        return load.offset + Number(delta);
    }
    return null;
  };

  const tags = new Map<bigint, bigint>();
  for (
    let at = dynamic.offset;
    at + 16 <= dynamic.offset + dynamic.size;
    at += 16
  ) {
    const tag = image.readBigInt64LE(at);
    if (tag === DT_NULL) break;
    if (
      tags.has(tag) &&
      (tag === DT_RELA || tag === DT_RELASZ || tag === DT_RELAENT)
    )
      throw malformed(`duplicate dynamic tag ${tag}`);
    tags.set(tag, image.readBigUInt64LE(at + 8));
  }
  if (tags.has(DT_ANDROID_RELA) || tags.has(DT_ANDROID_REL))
    throw new Il2cppBinaryFormatFailure(
      "unsupported-pointer-encoding",
      "Android packed relocations (APS2) are not decoded",
    );

  const bytes = Buffer.from(image);
  const write = (address: bigint, value: bigint) => {
    const target = fileOffset(address, 8);
    if (target !== null) bytes.writeBigUInt64LE(value, target);
  };

  const relaAddress = tags.get(DT_RELA);
  if (relaAddress !== undefined) {
    const size = Number(tags.get(DT_RELASZ) ?? -1n);
    const entry = Number(tags.get(DT_RELAENT) ?? 24n);
    if (size < 0 || entry !== 24 || size % entry !== 0)
      throw malformed("invalid DT_RELASZ or DT_RELAENT");
    const start = fileOffset(relaAddress, size);
    if (start === null) throw malformed("DT_RELA table is not file-backed");
    for (let at = start; at < start + size; at += entry) {
      const info = image.readBigUInt64LE(at + 8);
      if (Number(info & 0xffffffffn) !== relative || info >> 32n !== 0n)
        continue;
      write(
        image.readBigUInt64LE(at),
        image.readBigInt64LE(at + 16) & 0xffffffffffffffffn,
      );
    }
  }

  return bytes;
};
