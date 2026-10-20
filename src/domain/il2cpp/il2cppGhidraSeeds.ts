import type { Il2cppMetadata } from "./il2cppMetadata.js";

/** A linked metadata report reduced to Ghidra function seeds. */
export interface Il2cppGhidraSeeds {
  /** `address<TAB>function<TAB>name` lines in the REA_GHIDRA_SEED_FILE format. */
  readonly text: string;
  readonly functions: number;
  /** Methods whose code address another method already seeded (identical code folding). */
  readonly folded: number;
  /** Each folded address with the name its function seed kept and the names it shares. */
  readonly folded_groups: readonly {
    readonly address: string;
    readonly kept: string;
    readonly also: readonly string[];
  }[];
  /** Methods without native code: abstract, interface, or generic definitions. */
  readonly without_address: number;
}

/**
 * Where Ghidra's default loaders place the binary: an ELF linked at 0 goes to
 * 0x100000, while Mach-O and PE images keep their link base.
 */
export const ghidraDefaultBase = (
  binary: NonNullable<Il2cppMetadata["binary"]>,
): bigint => {
  const linked = BigInt(binary.image_base);
  return binary.format === "elf" && linked === 0n ? 0x100000n : linked;
};

/** `Namespace.Outer.Inner` for a type, following declaring_type to the outermost type. */
const typeName = (report: Il2cppMetadata, index: number): string => {
  const parts: string[] = [];
  let namespace = "";
  for (let at = index; at !== -1;) {
    const type = report.types[at]!;
    parts.unshift(type.name);
    namespace = type.namespace;
    at = type.declaring_type;
  }
  return namespace === "" ? parts.join(".") : `${namespace}.${parts.join(".")}`;
};

/**
 * Name every linked method `Type$$Method`, the Il2CppDumper convention, at
 * `base + rva`. Whitespace becomes `_` because seed names cannot contain it.
 * The first method at an address names its function, since a seed file holds
 * one function seed per address. The other methods at that address are listed
 * in `#` comment lines after the seeds, so a reader of the file or the
 * decompilation can see that the kept name is one of several.
 */
export const il2cppGhidraSeeds = (
  report: Il2cppMetadata,
  base: bigint,
): Il2cppGhidraSeeds => {
  if (report.binary === null)
    throw new Error("Ghidra seeds need a report linked with binary_path");
  const seeded = new Map<bigint, { kept: string; also: string[] }>();
  const lines: string[] = [];
  let folded = 0;
  let withoutAddress = 0;
  report.methods.forEach((method, index) => {
    const rva = report.method_addresses[index]?.rva ?? null;
    if (rva === null) {
      withoutAddress++;
      return;
    }
    const address = base + BigInt(rva);
    const name =
      `${typeName(report, method.declaring_type)}$$${method.name}`.replace(
        /\s/gu,
        "_",
      );
    const group = seeded.get(address);
    if (group !== undefined) {
      folded++;
      group.also.push(name);
      return;
    }
    seeded.set(address, { kept: name, also: [] });
    lines.push(`0x${address.toString(16)}\tfunction\t${name}\n`);
  });
  const foldedGroups = [...seeded]
    .filter(([, group]) => group.also.length > 0)
    .map(([address, group]) => ({
      address: `0x${address.toString(16)}`,
      kept: group.kept,
      also: group.also,
    }));
  return {
    text:
      lines.join("") +
      foldedGroups
        .map(
          (group) =>
            `# folded ${group.address} ${group.kept} also ${group.also.join(" ")}\n`,
        )
        .join(""),
    functions: lines.length,
    folded,
    folded_groups: foldedGroups,
    without_address: withoutAddress,
  };
};
