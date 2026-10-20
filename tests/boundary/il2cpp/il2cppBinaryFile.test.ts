import { expect, it } from "vitest";
import {
  Il2cppBinaryFormatFailure,
  linkIl2cppBinary,
} from "../../../src/il2cpp/Il2cppBinaryFile.js";
import { readIl2cppMetadataForLinking } from "../../../src/il2cpp/Il2cppMetadataFile.js";
import {
  createElfFixture,
  createIl2cppBinaryFixture,
  createUniversalFixture,
  FIXTURE_BINARY_BASE,
  FIXTURE_METHOD_ADDRESSES,
  FIXTURE_RETURN_TYPE_NAME,
  type Il2cppBinaryFixtureOptions,
} from "../../fixtures/il2cpp/binary.js";
import { createIl2cppMetadataFixture } from "../../fixtures/il2cpp/metadata.js";

const { metadata, link: facts } = readIl2cppMetadataForLinking(
  createIl2cppMetadataFixture().bytes,
);
const link = (bytes: Buffer, architecture?: string) =>
  linkIl2cppBinary(bytes, metadata, facts, architecture);
const failure = (bytes: Buffer, architecture?: string) => {
  try {
    link(bytes, architecture);
  } catch (cause) {
    if (cause instanceof Il2cppBinaryFormatFailure)
      return { reason: cause.reason, kind: cause.kind };
    throw cause;
  }
  throw new Error("expected a link failure");
};

it("links methods to code through module tokens, not metadata order", () => {
  const linked = link(createIl2cppBinaryFixture());
  expect(linked).toMatchObject({
    format: "macho",
    architecture: "arm64",
    image_base: FIXTURE_BINARY_BASE,
    code_gen_modules_field: FIXTURE_BINARY_BASE + 0x600n,
    code_gen_modules_array: FIXTURE_BINARY_BASE + 0x500n,
    code_gen_modules: [
      {
        image: 0,
        address: FIXTURE_BINARY_BASE + 0x400n,
        method_pointer_count: 3,
      },
      {
        image: 1,
        address: FIXTURE_BINARY_BASE + 0x440n,
        method_pointer_count: 2,
      },
    ],
  });
  expect(linked.method_addresses).toEqual(FIXTURE_METHOD_ADDRESSES);
  expect(linked).toMatchObject({
    types_field: FIXTURE_BINARY_BASE + 0x830n,
    types_count: 4,
  });
  expect(linked.return_types).toEqual(
    Array.from({ length: 5 }, () => ({
      type: 0,
      name: FIXTURE_RETURN_TYPE_NAME,
    })),
  );
});

it("requires an explicit slice of a universal Mach-O and reads only that slice", () => {
  const thin = createIl2cppBinaryFixture();
  const universal = createUniversalFixture([
    { cpu: 0x01000007, bytes: Buffer.alloc(0x100) },
    { cpu: 0x0100000c, bytes: thin },
  ]);
  expect(failure(universal)).toEqual({
    reason: "slice-selection-required",
    kind: "unsupported",
  });
  expect(link(universal, "arm64").method_addresses).toEqual(
    FIXTURE_METHOD_ADDRESSES,
  );
  expect(failure(universal, "ppc64").reason).toBe("slice-not-found");
  expect(failure(thin, "arm64").reason).toBe("slice-not-found");
});

it.each<
  [string, Il2cppBinaryFixtureOptions, string, "unsupported" | "malformed"]
>([
  [
    "a method count mismatch",
    { firstModuleCount: 4 },
    "code-gen-modules-not-found",
    "malformed",
  ],
  [
    "two matching module records",
    { duplicateModule: true },
    "ambiguous-code-gen-module",
    "malformed",
  ],
  [
    "no CodeRegistration module table",
    { codeRegistration: false },
    "code-registration-not-found",
    "malformed",
  ],
  [
    "no MetadataRegistration type table",
    { metadataRegistration: false },
    "metadata-registration-not-found",
    "malformed",
  ],
  [
    "chained fixups",
    { chainedFixups: true },
    "unsupported-pointer-encoding",
    "unsupported",
  ],
])("rejects %s without partial addresses", (_, options, reason, kind) => {
  expect(failure(createIl2cppBinaryFixture(options))).toEqual({ reason, kind });
});

it("reports type indices without names for metadata version 27", () => {
  const linked = linkIl2cppBinary(
    createIl2cppBinaryFixture(),
    { ...metadata, metadata_version: 27 },
    facts,
  );
  const rows = [
    ...linked.return_types,
    ...linked.field_types,
    ...linked.parameter_types,
  ];
  expect(rows.length).toBeGreaterThan(0);
  expect(rows.every((row) => row.name === null)).toBe(true);
  expect(link(createIl2cppBinaryFixture()).return_types[0]?.name).toBe(
    FIXTURE_RETURN_TYPE_NAME,
  );
});

it("does not search for an empty image name", () => {
  const unnamed = {
    ...metadata,
    images: metadata.images.map((image, index) =>
      index === 0 ? { ...image, name: "" } : image,
    ),
  };
  expect(() =>
    linkIl2cppBinary(createIl2cppBinaryFixture(), unnamed, facts),
  ).toThrow("code-gen-modules-not-found");
});

it("refuses an image name repeated past the search bound", () => {
  const fixture = createIl2cppBinaryFixture();
  const flooded = Buffer.concat([
    fixture,
    Buffer.from("\0mscorlib.dll".repeat(4200) + "\0", "utf8"),
  ]);
  // The Mach-O segment covers the original size; widen it to the new tail.
  flooded.writeBigUInt64LE(BigInt(flooded.length), 64);
  flooded.writeBigUInt64LE(BigInt(flooded.length), 80);
  expect(failure(flooded)).toEqual({
    reason: "ambiguous-code-gen-module",
    kind: "malformed",
  });
});

it.each([
  [{ duplicateRela: true }],
  [{ relaEntry: 16n }],
  [{ relaSize: 25n }],
] as const)("rejects malformed ELF relocation tables (%o)", (options) => {
  expect(
    failure(createElfFixture(createIl2cppBinaryFixture(), options)),
  ).toEqual({ reason: "malformed-container", kind: "malformed" });
});

it("does not apply symbol relocations as RELATIVE ones", () => {
  // With every slot left zero, no module table can be found.
  expect(() =>
    link(
      createElfFixture(createIl2cppBinaryFixture(), {
        symbolRelocations: true,
      }),
    ),
  ).toThrow(Il2cppBinaryFormatFailure);
});

it("reads a method pointer array in zero-fill as methods without bodies", () => {
  // An iOS-only assembly in an Android build keeps its array in .bss.
  const linked = link(
    createElfFixture(createIl2cppBinaryFixture(), { zeroFilledTable: true }),
  );
  expect(linked.method_addresses).toEqual([
    ...FIXTURE_METHOD_ADDRESSES.slice(0, 3),
    "no-body",
    "no-body",
  ]);
});

it("reports a method no image range claims as unknown, not as without a body", () => {
  // No type's method range holds this row, so no module slot describes it.
  const orphan = {
    ...metadata,
    methods: [...metadata.methods, { name: "Lost", declaring_type: -1 }],
  };
  const tokens = Uint32Array.from([...facts.methodTokens, 0x06000001]);
  const linked = linkIl2cppBinary(createIl2cppBinaryFixture(), orphan, {
    ...facts,
    methodTokens: tokens,
  });
  expect(linked.method_addresses).toEqual([
    ...FIXTURE_METHOD_ADDRESSES,
    "unknown",
  ]);
});

it("finds an x86-64 module array through the instruction that loads it", () => {
  const inlined = createElfFixture(
    createIl2cppBinaryFixture({ codeRegistration: false, codeReference: true }),
    { machine: 62 },
  );
  const linked = link(inlined);
  expect(linked.code_gen_modules_field).toBeNull();
  expect(linked.code_gen_modules_array).toBe(FIXTURE_BINARY_BASE + 0x500n);
  expect(linked.method_addresses).toEqual(
    link(createElfFixture(createIl2cppBinaryFixture(), { machine: 62 }))
      .method_addresses,
  );
});

it.each([
  ["no instruction loads the array", { machine: 62 }, { codeReference: false }],
  ["the image is not x86-64", { machine: 183 }, { codeReference: true }],
] as const)("keeps code-registration-not-found when %s", (_, elf, binary) => {
  expect(
    failure(
      createElfFixture(
        createIl2cppBinaryFixture({ codeRegistration: false, ...binary }),
        elf,
      ),
    ).reason,
  ).toBe("code-registration-not-found");
});

it("refuses to choose among too many candidate module arrays", () => {
  const base = createIl2cppBinaryFixture({
    codeRegistration: false,
    codeReference: true,
  });
  // Copy the two-slot module array (16 bytes at 0x500) 80 times after the image.
  const copies = Buffer.concat(
    Array.from({ length: 80 }, () => base.subarray(0x500, 0x510)),
  );
  const crafted = Buffer.concat([base, copies]);
  crafted.writeBigUInt64LE(BigInt(crafted.length), 64);
  crafted.writeBigUInt64LE(BigInt(crafted.length), 80);
  // Mach-O is arm64 in the fixture; relabel it x86-64 so the fallback runs.
  crafted.writeUInt32LE(0x01000007, 4);
  crafted.writeUInt32LE(3, 8);
  expect(failure(crafted).reason).toBe("code-registration-not-found");
});

it("finds image names padded with 0xFF as MSVC writes them", () => {
  expect(link(createIl2cppBinaryFixture({ namePadding: 0xff }))).toEqual(
    link(createIl2cppBinaryFixture()),
  );
});

it("does not take an image name from the tail of a longer name", () => {
  expect(failure(createIl2cppBinaryFixture({ namePrefix: "Mono." }))).toEqual({
    reason: "code-gen-modules-not-found",
    kind: "malformed",
  });
});

it("links an ELF shared object after applying its RELATIVE relocations", () => {
  const elf = createElfFixture(createIl2cppBinaryFixture());
  const fromMacho = link(createIl2cppBinaryFixture());
  expect(link(elf)).toEqual({ ...fromMacho, format: "elf" });
});

it.each([
  [{ dynamic: false }, "unsupported-container"],
  [{ machine: 243 }, "unsupported-container"],
  [{ androidPacked: true }, "unsupported-pointer-encoding"],
] as const)(
  "refuses ELF relocations it cannot apply (%o)",
  (options, reason) => {
    expect(
      failure(createElfFixture(createIl2cppBinaryFixture(), options)),
    ).toEqual({
      reason,
      kind: "unsupported",
    });
  },
);
