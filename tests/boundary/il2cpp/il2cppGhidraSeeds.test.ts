import { expect, it } from "vitest";
import { parseGhidraSeeds } from "../../../src/ghidra/GhidraAnalysisSeeds.js";
import {
  ghidraDefaultBase,
  il2cppGhidraSeeds,
} from "../../../src/domain/il2cpp/il2cppGhidraSeeds.js";
import {
  IL2CPP_METADATA_MAGIC,
  IL2CPP_METADATA_SECTION_NAMES,
  type Il2cppMetadata,
} from "../../../src/domain/il2cpp/il2cppMetadata.js";

const type = (
  name: string,
  namespace: string,
  method_start: number,
  method_count: number,
  declaring_type: number,
) => ({
  name,
  namespace,
  method_start,
  method_count,
  nested_type_start: -1,
  nested_type_count: 0,
  declaring_type,
});

const address = (rva: string): Il2cppMetadata["method_addresses"][number] =>
  rva === "no-body" || rva === "unknown"
    ? { state: rva, address: null, rva: null }
    : { state: "code", address: rva, rva };

const report: Il2cppMetadata = {
  artifact: {
    path: "/artifacts/global-metadata.dat",
    sha256: "a".repeat(64),
    bytes: 1024,
  },
  magic: IL2CPP_METADATA_MAGIC,
  metadata_version: 31,
  index_widths: {
    type_definition: 4,
    generic_container: 4,
    parameter: 4,
    type: 4,
    type_width_source: "fixed-width-version",
  },
  sections: IL2CPP_METADATA_SECTION_NAMES.map((name) => ({
    name,
    offset: 256,
    size: 0,
    count: 0,
  })),
  images: [{ name: "Assembly-CSharp.dll", type_start: 0, type_count: 3 }],
  types: [
    type("Player", "Game", 0, 2, -1),
    type("Slot", "", 2, 2, 0),
    type("<>c", "", 4, 1, 1),
  ],
  methods: [
    { name: "Update", declaring_type: 0 },
    { name: "Abstract", declaring_type: 0 },
    { name: "Add", declaring_type: 1 },
    { name: "Folded", declaring_type: 1 },
    { name: "<Run>b__0 x", declaring_type: 2 },
  ],
  fields: [],
  properties: [],
  events: [],
  parameters: [],
  string_literals: [],
  binary: {
    artifact: {
      path: "/artifacts/libil2cpp.so",
      sha256: "b".repeat(64),
      bytes: 4096,
    },
    format: "elf",
    architecture: "arm64",
    image_base: "0x0",
    code_gen_modules_field: "0x800",
    code_gen_modules_array: "0x900",
    code_gen_modules: [{ image: 0, address: "0x700", method_pointer_count: 5 }],
    types_field: "0x900",
    types_count: 0,
  },
  method_addresses: [
    address("0x100"),
    address("no-body"),
    address("0x110"),
    address("0x100"),
    address("0x120"),
  ],
  return_types: [],
  field_types: [],
  parameter_types: [],
  limitations: [],
};

it("names linked methods Type$$Method with nested types and shifts by the base", () => {
  const seeds = il2cppGhidraSeeds(report, 0x100000n);
  expect(seeds).toEqual({
    text:
      "0x100100\tfunction\tGame.Player$$Update\n" +
      "0x100110\tfunction\tGame.Player.Slot$$Add\n" +
      "0x100120\tfunction\tGame.Player.Slot.<>c$$<Run>b__0_x\n" +
      "# folded 0x100100 Game.Player$$Update also Game.Player.Slot$$Folded\n",
    functions: 3,
    folded: 1,
    folded_groups: [
      {
        address: "0x100100",
        kept: "Game.Player$$Update",
        also: ["Game.Player.Slot$$Folded"],
      },
    ],
    without_address: 1,
  });
  const parsed = parseGhidraSeeds(seeds.text);
  expect(parsed.ok && parsed.value.length).toBe(3);
});

it("seeds neither a method without a body nor one no module claims", () => {
  const unknown = {
    ...report,
    method_addresses: report.method_addresses.map((row, index) =>
      index === 1 ? address("unknown") : row,
    ),
  };
  expect(il2cppGhidraSeeds(unknown, 0x100000n)).toEqual(
    il2cppGhidraSeeds(report, 0x100000n),
  );
});

it("refuses an unlinked report", () => {
  expect(() => il2cppGhidraSeeds({ ...report, binary: null }, 0n)).toThrow(
    "binary_path",
  );
});

it("defaults to Ghidra's load base: 0x100000 for an ELF linked at 0, else the link base", () => {
  const binary = report.binary!;
  expect(ghidraDefaultBase(binary)).toBe(0x100000n);
  expect(ghidraDefaultBase({ ...binary, image_base: "0x200000" })).toBe(
    0x200000n,
  );
  expect(ghidraDefaultBase({ ...binary, format: "macho" })).toBe(0n);
  expect(
    ghidraDefaultBase({ ...binary, format: "pe", image_base: "0x180000000" }),
  ).toBe(0x180000000n);
});
