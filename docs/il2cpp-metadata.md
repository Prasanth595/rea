# IL2CPP metadata

`inspect_il2cpp_metadata` / `inspect-il2cpp-metadata` decodes one selected local
Unity IL2CPP `global-metadata.dat` file and returns its assembly images, type
definitions and method definitions by name, namespace, index range and count,
with the header sections and serialized index widths. It reads the file without
running it and requires no Unity installation, IL2CPP binary, active target,
Hopper, Ghidra or IDA.

Metadata versions 24, 27, 29, 31 and 39 are supported. For example, Unity 2019.4.41f2
wrote version 24, 2020.3.49f1 version 27, 2022.3.30f1
wrote version 29, 2022.3.62f3 wrote 31 and 6000.4.2f1 wrote 39; other Unity
releases that write these numbers have not been checked. Other versions are
rejected as unsupported. The path must name a regular file; directories and
symbolic links are rejected.

With `binary_path`, the tool also reads the matching native binary and links
each method to its code address. See [Native method addresses](#native-method-addresses).

## MCP

MCP defaults to a compact summary and retains the complete decoded Evidence in
the session. MCP requires an absolute filesystem path:

```json
{
  "name": "inspect_il2cpp_metadata",
  "arguments": {
    "path": "/artifacts/Data/Managed/Metadata/global-metadata.dat"
  }
}
```

The summary retains the complete decoded Evidence in the session and returns a
linked `inspect_analysis_view` overview: artifact identity, metadata version,
index widths and `counts` (`sections`, `images`, `types`, `methods` and
`nested_types`) without rows. Use `normalized_result.parent_evidence_id` to page
the original rows without reopening or decoding the file:

```json
{
  "source": {
    "kind": "retained-evidence",
    "evidence_id": "<parent_evidence_id>"
  },
  "view": {
    "kind": "il2cpp-metadata",
    "collection": "types",
    "offset": 0,
    "limit": 64
  }
}
```

Collections are `sections`, `images`, `types`, `methods`, `fields`,
`properties`, `events`, `parameters`, `string_literals`, `method_addresses`,
`return_types`, `field_types` and `parameter_types`. Every returned row includes
its source `index`, scoped by artifact SHA-256 and collection. All collections
accept batch `indices` and `fields`; collections whose rows have a `name` also
accept exact `names`. Types also accept `image_indices`, `namespaces` and
`declaring_types`; methods, fields, properties and events accept
`declaring_types`. Filters intersect, duplicate indices are returned once, and
rows retain metadata order. An empty filter selects no rows; `fields: []`
returns indices only. Omitted fields return the complete selected rows.

For example, after resolving a type index, retrieve selected method facts:

```json
{
  "source": {
    "kind": "retained-evidence",
    "evidence_id": "<parent_evidence_id>"
  },
  "view": {
    "kind": "il2cpp-metadata",
    "collection": "methods",
    "declaring_types": [1555],
    "names": ["SendMessage"],
    "fields": ["name", "declaring_type"]
  }
}
```

`offset` counts matching rows, not source indices. `limit` defaults to 64;
`coverage.next_offset` continues that filtered page. Coverage describes retained
metadata facts only; runtime behavior and correspondence to native code remain
unknown. Each view preserves the parent Evidence link, artifact identity and
limitations. Queries work after the source file is removed. Select
`detail: "complete"` to return every row inline within the separate MCP response
budget.

## CLI

```bash
rea inspect-il2cpp-metadata /absolute/path/global-metadata.dat --json
```

The CLI defaults to complete Evidence. For compact delivery, explicitly preserve
the full Evidence in a new file:

```bash
rea inspect-il2cpp-metadata /absolute/path/global-metadata.dat \
  --detail summary --evidence_output /tmp/metadata-evidence.json --json
jq -c '{source: {kind: "inline", evidence: .records[0]}, view: {kind: "il2cpp-metadata", collection: "methods", indices: [9785], fields: ["name", "declaring_type"]}}' \
  /tmp/metadata-evidence.json > /tmp/metadata-query.json
rea inspect-analysis-view /tmp/metadata-query.json --json
```

Use the exported Evidence with the CLI's inline Evidence source format described
in [CLI and Evidence](cli.md#run-a-command). Compact delivery requires
`--evidence_output`; existing files are never overwritten. The full export
preserves every decoded row for subsequent queries without the original file.

`--binary PATH` links method addresses and `--architecture arm64|amd64` selects
the slice of a universal Mach-O.

## Observations

The result contains:

- `artifact`: path, SHA-256 and byte length;
- `magic`: unsigned little-endian header signature (`0xFAB11BAF`, delivered as a JSON number);
- `metadata_version`: `24`, `27`, `29`, `31` or `39`;
- `index_widths`: the serialized widths (1, 2 or 4 bytes) of
  `type_definition`, `generic_container`, `parameter` and `type` indices, and
  `type_width_source`. Version 39 derives the type index width from the
  `interface-offsets-record` or the `type-definition-record`; versions 27, 29
  and 31 always use 4-byte indices (`fixed-width-version`);
- `sections`: all 31 header sections in header order, each with `offset`, `size`
  and `count`. Versions 24 to 31 record no counts, so `count` is `null` and
  record counts come from the section sizes;
- `images`: `name`, `type_start` and `type_count`;
- `types`: `name`, `namespace`, `method_start`, `method_count`,
  `nested_type_start`, `nested_type_count` and `declaring_type`;
- `methods`: `name` and `declaring_type`;
- `fields`, `properties` and `events`: `name` and `declaring_type`, the type
  whose member range holds the row (`-1` when none does);
- `parameters`: `name` and `method`, the method whose parameter range holds it;
- `string_literals`: managed string literals as `value`, or `value_base64` with
  the exact bytes when they are not valid UTF-8;
- `limitations`.

A row's position in its collection is its metadata index, so `type_start`,
`method_start` and `declaring_type` refer to positions in `types` or `methods`.
`nested_type_start` instead indexes the metadata's `nestedTypes` table, which is
not returned; each nested type's `declaring_type` carries that relationship.
A type's `declaring_type` is derived from the `nestedTypes` section and is `-1`
for top-level types. The start of an empty range can retain the original value
`-1`.

The complete inventory of a large game is several megabytes and can exceed
the MCP response budget. Summary delivery and filtered, projected pages keep
unneeded rows out of agent context without discarding the source Evidence.

## Native method addresses

`binary_path` names the native binary built with the metadata: macOS
`GameAssembly.dylib` (Mach-O), Windows `GameAssembly.dll` (64-bit PE) or
Android `libil2cpp.so` (64-bit ELF, AArch64 or x86-64). A
universal Mach-O needs `binary_architecture` (`arm64` or `amd64`); a thin binary
rejects it. The file is read, never loaded or executed.

A position-independent `libil2cpp.so` stores zero in most pointer slots and
keeps the value in `R_AARCH64_RELATIVE` or `R_X86_64_RELATIVE` relocations
(`DT_RELA`). The reader writes those values into a private copy before
searching it, so addresses are the link-time addresses and RVAs are relative to
the first loaded segment. Android packed
relocations (`DT_ANDROID_RELA`) are refused.

The binary's `Il2CppCodeRegistration` points to one `Il2CppCodeGenModule` per
assembly image. Each module record starts with its module name, its method
pointer count and its method pointer array. The reader finds, for every metadata
image, the single record whose name pointer reaches that image's name string and
whose count equals the image's method count. It then requires exactly one
`codeGenModulesCount`/`codeGenModules` pair that lists exactly those records. No
symbols are needed, so stripped builds work. A method's token row id selects its
slot in the module's method pointer array.

Name strings may be padded with NUL or, as MSVC writes them, with `0xFF`; a
name byte directly before a match means it is the tail of a longer name and is
not used. Some x86-64 builds keep no static CodeRegistration: in a Linux
`GameAssembly.so` from Unity 2023.2.13f1 the compiler folded the module array
and its count into the one loop that walks it, so no data word points at the
array (Il2CppDumper fails to link that file). When no CodeRegistration pair is
found on x86-64, the reader looks for pointer arrays listing exactly the located
modules and accepts one only if exactly one such array is the target of a
RIP-relative `lea` or `mov`; `code_gen_modules_field` is then `null`. Otherwise
the result stays `code-registration-not-found`. On that Linux build all 42,605
linked addresses are function starts in its `.eh_frame_hdr` table.

Checked builds: macOS arm64 and x86_64 slices from Unity 2021.3.45f2, 2022.3.30f1, 2022.3.62f3 and
6000.0.84f1 against dSYM symbols; Android arm64 and x86-64 from 2022.3.62f3
against `libil2cpp.sym.so`; Windows x64 from 2023.2.13f1 (metadata version 29,
the MIT-licensed game Between Two Worlds 1.0.5, `GameAssembly.dll` SHA-256
`a3ae7f6ecd1f671297b7d98d12713ef024062d93cd7a4205298102656c93b67a`) against
Il2CppDumper, where all 43,198 linked methods share an address with a
same-named Il2CppDumper method and identical code folding groups 10,448 methods
into 1,735 addresses. A macOS x86_64 build from Unity 2020.3.49f1 (metadata version 27, which Il2CppDumper reads as 27.1) links 10,555 methods, all at addresses where Il2CppDumper names the same method; its other addresses are generic instances. A build from Unity 2021.1.28f1 (also read as 27.1) gives the same result: 10,345 methods linked, every address named the same by Il2CppDumper, and its other 3,486 addresses generic instances.

These checks compare addresses with symbols or with another static tool. They
do not establish that a linked address is the code the game runs (a runtime may
patch, hook or replace it), that builds from other Unity versions, compilers or
obfuscators link the same way, or that a method without an address has no code:
generic instances, adjustor thunks and invokers are not linked, and an
`unknown` row was not looked up at all.

The result adds:

- `binary`: artifact identity, `format`, `architecture`, `image_base`,
  `code_gen_modules_field` (the address of `codeGenModulesCount`, or `null` as
  described above), `code_gen_modules_array` (the module pointer array) and
  `code_gen_modules` (`image`, record `address`, `method_pointer_count`);
- `method_addresses`: one row per method index with `state`, `address` and
  `rva` (address minus `image_base`), both hexadecimal strings. `state` is
  `code` when the module slot holds an address, `no-body` when the slot is zero,
  as for abstract, extern and most generic methods, and `unknown` when no type
  range in any image holds the method, so no module slot was read for it.
  `address` and `rva` are `null` unless `state` is `code`. The summary counts
  each state in `counts.method_address_states`. Ghidra seeds are written only
  for `code` rows.

- `return_types`, `field_types` and `parameter_types`: one row per method,
  field and parameter index with `type`, the index into the binary's
  `Il2CppType` table, and `name`, rendered from that table: C# keywords for
  primitives (`int`, `string`, `object`), `Namespace.Outer+Inner` for type
  definitions, `T[]`, `T[,]` and `T*`, generic instances as
  `System.Collections.Generic.List<string>` and generic parameters by their
  metadata name (`TKey`). A trailing `&` marks a by-reference type. `name` is
  `null` only for type index `-1`.

`binary` also records `types_field` and `types_count`: the address of
`Il2CppMetadataRegistration.typesCount` and its value. That record is found as
the single place whose `fieldOffsetsCount` and `typeDefinitionsSizesCount` both
equal the metadata type-definition count and whose type table is file mapped.

Without `binary_path`, `binary` is `null` and the four binary collections are
empty.

For metadata version 27, type names are `null` and only type indices are
reported: versions 27.0 to 27.2 share that header number but place the
Il2CppType byref flag in different bits, so a rendered name could gain or lose
`&` without warning.

The builds checked are listed after the module search rules above.

| Reason                            | Category    | Meaning                                                                                                            |
| --------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------ |
| `unsupported-container`           | unsupported | Not a 64-bit little-endian Mach-O, PE or ELF image (ELF: AArch64 or x86-64 with dynamic section).                  |
| `slice-selection-required`        | unsupported | A universal Mach-O was given without `binary_architecture`.                                                        |
| `slice-not-found`                 | unsupported | The requested slice is absent, or a thin binary was given an architecture.                                         |
| `unsupported-pointer-encoding`    | unsupported | Mach-O chained fixups or Android packed (APS2) ELF relocations; pointers not decoded.                              |
| `malformed-container`             | input error | The container headers are damaged.                                                                                 |
| `code-gen-modules-not-found`      | input error | An image has no module record; often a binary from a different build.                                              |
| `ambiguous-code-gen-module`       | input error | More than one record matches an image, or image names occur more than 4,096 times each or 65,536 times in all.     |
| `code-registration-not-found`     | input error | No single module table lists exactly the located records, and on x86-64 no single instruction loads such an array. |
| `invalid-method-token`            | input error | A method token is not a method row inside its module's pointer count.                                              |
| `invalid-method-pointer`          | input error | A pointer slot or a method address is not file mapped.                                                             |
| `metadata-registration-not-found` | input error | No single MetadataRegistration matches the type-definition count.                                                  |
| `invalid-type`                    | input error | A type index or `Il2CppType` record is out of range, unmapped or of an unrendered kind.                            |

Binary failures report `binary_path` as the input field. There is no partial
linking: any failure returns no addresses. The binary is bounded to 1 GiB.

## Ghidra function names

The CLI can turn a linked report into a
[`REA_GHIDRA_SEED_FILE`](installation.md) so Ghidra names every IL2CPP method
before auto-analysis:

```bash
rea inspect-il2cpp-metadata global-metadata.dat --binary libil2cpp.so \
  --ghidra-seeds il2cpp-seeds.tsv --json > /dev/null
export REA_GHIDRA_SEED_FILE="$PWD/il2cpp-seeds.tsv"
```

Each linked method becomes one `function` seed named `Namespace.Type$$Method`
(nested types joined with `.`, whitespace replaced by `_`), the Il2CppDumper
convention. Seeds are at `seed-base + rva`. The default base is where Ghidra's
loaders place the binary: `0x100000` for an ELF linked at 0, and the link base
for Mach-O and PE; `--seed-base 0x...` overrides it for a different import. When
identical code folding gives several methods one address, the first method names
the function and a `# folded <address> <kept> also <names>` comment line after
the seeds lists the others, so the kept name is visibly one of several. Ghidra still names a seeded function that is a thunk after its
target. The file is created and never overwritten.

## Failures

A file whose magic is not `0xFAB11BAF` fails as an unsupported target with
`unrecognized-magic`. The file may be encrypted or may not be IL2CPP metadata.
A version other than 24, 27, 29, 31 or 39 fails as an unsupported target with
`unsupported-version`.

Damaged metadata returns an input error (`invalid_format`) whose
message names one reason:

| Reason                    | Meaning                                                                                                          |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `truncated-header`        | The file is shorter than the header.                                                                             |
| `unexpected-header-size`  | `stringLiterals.offset` is not the header size: 264 bytes for version 24, 256 for 27, 29 and 31, 380 for 39.     |
| `section-out-of-bounds`   | A section extends beyond the file, or a non-empty section starts inside the header.                              |
| `section-overlap`         | Two sections overlap. Zero-size sections are exempt and gaps are allowed.                                        |
| `record-size-mismatch`    | A section size does not divide into its records, or the record size differs from the one the index widths imply. |
| `type-index-width`        | The record used to derive the type index width implies no 1, 2 or 4 byte width.                                  |
| `index-out-of-range`      | A serialized index or range points outside its target collection.                                                |
| `nested-type-conflict`    | A type is listed as nested in two types, in itself, or in a cycle of declaring types.                            |
| `declaring-type-mismatch` | A method inside a type's method range names a different type, or a method lies outside its type's range.         |
| `image-range-overlap`     | Two images claim the same type definitions.                                                                      |
| `invalid-string`          | A name index does not start a string, or the name is unterminated or not valid UTF-8.                            |

A version field that disagrees with the file's layout, for example a version
39 file relabeled as 29, usually surfaces as `unexpected-header-size` or
`record-size-mismatch`.

Two checks are stricter than the IL2CPP runtime: a name index must start a
string, and an empty range's start must lie between -1 and the collection size.
Every Unity-written file checked so far satisfies both; metadata rewritten by
other tools may be rejected.

An incomplete inventory is never reported as complete. Failures after a verified
snapshot retain partial source Evidence with its SHA-256, byte length and any
validated section row counts; these counts do not establish that names and
relationships were decoded. A file that changes during reading and a cancelled
request keep distinct errors. Decode checkpoints yield for cancellation, and
close waits for active work. Each reader admits one inspection at a time.
Resource guards bound the selected file to 256 MiB and the encoded complete
report to 64 MiB, checking JSON/UTF-8 expansion before serialization. MCP also applies its
[response transport budget](mcp-contracts.md); a complete report within the
report limit can still require the summary and paging path.

## Outside this tool

- Decrypting or deobfuscating protected metadata.
- Linking Mach-O binaries that use chained fixups, ELF images with Android
  packed (APS2) relocations, and 32-bit images; generic method instances,
  adjustor thunks and invokers.
- Full method signatures beyond the rendered field, parameter and return type
  names, generic method instances, and type names for metadata version 27.
- Running Ghidra or another disassembler. `--ghidra-seeds` only writes a seed
  file for [`REA_GHIDRA_SEED_FILE`](installation.md); use the
  [native workflow](native-investigation.md) for native code.
- Metadata versions other than 24, 27, 29, 31 and 39.

Names come from the metadata file only. They do not establish which methods
were compiled into the native binary or how they behave at runtime.

## Real producer verification

`npm run verify:il2cpp:metadata -- --metadata PATH` exercises a caller-supplied
`global-metadata.dat` through the public CLI and MCP. It is opt-in, like
`verify:pcap`, because no real game metadata ships with the repository. Normal
inspection does not need it.

The follow-up was checked against the public Cpp2IL
[`Simple_2022_3_35` sample](https://github.com/SamboyCoding/Cpp2IL/tree/b5ad444b82267cb1e4b88b8b373c008105bdea52/TestFiles/Simple_2022_3_35):
version 31, 1,892,268 bytes, SHA-256
`2441635a7c234a1a34deccc6a9906d6f5abcbdab078a38b2bf488a52a4962c48`.
An independent byte-layout oracle matched all 36 images, 2,468 types and 12,409
methods. Corresponding managed DLLs independently matched names and ownership
for 35 images, 2,463 types and 12,406 methods; the generated image has no matching
DLL. This does not establish real-producer coverage for versions 29 or 39.
