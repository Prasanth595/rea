# Headerless raw-binary analysis with Ghidra

REA admits a headerless executable when the caller supplies the CPU family and
code entry address, with an optional independent load base. That interpretation is not
inferred from a `.bin` suffix or from unrecognized bytes.

## Open and inspect

```bash
rea inspect /absolute/path/to/ecu.bin --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
rea function /absolute/path/to/ecu.bin 0x8000000 --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/ecu.bin --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
```

```json
{
  "name": "open_binary",
  "arguments": {
    "path": "/absolute/path/to/ecu.bin",
    "format": "raw-binary",
    "architecture": "arm",
    "entry_point": "0x8000000",
    "provider_id": "ghidra"
  }
}
```

`architecture` is one of `x86`, `x86_64`, `arm`, `arm64`, `6502`, or `m68k`. `entry_point` is a
hexadecimal code address of the form `0x…`. By default, the complete file is
mapped starting at that address. To load an image whose leading bytes are data,
supply `base_address` (CLI: `--base-address`) separately. File offset 0 maps to
the load base; Ghidra seeds an `entry` function at `entry_point` before analysis.
The entry must lie within the mapped image. Its source offset is reported by
`inspect_native_load_image`, independently of the base.

For example, a caller-selected ARM image with a data word before its code can
use `base_address: "0x8000000"` and `entry_point: "0x8000004"`. Existing calls
that omit the base retain their entry-based mapping. The base need not have the
code entry's alignment; overflow checks apply to the complete mapped file.
Generic ARM and AArch64 entries must be 4-byte aligned; m68k entries must be 2-byte
aligned; x86 and 6502 entries may be byte-aligned.
For 6502, the entry and complete mapped file must fit within `0x0000..0xffff`;
images that cross the 16-bit boundary are rejected before provider startup.
For m68k, the mapping must fit within `0x0..0xffffffff`.
`open_binary` and an open `binary_session` return the canonical `entry_point`
for raw targets so callers can verify the selected mapping directly.
Omitted `format` keeps header-based detection; architecture and entry without
`format=raw-binary` are rejected.

Ghidra imports a private snapshot with `BinaryLoader` and these generic
languages and compiler specifications. Each family has one fixed byte order:
m68k is big-endian and the others are little-endian.

| architecture                       | language_id           | compiler_spec_id |
| ---------------------------------- | --------------------- | ---------------- |
| x86                                | `x86:LE:32:default`   | `gcc`            |
| x86_64                             | `x86:LE:64:default`   | `gcc`            |
| arm                                | `ARM:LE:32:v7`        | `default`        |
| arm, `processor_variant: cortex-m` | `ARM:LE:32:Cortex`    | `default`        |
| arm64                              | `AARCH64:LE:64:v8A`   | `default`        |
| 6502                               | `6502:LE:16:default`  | `default`        |
| m68k                               | `68000:BE:32:default` | `default`        |

Compiler specifications select analysis conventions; they do not identify the
original compiler or ABI of a headerless target. Ghidra's x86 languages do not
provide a compiler specification named `default`.

Those settings, the caller-supplied base and entry, and `language_selection:
caller-supplied-v1` are committed in the analysis profile. A different base, entry
or architecture is a different profile; snapshots from header-detected targets
do not replay.

Raw snapshot targets retain a distinct base, and session reuse compares it as
well as the entry. An explicit base equal to the entry is equivalent to omitting
it. This import revision updates the Ghidra analysis profile, so older raw
snapshots must be regenerated rather than replayed under the new preparer.

The mapped start is independent of Ghidra's program image base, which remains
`0x0` for BinaryLoader. Ghidra may report additional language-defined entry
points, including unmapped ARM vectors. Load-image verification requires the
caller-supplied entry and preserves those other entries as observations.
For 6502, BinaryLoader maps the file before adding its language-defined zero-page
and stack blocks. Conflicting default blocks are skipped; low-address files stay
in the default address space rather than an overlay. Non-conflicting uninitialized
blocks remain observations, not file-backed bytes.
Independent raw verification streams the complete private snapshot digest and
extent with bounded memory and supports cancellation during the read.
It also requires the source-backed block to be initialized, loaded, and
non-overlay in the bound language's default address space. Contradictory mapping
observations are retained with `mismatch`, even when the source hashes agree.

Hopper and IDA refuse raw-binary targets. Windows Ghidra P0 admits native PE
applications/DLLs and explicitly selected raw 6502 images. Other raw CPU families
remain outside the Windows boundary. Native path admission, private DACLs, Job
Object ownership, immutable snapshots, and the no-mutation policy still apply.

## Cortex-M / Thumb

Select `architecture: "arm"` and `processor_variant: "cortex-m"` explicitly.
The ordinary ARM profile remains `ARM:LE:32:v7` when the variant is omitted.
The Cortex profile selects Ghidra's little-endian Cortex/Thumb language and
requires a two-byte-aligned code entry. An odd Thumb function pointer, such as
one read from a reset vector, is rejected with a diagnostic; supply its actual
even code address instead. REA does not silently clear pointer bits.

For this guide's source-owned synthetic fixture (not a device memory map):

```json
{
  "path": "/absolute/path/to/synthetic-cortex.bin",
  "format": "raw-binary",
  "architecture": "arm",
  "processor_variant": "cortex-m",
  "base_address": "0x8000000",
  "entry_point": "0x8000040",
  "provider_id": "ghidra"
}
```

The equivalent CLI selection is `--target-format raw-binary --architecture arm
--processor-variant cortex-m --base-address 0x8000000 --entry-point 0x8000040`.
The base, entry and variant are part of session and snapshot identity; a generic
ARM analysis cannot be reused as a Cortex analysis. Ghidra's entry `TMode` context
is checked before disassembly and independently reported by
`inspect_native_load_image`. Missing or non-Thumb context cannot yield a verified
Cortex import.

`npm run verify:ghidra:cortex-m` uses a source-owned Cortex-M0 instruction fixture
with initial vector data, a Thumb call, a branch and an absolute data pointer.
It checks zero and nonzero load bases through the real CLI/MCP, source mappings,
entry context, decompilation, invalid odd-pointer rejection, variant partitioning,
unchanged source bytes and cleanup. It does not execute the firmware. Ghidra's
Cortex language supports a broader ISA than Cortex-M0; this fixture does not
validate every Cortex-M version, floating-point ABI or TrustZone behavior.

Base and code entry must be supplied by the analyst. REA does not infer vector
tables, RAM, peripheral regions or vendor boot mappings. Windows P0 retains its
existing raw-6502-only boundary; this is a Linux/macOS provider lane.

## NMOS 6502

```bash
rea function /absolute/path/to/image.bin 0x8001 --target-format raw-binary --architecture 6502 --entry-point 0x8001 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/image.bin --target-format raw-binary --architecture 6502 --entry-point 0x8001 --provider ghidra --json
```

Select only headerless NMOS 6502 code with a known entry at file offset 0.
The built-in Ghidra processor supplies static instructions, functions,
pseudocode, and references. Evidence preserves `architecture: "6502"`, the
selected language, entry, file digest, and verified source mapping. Register and
calling conventions are analysis conventions, not a recovered source ABI.

This lane does not interpret iNES headers, cartridge mappers, bank switching,
or other console-specific memory layouts. 65C02 and 65816 programs need different
processor semantics and are not admitted as those variants. REA does not infer
the CPU from the file suffix, guess the reset vector, or emulate the target.

`npm run verify:ghidra:6502` assembles and links the source-owned fixture with
`ca65` and `ld65` (tested from cc65 tag `V2.19`, whose tools report `V2.18`).
Set `REA_CA65` and `REA_LD65` to explicit executable paths if needed. The lane
checks real CLI/MCP load-image parity, mapped bytes, decoded calls, decompilation,
invalid mappings, unchanged source bytes and runtime cleanup.
Low-memory checks include a file spanning the zero-page/stack boundary at `0xff`
and a complete 64-KiB image at `0x0`, with verified default-space mappings through
both CLI and MCP. On Windows, the lane also checks that a caller-selected
junction path is rejected at snapshot admission through CLI and MCP, with
unchanged source bytes and complete runtime cleanup. Windows requires the
matching native addon; the POSIX provider path has not been exercised by the
Windows run.

## Motorola 68000

```bash
rea function /absolute/path/to/image.bin 0x1000 --target-format raw-binary --architecture m68k --entry-point 0x1000 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/image.bin --target-format raw-binary --architecture m68k --entry-point 0x1000 --provider ghidra --json
```

Select only headerless big-endian 68000-family code with a known, even entry at
file offset 0. Ghidra's `68000:BE:32:default` language decodes the 68040
superset in the 32-bit `ram` address space. Instructions that a real MC68000
would not execute are therefore not rejected, and 68020, 68030, CPU32, and
ColdFire programs are not admitted as those variants. Addresses are not masked
to the MC68000 24-bit bus. Evidence preserves `architecture: "m68k"`, the
selected language, entry, file digest, and verified source mapping. Register and
calling conventions are analysis conventions, not a recovered source ABI.

This lane does not interpret Amiga hunks, Atari ST, or other container headers,
cartridge or console memory maps, or bank switching. REA does not read the
initial stack pointer and reset vector from the first eight bytes; select the
entry explicitly. Windows Ghidra P0 does not admit m68k.

`npm run verify:ghidra:m68k` uses a source-owned 22-byte fixture written as
annotated hex in the verifier, so it needs no assembler. The lane checks real
CLI/MCP load-image parity, mapped bytes, a decoded call, decompilation by address
and file offset, misaligned and out-of-range mappings, unchanged source bytes and
runtime cleanup. It has been run with Ghidra 12.1.4 on macOS; Linux has not been
exercised.

## Limitations

- Headers are not discovered from file bytes. This increment does not guess
  load addresses, vector tables, or memory maps.
- Big-endian ARM and unspecified Thumb-only or other Ghidra processor variants
  are unsupported. Cortex-M requires its explicit variant; m68k is the only
  big-endian family.
- Reset vectors, memory-mapped I/O, and firmware boot sequences are not
  emulated.
- Independent load-image verification covers source identity, mapped file
  bytes, the bound language, and the caller-supplied entry. Original bytes
  stay unchanged.
