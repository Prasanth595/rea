import type {
  MachoDependency,
  MachoImageFacts,
  MachoSlice,
} from "../../domain/apple/dylibResolution.js";
import { machoCpuSubtypeBase } from "../../domain/apple/machoCpuIdentity.js";
import {
  classifyFatContainerIdentity,
  isMachoHeaderMagic,
  readFatContainerHeader,
  validateFatSliceIdentity,
  type FatSliceDeclaration,
  type FatSliceRangeIssue,
} from "../../domain/apple/machoContainer.js";

/** Read `length` bytes at `offset`; shorter results mean end of file. */
export type ReadAt = (offset: number, length: number) => Promise<Uint8Array>;

/** Load commands larger than this are refused instead of buffered. */
export const MAX_LOAD_COMMAND_BYTES = 16 * 1024 * 1024;
const MH_MAGIC = 0xfeedface;
const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM = 0xcefaedfe;
const MH_CIGAM_64 = 0xcffaedfe;
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;
const FAT_CIGAM = 0xbebafeca;
const FAT_CIGAM_64 = 0xbfbafeca;

const LC_ID_DYLIB = 0xd;
const LC_LOAD_DYLIB = 0xc;
const LC_LOAD_WEAK_DYLIB = 0x80000018;
const LC_REEXPORT_DYLIB = 0x8000001f;
const LC_LAZY_LOAD_DYLIB = 0x20;
const LC_LOAD_UPWARD_DYLIB = 0x80000023;
const LC_RPATH = 0x8000001c;
const LC_DYLD_ENVIRONMENT = 0x27;
const LC_CODE_SIGNATURE = 0x1d;
const LC_VERSION_MIN_MACOSX = 0x24;
const LC_VERSION_MIN_IPHONEOS = 0x25;
const LC_VERSION_MIN_TVOS = 0x2f;
const LC_VERSION_MIN_WATCHOS = 0x30;
const LC_BUILD_VERSION = 0x32;

// `mach-o/loader.h` `PLATFORM_*` numbers observed via Apple linker output.
const PLATFORM_MACOS = 1;
const PLATFORM_IOS = 2;
const PLATFORM_TVOS = 3;
const PLATFORM_WATCHOS = 4;
const PLATFORM_IOSSIMULATOR = 7;
const PLATFORM_TVOSSIMULATOR = 8;
const PLATFORM_WATCHOSSIMULATOR = 9;

const CPU_TYPE_I386 = 7;
const CPU_TYPE_X86_64 = 0x01000007;

/**
 * Legacy `LC_VERSION_MIN_*` commands predate explicit simulator platform
 * IDs. Per Apple's dyld rules the image CPU type distinguishes simulator
 * from device: Intel images are simulator, ARM images are device
 * (tvOS simulator applies to x86_64 only). `LC_BUILD_VERSION` platform
 * numbers are preserved verbatim; unknown future numbers stay unknown
 * downstream, never mapped to nearest.
 */
const legacyVersionMinPlatform = (
  command: number,
  cpuType: number,
): number | undefined => {
  const isIntel = cpuType === CPU_TYPE_I386 || cpuType === CPU_TYPE_X86_64;
  switch (command) {
    case LC_VERSION_MIN_MACOSX:
      return PLATFORM_MACOS;
    case LC_VERSION_MIN_IPHONEOS:
      return isIntel ? PLATFORM_IOSSIMULATOR : PLATFORM_IOS;
    case LC_VERSION_MIN_TVOS:
      return cpuType === CPU_TYPE_X86_64
        ? PLATFORM_TVOSSIMULATOR
        : PLATFORM_TVOS;
    case LC_VERSION_MIN_WATCHOS:
      return isIntel ? PLATFORM_WATCHOSSIMULATOR : PLATFORM_WATCHOS;
    default:
      return undefined;
  }
};

/** `mach-o/loader.h` `dylib_use_command`: `nameoff == 28` and this marker. */
const DYLIB_USE_MARKER = 0x1a741800;
const DYLIB_USE_WEAK_LINK = 0x1;
const DYLIB_USE_REEXPORT = 0x2;
const DYLIB_USE_UPWARD = 0x4;
const DYLIB_USE_DELAYED_INIT = 0x8;

const DEPENDENCY_COMMANDS: ReadonlyMap<number, MachoDependency["command"]> =
  new Map([
    [LC_LOAD_DYLIB, "LC_LOAD_DYLIB"],
    [LC_LOAD_WEAK_DYLIB, "LC_LOAD_WEAK_DYLIB"],
    [LC_REEXPORT_DYLIB, "LC_REEXPORT_DYLIB"],
    [LC_LAZY_LOAD_DYLIB, "LC_LAZY_LOAD_DYLIB"],
    [LC_LOAD_UPWARD_DYLIB, "LC_LOAD_UPWARD_DYLIB"],
  ]);

/** Malformed or unsupported structure found while decoding one image. */
class MachoFormatIssue extends Error {
  constructor(
    readonly status: "malformed" | "unsupported",
    message: string,
  ) {
    super(message);
  }
}

/** Report whether the first bytes carry a Mach-O or FAT magic number. */
export const hasMachoMagic = (head: Uint8Array): boolean => {
  if (head.byteLength < 4) return false;
  const magic = new DataView(
    head.buffer,
    head.byteOffset,
    head.byteLength,
  ).getUint32(0, false);
  return [
    MH_MAGIC,
    MH_MAGIC_64,
    MH_CIGAM,
    MH_CIGAM_64,
    FAT_MAGIC,
    FAT_MAGIC_64,
    FAT_CIGAM,
    FAT_CIGAM_64,
  ].includes(magic);
};

/** A structural defect, and whether it is malformed or merely unsupported. */
export interface MachoReadIssue {
  readonly status: "malformed" | "unsupported";
  readonly reason: string;
}

/**
 * File-level identity. FAT range issues stay per slice so a tolerant reader
 * can still report the slices whose ranges are valid.
 */
export type MachoContainer =
  | { readonly kind: "not-mach-o" }
  | ({ readonly kind: "issue" } & MachoReadIssue)
  | { readonly kind: "thin"; readonly size: number }
  | {
      readonly kind: "fat";
      readonly slices: readonly FatSliceDeclaration[];
      readonly rangeIssues: readonly (FatSliceRangeIssue | null)[];
    };

/** Classify a file as thin, FAT or not Mach-O without decoding any slice. */
export const readMachoContainer = async (
  readAt: ReadAt,
  size: number,
): Promise<MachoContainer> => {
  const head = await readAt(0, Math.min(size, 8));
  if (head.byteLength < 8)
    // A recognized magic with no room for a header is a truncated image.
    return hasMachoMagic(head)
      ? {
          kind: "issue",
          status: "malformed",
          reason: "Mach-O header is truncated",
        }
      : { kind: "not-mach-o" };
  const magic = viewOf(head).getUint32(0, false);
  let header: ReturnType<typeof readFatContainerHeader>;
  if (magic === FAT_MAGIC && size <= MAX_LOAD_COMMAND_BYTES) {
    const complete = await readAt(0, size);
    header =
      complete.byteLength === size
        ? readFatContainerHeader(complete, size)
        : readFatContainerHeader(head, size);
  } else header = readFatContainerHeader(head, size);
  if (header.state !== "not-fat") {
    if (header.state === "needs-data") {
      header = readFatContainerHeader(
        await readAt(0, header.requiredBytes),
        size,
      );
    }
    if (header.state === "not-fat") return { kind: "not-mach-o" };
    if (header.state === "needs-data")
      return {
        kind: "issue",
        status: "malformed",
        reason: "FAT table is truncated",
      };
    if (header.state === "malformed")
      return { kind: "issue", status: "malformed", reason: header.reason };
    let identity = classifyFatContainerIdentity(header, () => undefined);
    if (identity.state === "needs-slice-header") {
      const sliceHeaders = new Map<number, number | null>();
      for (const offset of identity.offsets)
        sliceHeaders.set(offset, await readSliceMagic(readAt, offset));
      identity = classifyFatContainerIdentity(header, (offset) =>
        sliceHeaders.get(offset),
      );
    }
    if (
      identity.state === "not-mach-o" ||
      identity.state === "needs-slice-header"
    )
      return { kind: "not-mach-o" };
    // A large CAFEBABE input whose bounded prefix resembles an invalid
    // known-CPU FAT table remains unknown until its JVM identity can be
    // checked; do not turn the resource limit into a malformed claim. A slice
    // with a valid range that starts with a Mach-O header settles identity,
    // and its siblings' range faults then stay their own.
    if (
      identity.state === "malformed" &&
      magic === FAT_MAGIC &&
      size > MAX_LOAD_COMMAND_BYTES &&
      !(await observesMachoSlice(readAt, header))
    )
      return {
        kind: "issue",
        status: "unsupported",
        reason:
          "FAT/JVM identity is unresolved because the class identity scan exceeds the 16 MiB limit",
      };
    // Identity is only malformed through a slice range issue, which the
    // returned rangeIssues retain.
    return {
      kind: "fat",
      slices: header.slices,
      rangeIssues: header.rangeIssues,
    };
  }
  if (magic === MH_CIGAM || magic === MH_CIGAM_64)
    return { kind: "thin", size };
  if (magic === MH_MAGIC || magic === MH_MAGIC_64)
    return {
      kind: "issue",
      status: "unsupported",
      reason: "big-endian Mach-O images are not supported",
    };
  return { kind: "not-mach-o" };
};

/** A slice's first word read big-endian, or null when it is truncated. */
const readSliceMagic = async (
  readAt: ReadAt,
  offset: number,
): Promise<number | null> => {
  const bytes = await readAt(offset, 4);
  return bytes.byteLength < 4 ? null : viewOf(bytes).getUint32(0, false);
};

const observesMachoSlice = async (
  readAt: ReadAt,
  header: {
    readonly slices: readonly FatSliceDeclaration[];
    readonly rangeIssues: readonly (FatSliceRangeIssue | null)[];
  },
): Promise<boolean> => {
  for (const [index, slice] of header.slices.entries())
    if (
      header.rangeIssues[index] === null &&
      isMachoHeaderMagic(await readSliceMagic(readAt, slice.offset))
    )
      return true;
  return false;
};

/** Decode every slice's dylib-loading load commands without reading code. */
export const readMachoImage = async (
  readAt: ReadAt,
  size: number,
): Promise<MachoImageFacts> => {
  try {
    const container = await readMachoContainer(readAt, size);
    if (container.kind === "not-mach-o") return { status: "not-mach-o" };
    if (container.kind === "issue")
      return { status: container.status, reason: container.reason };
    if (container.kind === "thin")
      return { status: "parsed", slices: [await readSlice(readAt, 0, size)] };
    const rangeIssue = container.rangeIssues.find(
      (issue): issue is FatSliceRangeIssue => issue !== null,
    );
    if (rangeIssue !== undefined)
      return { status: rangeIssue.category, reason: rangeIssue.reason };
    return {
      status: "parsed",
      slices: await readFatSlices(readAt, container.slices),
    };
  } catch (cause: unknown) {
    if (cause instanceof MachoFormatIssue)
      return { status: cause.status, reason: cause.message };
    throw cause;
  }
};

const readFatSlices = async (
  readAt: ReadAt,
  declarations: readonly FatSliceDeclaration[],
): Promise<MachoSlice[]> => {
  const slices: MachoSlice[] = [];
  // Keep validating after an unsupported slice so a later malformed slice is
  // reported as malformed whatever the slice order.
  let unsupported: MachoFormatIssue | undefined;
  for (const declaration of declarations) {
    const { offset, size: length, cpuType, cpuSubtype } = declaration;
    let slice: MachoSlice;
    try {
      slice = await readSlice(readAt, offset, length, {
        fatCpuType: cpuType,
        fatCpuSubtype: cpuSubtype,
        alignmentExponent: declaration.alignmentExponent,
      });
    } catch (cause: unknown) {
      if (
        !(cause instanceof MachoFormatIssue) ||
        cause.status !== "unsupported"
      )
        throw cause;
      unsupported ??= cause;
      continue;
    }
    const identityIssue = validateFatSliceIdentity(declaration, {
      cpuType: slice.cpu_type,
      cpuSubtype: slice.cpu_subtype,
    });
    if (identityIssue !== null)
      throw new MachoFormatIssue("malformed", identityIssue);
    slices.push(slice);
  }
  if (unsupported !== undefined) throw unsupported;
  return slices;
};

/** Little-endian `mach_header(_64)` fields that frame one slice's commands. */
export interface MachoSliceHeader {
  /** True for `MH_MAGIC_64`; the magic, not the CPU type, sets the width. */
  readonly wide: boolean;
  readonly headerSize: number;
  readonly cpuType: number;
  readonly cpuSubtype: number;
  readonly fileType: number;
  readonly commandCount: number;
  readonly commandBytes: number;
}

/** One framed load command; `offset` is relative to the end of the header. */
export interface MachoLoadCommand {
  readonly index: number;
  readonly command: number;
  readonly offset: number;
  readonly body: Uint8Array;
}

/** One slice's header and raw load-command table, or why it was not read. */
export type MachoSliceCommandTable =
  | {
      readonly status: "read";
      readonly header: MachoSliceHeader;
      readonly bytes: Uint8Array;
    }
  | (MachoReadIssue & { readonly header: MachoSliceHeader | null });

/** Read one slice's header and load-command bytes without framing them. */
export const readSliceCommandTable = async (
  readAt: ReadAt,
  base: number,
  length: number,
): Promise<MachoSliceCommandTable> => {
  const headerBytes = await readAt(base, 28);
  if (headerBytes.byteLength < 28)
    return failed("malformed", "Mach-O header is truncated", null);
  const view = viewOf(headerBytes);
  const magic = view.getUint32(0, true);
  if (magic !== MH_MAGIC_64 && magic !== MH_MAGIC)
    return magic === swap(MH_MAGIC) || magic === swap(MH_MAGIC_64)
      ? failed(
          "unsupported",
          "big-endian Mach-O slices are not supported",
          null,
        )
      : failed(
          "malformed",
          `slice at offset ${base} has no Mach-O header`,
          null,
        );
  const wide = magic === MH_MAGIC_64;
  const header: MachoSliceHeader = {
    wide,
    headerSize: wide ? 32 : 28,
    cpuType: view.getUint32(4, true),
    cpuSubtype: view.getUint32(8, true),
    fileType: view.getUint32(12, true),
    commandCount: view.getUint32(16, true),
    commandBytes: view.getUint32(20, true),
  };
  if (header.commandBytes > MAX_LOAD_COMMAND_BYTES)
    return failed(
      "unsupported",
      `load commands occupy ${header.commandBytes} bytes, above the ${MAX_LOAD_COMMAND_BYTES}-byte limit`,
      header,
    );
  if (header.headerSize + header.commandBytes > length)
    return failed(
      "malformed",
      "load commands extend beyond the Mach-O slice",
      header,
    );
  const bytes = await readAt(base + header.headerSize, header.commandBytes);
  if (bytes.byteLength < header.commandBytes)
    return failed("malformed", "load commands is truncated", header);
  return { status: "read", header, bytes };
};

const failed = (
  status: MachoReadIssue["status"],
  reason: string,
  header: MachoSliceHeader | null,
): MachoSliceCommandTable => ({ status, reason, header });

/**
 * Hand each load command to `visit` in order without retaining it. A framing
 * failure is returned after every command before the failing one was visited.
 */
export const frameLoadCommands = (
  {
    header,
    bytes,
  }: { readonly header: MachoSliceHeader; readonly bytes: Uint8Array },
  visit: (command: MachoLoadCommand) => void,
): { readonly status: "framed" } | MachoReadIssue => {
  // loader.h: load commands are 8-byte aligned in 64-bit images, 4 in 32-bit.
  const alignment = header.wide ? 8 : 4;
  const view = viewOf(bytes);
  let offset = 0;
  for (let index = 0; index < header.commandCount; index++) {
    if (offset + 8 > bytes.byteLength)
      return {
        status: "malformed",
        reason: `load command ${index} starts beyond sizeofcmds`,
      };
    const command = view.getUint32(offset, true);
    const size = view.getUint32(offset + 4, true);
    if (size < 8 || size % alignment !== 0 || offset + size > bytes.byteLength)
      return {
        status: "malformed",
        reason: `load command ${index} at offset ${offset} has invalid cmdsize ${size}`,
      };
    visit({
      index,
      command,
      offset,
      body: bytes.subarray(offset, offset + size),
    });
    offset += size;
  }
  if (offset !== bytes.byteLength)
    return {
      status: "malformed",
      reason: `load commands declare ${header.commandCount} commands but sizeofcmds holds ${bytes.byteLength} bytes`,
    };
  return { status: "framed" };
};

const readSlice = async (
  readAt: ReadAt,
  base: number,
  length: number,
  fat: {
    readonly fatCpuType: number;
    readonly fatCpuSubtype: number;
    readonly alignmentExponent: number;
  } | null = null,
): Promise<MachoSlice> => {
  const table = await readSliceCommandTable(readAt, base, length);
  if (table.status !== "read")
    throw new MachoFormatIssue(table.status, table.reason);
  const { header } = table;
  const slice: MachoSlice = {
    architecture: architectureName(header.cpuType, header.cpuSubtype),
    slice_offset: base,
    slice_size: length,
    cpu_type: header.cpuType,
    cpu_subtype: header.cpuSubtype,
    fat_cpu_type: fat?.fatCpuType ?? null,
    fat_cpu_subtype: fat?.fatCpuSubtype ?? null,
    fat_alignment_exponent: fat?.alignmentExponent ?? null,
    file_type: fileTypeName(header.fileType),
    file_type_code: header.fileType,
    platform: null,
    platforms: [],
    install_name: null,
    dependencies: [],
    rpaths: [],
    dyld_environment: [],
    code_signature_present: false,
  };
  // Each command decodes as it is framed, so a defect in an earlier command
  // keeps precedence over a later framing defect.
  const framed = frameLoadCommands(table, ({ command, body, index }) =>
    decodeCommand(command, body, index, slice),
  );
  if (framed.status !== "framed")
    throw new MachoFormatIssue(framed.status, framed.reason);
  const distinctPlatforms = [...new Set(slice.platforms)];
  slice.platform =
    distinctPlatforms.length === 1 ? (distinctPlatforms[0] ?? null) : null;
  return slice;
};

const decodeCommand = (
  command: number,
  body: Uint8Array,
  index: number,
  slice: MachoSlice,
): void => {
  if (command === LC_ID_DYLIB) {
    slice.install_name = commandString(body, 24, index);
    return;
  }
  if (command === LC_RPATH) {
    slice.rpaths.push(commandString(body, 12, index));
    return;
  }
  if (command === LC_DYLD_ENVIRONMENT) {
    slice.dyld_environment.push(commandString(body, 12, index));
    return;
  }
  if (command === LC_CODE_SIGNATURE) {
    // linkedit_data_command: cmd, cmdsize, dataoff, datasize.
    if (body.byteLength < 16)
      throw new MachoFormatIssue(
        "malformed",
        `load command ${index} is too short for LC_CODE_SIGNATURE`,
      );
    slice.code_signature_present = true;
    return;
  }
  if (command === LC_BUILD_VERSION) {
    if (body.byteLength < 24)
      throw new MachoFormatIssue(
        "malformed",
        `load command ${index} is too short for LC_BUILD_VERSION`,
      );
    const view = viewOf(body);
    const toolCount = view.getUint32(20, true);
    if (toolCount > Math.floor((body.byteLength - 24) / 8))
      throw new MachoFormatIssue(
        "malformed",
        `load command ${index} LC_BUILD_VERSION tool records exceed cmdsize`,
      );
    const platform = view.getUint32(8, true);
    slice.platforms.push(platform);
    return;
  }
  const legacyPlatform = legacyVersionMinPlatform(command, slice.cpu_type);
  if (legacyPlatform !== undefined) {
    if (body.byteLength < 16)
      throw new MachoFormatIssue(
        "malformed",
        `load command ${index} is too short for a version-min command`,
      );
    slice.platforms.push(legacyPlatform);
    return;
  }
  const name = DEPENDENCY_COMMANDS.get(command);
  if (name !== undefined)
    slice.dependencies.push(decodeDependency(name, body, index));
};

const decodeDependency = (
  command: MachoDependency["command"],
  body: Uint8Array,
  index: number,
): MachoDependency => {
  if (body.byteLength < 24)
    throw new MachoFormatIssue(
      "malformed",
      `load command ${index} is too short for a dylib command`,
    );
  const view = viewOf(body);
  const nameOffset = view.getUint32(8, true);
  const usesFlags =
    nameOffset === 28 &&
    body.byteLength >= 28 &&
    view.getUint32(12, true) === DYLIB_USE_MARKER;
  const flags = usesFlags ? view.getUint32(24, true) : 0;
  return {
    command,
    encoding: usesFlags ? "dylib_use_command" : "dylib_command",
    install_name: commandString(body, usesFlags ? 28 : 24, index),
    weak:
      command === "LC_LOAD_WEAK_DYLIB" || (flags & DYLIB_USE_WEAK_LINK) !== 0,
    upward:
      command === "LC_LOAD_UPWARD_DYLIB" || (flags & DYLIB_USE_UPWARD) !== 0,
    reexport:
      command === "LC_REEXPORT_DYLIB" || (flags & DYLIB_USE_REEXPORT) !== 0,
    delayed_init: (flags & DYLIB_USE_DELAYED_INIT) !== 0,
    current_version: version(view.getUint32(16, true)),
    compatibility_version: version(view.getUint32(20, true)),
  };
};

/** NUL-terminated UTF-8 string at a `lc_str` offset inside one command. */
const commandString = (
  body: Uint8Array,
  minimumOffset: number,
  index: number,
): string => {
  if (body.byteLength < 12)
    throw new MachoFormatIssue(
      "malformed",
      `load command ${index} is too short to hold a string offset`,
    );
  const offset = viewOf(body).getUint32(8, true);
  if (offset < minimumOffset || offset >= body.byteLength)
    throw new MachoFormatIssue(
      "malformed",
      `load command ${index} has string offset ${offset} outside the command`,
    );
  const end = body.indexOf(0, offset);
  if (end < 0)
    throw new MachoFormatIssue(
      "malformed",
      `load command ${index} has an unterminated string`,
    );
  try {
    // lc_str contains name/path data, so a leading U+FEFF is part of its identity.
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      body.subarray(offset, end),
    );
  } catch {
    throw new MachoFormatIssue(
      "malformed",
      `load command ${index} has a string that is not UTF-8`,
    );
  }
};

const CPU_ARCH_ABI64 = 0x01000000;
const CPU_ARCH_ABI64_32 = 0x02000000;
const CPU_TYPE_X86 = 7;
const CPU_TYPE_ARM = 12;
const CPU_SUBTYPE_ARM64E = 2;
const CPU_SUBTYPE_ARM64E_X1 = 12;
const CPU_SUBTYPE_X86_64_H = 8;

const architectureName = (cpuType: number, cpuSubtype: number): string => {
  const subtype = machoCpuSubtypeBase(cpuSubtype);
  if (cpuType === (CPU_TYPE_ARM | CPU_ARCH_ABI64))
    // Both pointer-authentication subtypes belong to the arm64e family.
    return subtype === CPU_SUBTYPE_ARM64E || subtype === CPU_SUBTYPE_ARM64E_X1
      ? "arm64e"
      : "arm64";
  if (cpuType === (CPU_TYPE_ARM | CPU_ARCH_ABI64_32)) return "arm64_32";
  if (cpuType === (CPU_TYPE_X86 | CPU_ARCH_ABI64))
    return subtype === CPU_SUBTYPE_X86_64_H ? "x86_64h" : "x86_64";
  if (cpuType === CPU_TYPE_X86) return "i386";
  if (cpuType === CPU_TYPE_ARM) return "arm";
  return `cpu-${cpuType.toString(16)}`;
};

const fileTypeName = (fileType: number): MachoSlice["file_type"] =>
  fileType === 2
    ? "execute"
    : fileType === 6
      ? "dylib"
      : fileType === 8
        ? "bundle"
        : "other";

const version = (value: number): string =>
  `${value >>> 16}.${(value >>> 8) & 0xff}.${value & 0xff}`;

const swap = (value: number): number =>
  (((value & 0xff) << 24) |
    ((value & 0xff00) << 8) |
    ((value >>> 8) & 0xff00) |
    (value >>> 24)) >>>
  0;

const viewOf = (bytes: Uint8Array): DataView =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
