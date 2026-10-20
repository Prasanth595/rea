import type {
  Il2cppMetadata,
  Il2cppMetadataSection,
} from "../domain/il2cpp/il2cppMetadata.js";
import {
  checkRange,
  Il2cppMetadataFormatFailure,
  readIndex,
  type MetadataTables,
} from "./Il2cppMetadataFile.js";

type Members = Pick<
  Il2cppMetadata,
  "fields" | "properties" | "events" | "parameters" | "string_literals"
>;

interface Range {
  readonly start: number;
  readonly count: number;
}

/** Entries in a member section, checked against its record size. */
const entries = (
  { indexing }: MetadataTables,
  section: Il2cppMetadataSection,
  recordBytes: number,
) => {
  const count =
    indexing === "counted" ? (section.count ?? 0) : section.size / recordBytes;
  if (!Number.isInteger(count) || section.size !== count * recordBytes)
    throw new Il2cppMetadataFormatFailure(
      "record-size-mismatch",
      `section ${section.name} size ${section.size} does not hold whole ${recordBytes}-byte records`,
    );
  return count;
};

/** Owner of each row from the owners' ranges; unclaimed rows keep -1. */
const claim = (ranges: readonly Range[], total: number, label: string) => {
  const owners = new Int32Array(total).fill(-1);
  for (const [owner, range] of ranges.entries()) {
    checkRange(
      `${label} range of owner ${owner}`,
      range.start,
      range.count,
      total,
    );
    for (let row = range.start; row < range.start + range.count; row += 1) {
      if (owners[row] !== -1)
        throw new Il2cppMetadataFormatFailure(
          "declaring-type-mismatch",
          `${label} ${row} is claimed by owners ${owners[row]} and ${owner}`,
        );
      owners[row] = owner;
    }
  }
  return owners;
};

const typeMemberRanges = (tables: MetadataTables, typeTotal: number) => {
  const { bytes, section, widths, recordBytes } = tables;
  const typeDefinitions = section("typeDefinitions");
  const fields: Range[] = [];
  const properties: Range[] = [];
  const events: Range[] = [];
  for (let index = 0; index < typeTotal; index += 1) {
    const at = typeDefinitions.offset + index * recordBytes.typeDefinitions;
    // Same start and count blocks the type reader uses.
    const starts =
      at +
      12 +
      tables.typeDefinitionTypeIndices * widths.type +
      widths.generic_container;
    const countsAt = starts + 32;
    fields.push({
      start: bytes.readInt32LE(starts),
      count: bytes.readUInt16LE(countsAt + 4),
    });
    events.push({
      start: bytes.readInt32LE(starts + 8),
      count: bytes.readUInt16LE(countsAt + 6),
    });
    properties.push({
      start: bytes.readInt32LE(starts + 12),
      count: bytes.readUInt16LE(countsAt + 2),
    });
  }
  return { fields, properties, events };
};

const methodParameterRanges = (tables: MetadataTables, methodTotal: number) => {
  const { bytes, section, widths, recordBytes } = tables;
  const methods = section("methods");
  return Array.from({ length: methodTotal }, (_, index) => {
    const at = methods.offset + index * recordBytes.methods;
    // Name, declaring type, return type and the optional return token.
    const parameterStart =
      at +
      8 +
      widths.type_definition +
      widths.type +
      (tables.methodReturnParameterToken ? 4 : 0) -
      4;
    return {
      start: readIndex(bytes, parameterStart, widths.parameter),
      count: bytes.readUInt16LE(at + recordBytes.methods - 2),
    };
  });
};

/** Rows between cooperative yields, matching the metadata row readers. */
const BATCH = 256;

/** Names in a member section, each paired with its owner. */
function* readNamed(
  tables: MetadataTables,
  name: "fields" | "properties" | "events" | "parameters",
  recordBytes: number,
  ranges: readonly Range[],
): Generator<void, { name: string; owner: number }[]> {
  const section = tables.section(name);
  const total = entries(tables, section, recordBytes);
  const owners = claim(ranges, total, name);
  const rows: { name: string; owner: number }[] = [];
  for (let index = 0; index < total; index += 1) {
    if (index % BATCH === 0) yield;
    rows.push({
      name: tables.readString(
        tables.bytes.readInt32LE(section.offset + index * recordBytes),
        `${name} ${index} name`,
      ),
      owner: owners[index]!,
    });
  }
  return rows;
}

function* readStringLiterals(
  tables: MetadataTables,
): Generator<void, Members["string_literals"]> {
  const { bytes, section, indexing } = tables;
  const literals = section("stringLiterals");
  const data = section("stringLiteralData");
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  // Version 39 stores only start offsets and ends with a sentinel record;
  // earlier versions store (length, offset) pairs.
  const recordBytes = indexing === "counted" ? 4 : 8;
  const records = entries(tables, literals, recordBytes);
  const total = indexing === "counted" ? Math.max(records - 1, 0) : records;
  const rows: Members["string_literals"] = [];
  for (let index = 0; index < total; index += 1) {
    if (index % BATCH === 0) yield;
    const at = literals.offset + index * recordBytes;
    const start =
      indexing === "counted"
        ? bytes.readInt32LE(at)
        : bytes.readInt32LE(at + 4);
    const length =
      indexing === "counted"
        ? bytes.readInt32LE(at + 4) - start
        : bytes.readUInt32LE(at);
    if (start < 0 || length < 0 || start + length > data.size)
      throw new Il2cppMetadataFormatFailure(
        "index-out-of-range",
        `string literal ${index} [${start}, ${start + length}) is outside the ${data.size}-byte literal data`,
      );
    const value = bytes.subarray(
      data.offset + start,
      data.offset + start + length,
    );
    try {
      rows.push({ value: decoder.decode(value), value_base64: null });
    } catch {
      rows.push({ value: null, value_base64: value.toString("base64") });
    }
  }
  return rows;
}

/** Field, property, event and parameter names and managed string literals, yielding between row batches. */
export function* readIl2cppMembers(
  tables: MetadataTables,
  typeTotal: number,
  methodTotal: number,
): Generator<void, Members> {
  const T = tables.widths.type;
  const ranges = typeMemberRanges(tables, typeTotal);
  const owned = (row: { name: string; owner: number }) => ({
    name: row.name,
    declaring_type: row.owner,
  });
  yield;
  const fields = (yield* readNamed(tables, "fields", 8 + T, ranges.fields)).map(
    owned,
  );
  const properties = (yield* readNamed(
    tables,
    "properties",
    20,
    ranges.properties,
  )).map(owned);
  const events = (yield* readNamed(
    tables,
    "events",
    20 + T,
    ranges.events,
  )).map(owned);
  const parameterRanges = methodParameterRanges(tables, methodTotal);
  yield;
  const parameters = (yield* readNamed(
    tables,
    "parameters",
    8 + T,
    parameterRanges,
  )).map((row) => ({ name: row.name, method: row.owner }));
  return {
    fields,
    properties,
    events,
    parameters,
    string_literals: yield* readStringLiterals(tables),
  };
}
