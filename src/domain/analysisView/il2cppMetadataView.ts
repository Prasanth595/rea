import { z } from "zod";
import { analysisViewInputError } from "./analysisViewErrors.js";
import type { AnalysisError } from "../analysisErrorBase.js";
import type { JsonValue } from "../jsonValue.js";
import { isImmutableJsonSnapshot } from "../immutableJson.js";
import {
  il2cppMetadataImageSchema,
  il2cppMetadataMemberSchema,
  il2cppMetadataMethodSchema,
  il2cppMetadataSectionSchema,
  il2cppMetadataParameterSchema,
  il2cppMetadataStringLiteralSchema,
  il2cppMethodAddressSchema,
  il2cppTypeReferenceSchema,
  il2cppMetadataObjectSchema,
  il2cppMetadataSchema,
  il2cppMetadataTypeSchema,
} from "../il2cpp/il2cppMetadata.js";
import { err, ok, type Result } from "../result.js";
import { parseAnalysisViewResult } from "./analysisViewParent.js";
import type {
  AnalysisViewParent,
  AnalysisViewRequest,
  UnsignedAnalysisView,
} from "./analysisView.js";
import {
  completeWithinViewCoverage,
  pageViewCoverage,
} from "./analysisViewCoverage.js";

const countsSchema = z.strictObject({
  sections: z.number().int().nonnegative(),
  images: z.number().int().nonnegative(),
  types: z.number().int().nonnegative(),
  methods: z.number().int().nonnegative(),
  nested_types: z.number().int().nonnegative(),
  fields: z.number().int().nonnegative(),
  properties: z.number().int().nonnegative(),
  events: z.number().int().nonnegative(),
  parameters: z.number().int().nonnegative(),
  string_literals: z.number().int().nonnegative(),
  method_addresses: z.number().int().nonnegative(),
  /** method_addresses rows per state; all zero without a linked binary. */
  method_address_states: z.strictObject({
    code: z.number().int().nonnegative(),
    no_body: z.number().int().nonnegative(),
    unknown: z.number().int().nonnegative(),
  }),
  return_types: z.number().int().nonnegative(),
  field_types: z.number().int().nonnegative(),
  parameter_types: z.number().int().nonnegative(),
});

export const il2cppMetadataSummarySchema = il2cppMetadataObjectSchema
  .omit({
    sections: true,
    images: true,
    types: true,
    methods: true,
    fields: true,
    properties: true,
    events: true,
    parameters: true,
    string_literals: true,
    method_addresses: true,
    return_types: true,
    field_types: true,
    parameter_types: true,
  })
  .extend({ counts: countsSchema });

const indexSchema = z.number().int().nonnegative();
const sectionRowSchema = il2cppMetadataSectionSchema.extend({
  index: indexSchema,
});
const imageRowSchema = il2cppMetadataImageSchema.extend({ index: indexSchema });
const typeRowSchema = il2cppMetadataTypeSchema.extend({ index: indexSchema });
const methodRowSchema = il2cppMetadataMethodSchema.extend({
  index: indexSchema,
});
const memberRowSchema = il2cppMetadataMemberSchema.extend({
  index: indexSchema,
});
const parameterRowSchema = il2cppMetadataParameterSchema.extend({
  index: indexSchema,
});
const stringLiteralRowSchema = il2cppMetadataStringLiteralSchema.extend({
  index: indexSchema,
});
const methodAddressRowSchema = il2cppMethodAddressSchema.extend({
  index: indexSchema,
});
const typeReferenceRowSchema = il2cppTypeReferenceSchema.extend({
  index: indexSchema,
});
const indexPage = {
  kind: z.literal("il2cpp-metadata"),
  indices: z.array(indexSchema).optional(),
  offset: indexSchema.default(0),
  limit: z.number().int().positive().default(64),
};
const page = { ...indexPage, names: z.array(z.string()).optional() };
const declaringTypes = z.array(z.number().int().min(-1)).optional();

/** Filters intersect; pages use metadata order and always retain the source row index. */
export const il2cppMetadataViewRequestSchema = z.discriminatedUnion(
  "collection",
  [
    z.strictObject({
      ...page,
      collection: z.literal("sections"),
      fields: z.array(sectionRowSchema.keyof()).optional(),
    }),
    z.strictObject({
      ...page,
      collection: z.literal("images"),
      fields: z.array(imageRowSchema.keyof()).optional(),
    }),
    z.strictObject({
      ...page,
      collection: z.literal("types"),
      image_indices: z.array(indexSchema).optional(),
      namespaces: z.array(z.string()).optional(),
      declaring_types: declaringTypes,
      fields: z.array(typeRowSchema.keyof()).optional(),
    }),
    z.strictObject({
      ...page,
      collection: z.literal("methods"),
      declaring_types: declaringTypes,
      fields: z.array(methodRowSchema.keyof()).optional(),
    }),
    ...(["fields", "properties", "events"] as const).map((collection) =>
      z.strictObject({
        ...page,
        collection: z.literal(collection),
        declaring_types: declaringTypes,
        fields: z.array(memberRowSchema.keyof()).optional(),
      }),
    ),
    z.strictObject({
      ...page,
      collection: z.literal("parameters"),
      fields: z.array(parameterRowSchema.keyof()).optional(),
    }),
    z.strictObject({
      ...indexPage,
      collection: z.literal("string_literals"),
      fields: z.array(stringLiteralRowSchema.keyof()).optional(),
    }),
    z.strictObject({
      ...indexPage,
      collection: z.literal("method_addresses"),
      fields: z.array(methodAddressRowSchema.keyof()).optional(),
    }),
    ...(["return_types", "field_types", "parameter_types"] as const).map(
      (collection) =>
        z.strictObject({
          ...indexPage,
          collection: z.literal(collection),
          fields: z.array(typeReferenceRowSchema.keyof()).optional(),
        }),
    ),
  ],
);

export const il2cppMetadataViewItemsSchema = z.union([
  z.array(sectionRowSchema.partial().required({ index: true })),
  z.array(imageRowSchema.partial().required({ index: true })),
  z.array(typeRowSchema.partial().required({ index: true })),
  z.array(methodRowSchema.partial().required({ index: true })),
  z.array(memberRowSchema.partial().required({ index: true })),
  z.array(parameterRowSchema.partial().required({ index: true })),
  z.array(stringLiteralRowSchema.partial().required({ index: true })),
  z.array(methodAddressRowSchema.partial().required({ index: true })),
  z.array(typeReferenceRowSchema.partial().required({ index: true })),
]);

export const il2cppMetadataViewContextSchema = z.strictObject({
  metadata_version: il2cppMetadataObjectSchema.shape.metadata_version,
  counts: countsSchema,
});

type Report = z.infer<typeof il2cppMetadataSchema>;
type Request = z.infer<typeof il2cppMetadataViewRequestSchema>;
type Row = Report[Request["collection"]][number];
interface CheckedReport {
  readonly report: Report;
  readonly counts: z.infer<typeof countsSchema>;
}

// Authenticated, frozen parents own these facts. Cache validation/counts for
// their lifetime without a second report copy or a live filesystem cache.
const checkedReports = new WeakMap<object, CheckedReport>();

const parseMetadataReport = (
  parent: AnalysisViewParent,
): Result<CheckedReport, AnalysisError> => {
  const key = parent.normalizedResult;
  const reusable =
    parent.sealedResult === true &&
    typeof key === "object" &&
    key !== null &&
    isImmutableJsonSnapshot(key);
  const cached = reusable ? checkedReports.get(key) : undefined;
  if (cached !== undefined) return ok(cached);
  const parsed = parseAnalysisViewResult(il2cppMetadataSchema, parent);
  if (!parsed.ok) return parsed;
  // This schema has no coercions/transforms; the authenticated owner value is
  // equivalent to the validated clone and remains immutable across pages.
  const report = reusable ? (key as Report) : parsed.value;
  const checked = {
    report,
    counts: {
      sections: report.sections.length,
      images: report.images.length,
      types: report.types.length,
      methods: report.methods.length,
      nested_types: report.types.reduce(
        (count, type) => count + Number(type.declaring_type !== -1),
        0,
      ),
      fields: report.fields.length,
      properties: report.properties.length,
      events: report.events.length,
      parameters: report.parameters.length,
      string_literals: report.string_literals.length,
      method_addresses: report.method_addresses.length,
      method_address_states: report.method_addresses.reduce(
        (states, row) => {
          if (row.state === "code") states.code++;
          else if (row.state === "no-body") states.no_body++;
          else states.unknown++;
          return states;
        },
        { code: 0, no_body: 0, unknown: 0 },
      ),
      return_types: report.return_types.length,
      field_types: report.field_types.length,
      parameter_types: report.parameter_types.length,
    },
  };
  if (reusable) checkedReports.set(key, checked);
  return ok(checked);
};

/** Direct batch lookup visits selected indices only; metadata order is stable. */
function* rowIndices(length: number, indices: number[] | undefined) {
  if (indices === undefined) {
    for (let index = 0; index < length; index++) yield index;
  } else {
    for (const index of [...new Set(indices)].sort((a, b) => a - b))
      if (index < length) yield index;
  }
}

const selectFields = (
  row: Row,
  index: number,
  fields: Set<string> | undefined,
) => {
  const item: { index: number } & Record<string, JsonValue> = { index };
  const values: Readonly<Record<string, JsonValue>> = row;
  for (const key of Object.keys(values)) {
    const value = values[key];
    if (value !== undefined && (fields === undefined || fields.has(key)))
      item[key] = value;
  }
  return item;
};

/** Compile caller selections once; large batches do not multiply per-row work. */
const selection = (view: Request, report: Report) => {
  const names =
    !("names" in view) || view.names === undefined
      ? undefined
      : new Set(view.names);
  const owners =
    !("declaring_types" in view) || view.declaring_types === undefined
      ? undefined
      : new Set(view.declaring_types);
  const namespaces =
    view.collection !== "types" || view.namespaces === undefined
      ? undefined
      : new Set(view.namespaces);
  const imageIndices =
    view.collection === "types" ? view.image_indices : undefined;
  const ranges: { start: number; end: number }[] = [];
  if (imageIndices !== undefined) {
    const selected = [...new Set(imageIndices)]
      .flatMap((index) => {
        const image = report.images[index];
        return image === undefined || image.type_count === 0
          ? []
          : [
              {
                start: image.type_start,
                end: image.type_start + image.type_count,
              },
            ];
      })
      .sort((a, b) => a.start - b.start);
    for (const range of selected) {
      const last = ranges.at(-1);
      if (last !== undefined && range.start <= last.end)
        last.end = Math.max(last.end, range.end);
      else ranges.push(range);
    }
  }
  return (row: Row, index: number) => {
    if (
      names !== undefined &&
      (!("name" in row) || row.name === null || !names.has(row.name))
    )
      return false;
    if (
      owners !== undefined &&
      (!("declaring_type" in row) || !owners.has(row.declaring_type))
    )
      return false;
    if (
      namespaces !== undefined &&
      (!("namespace" in row) || !namespaces.has(row.namespace))
    )
      return false;
    if (imageIndices === undefined) return true;
    let lower = 0;
    let upper = ranges.length;
    while (lower < upper) {
      const middle = lower + Math.floor((upper - lower) / 2);
      if (ranges[middle]!.start <= index) lower = middle + 1;
      else upper = middle;
    }
    const range = ranges[lower - 1];
    return range !== undefined && index < range.end;
  };
};

/** Reuse retained facts; source indices stay distinct from filtered page offsets. */
export const projectIl2cppMetadataView = (
  parent: AnalysisViewParent,
  view: AnalysisViewRequest,
): Result<UnsignedAnalysisView, AnalysisError> => {
  if (view.kind !== "summary" && view.kind !== "il2cpp-metadata")
    return err(
      analysisViewInputError([
        {
          path: ["view"],
          reason: "invalid_value",
          message:
            "IL2CPP metadata Evidence supports summary and selected sections, images, types, methods, member, parameter, string literal, method address and type reference pages.",
        },
      ]),
    );
  const parsed = parseMetadataReport(parent);
  if (!parsed.ok) return parsed;
  const { report, counts } = parsed.value;
  if (
    parent.subject != null &&
    (parent.subject.format !== "file" ||
      parent.subject.local_path !== report.artifact.path ||
      parent.subject.digest.sha256 !== report.artifact.sha256)
  )
    return err(
      analysisViewInputError([
        {
          path: ["source", "subject"],
          reason: "invalid_value",
          message:
            "IL2CPP metadata artifact identity does not match its parent subject.",
        },
      ]),
    );
  const {
    sections,
    images,
    types,
    methods,
    fields,
    properties,
    events,
    parameters,
    string_literals,
    method_addresses,
    return_types,
    field_types,
    parameter_types,
    ...identity
  } = report;
  const allRows = {
    sections,
    images,
    types,
    methods,
    fields,
    properties,
    events,
    parameters,
    string_literals,
    method_addresses,
    return_types,
    field_types,
    parameter_types,
  };
  const shared = {
    parent_evidence_id: parent.evidenceId,
    parent_operation: "inspect_il2cpp_metadata" as const,
    parent_digest: parent.evidenceId.slice(3),
    artifact: { path: report.artifact.path, sha256: report.artifact.sha256 },
    limitations: [...parent.limitations],
    unknowns: [
      identity.binary === null
        ? "Names come from unencrypted metadata only; native code addresses and runtime registration remain unknown."
        : "Addresses come from static binary tables; runtime behavior and generic instance code remain unknown.",
      ...(parent.subject == null
        ? [
            "The parent has no recorded subject; its normalized artifact identity cannot be cross-checked against a subject digest.",
          ]
        : []),
    ],
  };
  if (view.kind === "summary")
    return ok({
      kind: "summary",
      view,
      ...shared,
      summary: { ...identity, counts },
      coverage: completeWithinViewCoverage(1, 1),
    });
  const rows = allRows[view.collection];
  const matches = selection(view, report);
  const selectedFields =
    view.fields === undefined ? undefined : new Set<string>(view.fields);
  const items = [];
  let total = 0;
  for (const index of rowIndices(rows.length, view.indices)) {
    const row = rows[index]!;
    if (!matches(row, index)) continue;
    if (total >= view.offset && items.length < view.limit)
      items.push(selectFields(row, index, selectedFields));
    total++;
  }
  return ok({
    kind: "il2cpp-metadata",
    view,
    ...shared,
    items,
    metadata_version: report.metadata_version,
    counts,
    coverage: pageViewCoverage(view.offset, items.length, total),
  });
};
