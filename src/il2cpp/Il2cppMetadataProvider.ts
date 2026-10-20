import { setImmediate } from "node:timers/promises";
import {
  readStableArtifact,
  type StableArtifactSnapshot,
} from "../artifacts/readStableArtifact.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import {
  ArtifactFileCleanupFailure,
  ArtifactFileCancelled,
  bindArtifactFileCleanup,
  artifactFileCancellationCause,
  assertArtifactReadActive,
} from "../artifacts/ArtifactFileOperation.js";
import { analysisErrorWithCleanupFailure } from "../domain/analysisErrorCleanup.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";
import type { Il2cppMetadataPort } from "../application/il2cpp/Il2cppMetadataPort.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { createEvidence } from "../domain/evidence.js";
import { jsonStringByteLength } from "../domain/jsonStringByteLength.js";
import { jsonValueByteLength } from "../domain/jsonValueByteLength.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../domain/analysisErrorCore.js";
import {
  il2cppMetadataSchema,
  type Il2cppMetadata,
  type Il2cppMetadataProviderInput,
} from "../domain/il2cpp/il2cppMetadata.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  Il2cppMetadataFormatFailure,
  readIl2cppMetadataForLinkingSteps,
  type Il2cppMetadataDecoded,
  type Il2cppMetadataRowCounts,
} from "./Il2cppMetadataFile.js";
import {
  Il2cppBinaryFormatFailure,
  linkIl2cppBinarySteps,
  type Il2cppBinaryLink,
} from "./Il2cppBinaryFile.js";

/** Bundled format reader identity; the metadata version is a separate observed fact. */
export const IL2CPP_METADATA_PROVIDER_IDENTITY = {
  id: "il2cpp-metadata",
  name: "REA IL2CPP global-metadata reader",
  version: "1",
} as const;
const OPERATION = "inspect_il2cpp_metadata";
const INPUT_BYTES = 256 * 1024 * 1024;
// GameAssembly binaries of large games reach several hundred megabytes.
const BINARY_BYTES = 1024 * 1024 * 1024;
// A 12.9 MB Unity 6000.4 file with 112,232 methods serializes to 7.8 MB.
const OUTPUT_BYTES = 64 * 1024 * 1024;
// The smallest JSON a row can take: empty names and one-digit numbers.
const EMPTY_NAME = JSON.stringify("").length;

/** JSON characters of one row besides its strings, with one-digit numbers. */
const rowOverhead = (row: Record<string, string | number>) =>
  JSON.stringify(row).length -
  2 * Object.values(row).filter((value) => typeof value === "string").length;
const IMAGE_ROW = rowOverhead({ name: "", type_start: 0, type_count: 0 });
const TYPE_ROW = rowOverhead({
  name: "",
  namespace: "",
  method_start: 0,
  method_count: 0,
  nested_type_start: 0,
  nested_type_count: 0,
  declaring_type: 0,
});
const METHOD_ROW = rowOverhead({ name: "", declaring_type: 0 });
const MEMBER_ROW = METHOD_ROW;
const PARAMETER_ROW = rowOverhead({ name: "", method: 0 });
// Literals carry `null` for the unused form instead of a string.
const LITERAL_ROW =
  JSON.stringify({ value: null, value_base64: null }).length - 4;
// The shortest state with both address fields null.
const ADDRESS_ROW = JSON.stringify({
  state: "code",
  address: null,
  rva: null,
}).length;
// Each method, field and parameter gains a type reference row.
const TYPE_ROW_BOUND = JSON.stringify({ type: 0, name: null }).length;

/**
 * A lower bound on the serialized rows. Rows share decoded names, so the
 * report can be far larger than the file; refusing from this bound avoids
 * building a string the budget would reject anyway. Once the bound passes
 * `limit` it returns early, so no single name is escaped past the budget.
 */
const serializedRowsLowerBound = (
  decoded: Il2cppMetadataDecoded,
  limit: number,
  linked: boolean,
) => {
  const lengths = new Map<string, number>();
  let total = 0;
  const text = (value: string) => {
    let length = lengths.get(value);
    if (length === undefined) {
      // UTF-8 bytes, the unit the final report budget is checked in.
      length = jsonStringByteLength(value, limit - total);
      lengths.set(value, length);
    }
    return length;
  };
  for (const image of decoded.images) {
    total += IMAGE_ROW + text(image.name);
    if (total > limit) return total;
  }
  for (const type of decoded.types) {
    total += TYPE_ROW + text(type.name) + text(type.namespace);
    if (total > limit) return total;
  }
  for (const method of decoded.methods) {
    total += METHOD_ROW + text(method.name);
    if (total > limit) return total;
  }
  for (const members of [decoded.fields, decoded.properties, decoded.events])
    for (const member of members) {
      total += MEMBER_ROW + text(member.name);
      if (total > limit) return total;
    }
  for (const parameter of decoded.parameters) {
    total += PARAMETER_ROW + text(parameter.name);
    if (total > limit) return total;
  }
  for (const literal of decoded.string_literals) {
    total += LITERAL_ROW + text(literal.value ?? literal.value_base64 ?? "");
    if (total > limit) return total;
  }
  if (linked)
    total +=
      decoded.methods.length * (ADDRESS_ROW + TYPE_ROW_BOUND) +
      (decoded.fields.length + decoded.parameters.length) * TYPE_ROW_BOUND;
  return total;
};

const failureForPrimary = (
  cause: unknown,
  path: string,
  signal?: AbortSignal,
  field: "path" | "binary_path" = "path",
  maximum = INPUT_BYTES,
): AnalysisError => {
  if (cause instanceof AnalysisError) return cause;
  if (cause instanceof Il2cppBinaryFormatFailure)
    return cause.kind === "unsupported"
      ? new AnalysisUnsupportedTargetError(OPERATION, path, cause.message, {
          cause,
        })
      : new AnalysisInputError(OPERATION, { cause }, [
          {
            path: [field],
            reason: "invalid_format",
            message: `Selected binary ${path} does not link to the metadata: ${cause.message}`,
          },
        ]);
  if (cause instanceof ArtifactReaderFailure && cause.reason === "integrity")
    return new AnalysisArtifactChangedError(OPERATION, path, cause.message, {
      cause,
    });
  if (cause instanceof ArtifactReaderFailure && cause.reason === "cancelled")
    return new AnalysisCancelledError(OPERATION, {
      cause: artifactFileCancellationCause(cause),
    });
  if (cause instanceof Il2cppMetadataFormatFailure)
    return cause.kind === "unsupported"
      ? new AnalysisUnsupportedTargetError(OPERATION, path, cause.message, {
          cause,
        })
      : new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: `Selected artifact ${path} is corrupt: ${cause.message}`,
          },
        ]);
  if (cause instanceof ArtifactReaderFailure) {
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        OPERATION,
        "file-size",
        cause.message,
        { maximum_input_bytes: maximum },
        { cause },
      );
    if (cause.reason === "path")
      return new AnalysisInputError(OPERATION, { cause }, [
        { path: [field], reason: "invalid_format", message: cause.message },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, path, cause.code, {
        cause,
      });
    if (
      ["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(
        String(cause.code),
      )
    )
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: [field],
          reason: "invalid_value",
          message: `Selected artifact could not be read (${String(cause.code)}): ${path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(
    IL2CPP_METADATA_PROVIDER_IDENTITY.id,
    OPERATION,
    {
      cause,
      diagnostics: {
        path,
        reason: cause instanceof Error ? cause.message : String(cause),
      },
    },
  );
};

const failureFor = (
  cause: unknown,
  path: string,
  signal?: AbortSignal,
  field: "path" | "binary_path" = "path",
  maximum = INPUT_BYTES,
): AnalysisError => {
  const primary =
    cause instanceof ArtifactFileCleanupFailure &&
    cause.fileCleanupFailure.outcome.kind === "failed"
      ? failureForPrimary(
          cause.fileCleanupFailure.outcome.cause,
          path,
          signal,
          field,
          maximum,
        )
      : cause instanceof ArtifactFileCleanupFailure && signal?.aborted
        ? new AnalysisCancelledError(OPERATION, { cause: signal.reason })
        : failureForPrimary(cause, path, signal, field, maximum);
  if (
    cause instanceof ArtifactReaderFailure &&
    cause.partialObservation !== undefined &&
    primary.partialObservation === undefined
  )
    primary.retainPartialObservation(cause.partialObservation);
  if (!(cause instanceof ArtifactReaderFailure) || cause.cleanup === undefined)
    return primary;
  const cleanup = new ProviderCleanupError(
    IL2CPP_METADATA_PROVIDER_IDENTITY.id,
    cause.cleanup.resources,
    { reason: cause.cleanup.reason },
    { operation: OPERATION, cause },
  );
  const error = analysisErrorWithCleanupFailure(primary, cleanup, OPERATION);
  bindArtifactFileCleanup(cause, error);
  return error;
};

const hex = (value: bigint) => `0x${value.toString(16)}`;

/** Report fields for a linked binary, with addresses as exact hexadecimal strings. */
const binaryReport = (
  link: Il2cppBinaryLink,
  artifact: { path: string; sha256: string; bytes: number },
) => ({
  binary: {
    artifact,
    format: link.format,
    architecture: link.architecture,
    image_base: hex(link.image_base),
    code_gen_modules_field:
      link.code_gen_modules_field === null
        ? null
        : hex(link.code_gen_modules_field),
    code_gen_modules_array: hex(link.code_gen_modules_array),
    code_gen_modules: link.code_gen_modules.map((module) => ({
      image: module.image,
      address: hex(module.address),
      method_pointer_count: module.method_pointer_count,
    })),
    types_field: hex(link.types_field),
    types_count: link.types_count,
  },
  return_types: [...link.return_types],
  field_types: [...link.field_types],
  parameter_types: [...link.parameter_types],
  method_addresses: link.method_addresses.map((address) =>
    typeof address === "bigint"
      ? {
          state: "code" as const,
          address: hex(address),
          rva: hex(address - link.image_base),
        }
      : { state: address, address: null, rva: null },
  ),
});

const reportLimit = (path: string, maximumBytes: number) =>
  new AnalysisResourceConstraintError(
    OPERATION,
    "memory",
    `Complete IL2CPP metadata for ${path} exceeds the retained report budget; no complete inventory is retained.`,
    { maximum_report_bytes: maximumBytes },
  );

/** Lower bound from row counts alone, so oversized files fail before rows are allocated. */
const countLowerBound = ({ images, types, methods }: Il2cppMetadataRowCounts) =>
  images * (IMAGE_ROW + EMPTY_NAME) +
  types * (TYPE_ROW + 2 * EMPTY_NAME) +
  methods * (METHOD_ROW + EMPTY_NAME);

const sourceArtifact = (path: string, snapshot: StableArtifactSnapshot) => ({
  path,
  sha256: snapshot.sha256,
  bytes: snapshot.bytes.length,
});

/** Source identity survives a failed inventory without claiming decoded coverage. */
const metadataSourceEvidence = (
  artifact: Il2cppMetadata["artifact"],
  counts: Il2cppMetadataRowCounts | undefined,
) =>
  createEvidence(
    {
      path: artifact.path,
      sha256: artifact.sha256,
      format: "file",
    },
    IL2CPP_METADATA_PROVIDER_IDENTITY,
    {
      operation: "observe_il2cpp_metadata_source",
      predicateType: "rea.il2cpp-metadata-source",
      parameters: { path: artifact.path },
      result: {
        artifact,
        inventory_status: "not-returned-as-complete",
        ...(counts === undefined
          ? {}
          : { validated_section_row_counts: { ...counts } }),
      },
      confidence: "observed",
      limitations: [
        "This partial source observation does not contain a complete metadata inventory. Section row counts, when available, are derived from the validated header extents and record layout; names and relationships may remain unexamined.",
      ],
      locations: [
        { kind: "artifact-path", path: artifact.path },
        {
          kind: "file-offset-range",
          start: 0,
          end: artifact.bytes,
        },
      ],
    },
  );

/** Stable in-process decoding without subprocesses, temporary files, native binaries or decryption. */
export class Il2cppMetadataProvider implements Il2cppMetadataPort {
  readonly identity = IL2CPP_METADATA_PROVIDER_IDENTITY;
  readonly #resources = new ArtifactResourceScope();
  #inspecting = false;

  /** `outputBytes` exists so tests can reach the guard with small files. */
  constructor(
    private readonly outputBytes: number = OUTPUT_BYTES,
    private readonly yieldControl: () => Promise<void> = setImmediate,
  ) {}

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      if (
        !(cause instanceof ArtifactReaderFailure) ||
        cause.cleanup === undefined
      )
        throw cause;
      const error = new ProviderCleanupError(
        IL2CPP_METADATA_PROVIDER_IDENTITY.id,
        cause.cleanup.resources,
        { reason: cause.cleanup.reason },
        { cause, operation: OPERATION },
      );
      bindArtifactFileCleanup(cause, error);
      throw error;
    }
  }

  /** Read every image, type and method name from one stable file snapshot. */
  async inspect(
    input: Il2cppMetadataProviderInput,
    options?: ExecutionOptions,
  ): Promise<Result<Il2cppMetadata, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(
        new AnalysisCancelledError(OPERATION, { cause: options.signal.reason }),
      );
    if (this.#inspecting)
      return err(
        new AnalysisResourceConstraintError(
          OPERATION,
          "memory",
          "Only one IL2CPP metadata inspection is admitted per reader.",
          { maximum_concurrent_inspections: 1 },
        ),
      );
    this.#inspecting = true;
    const observed: {
      artifact?: Il2cppMetadata["artifact"];
      counts?: Il2cppMetadataRowCounts;
    } = {};
    try {
      return await this.#resources.run(async () => {
        const snapshot = await readStableArtifact(
          input.path,
          INPUT_BYTES,
          options?.signal,
          undefined,
          this.#resources,
        ).catch((cause: unknown) => {
          // Only this awaited stable read owns these typed physical outcomes.
          const outcome =
            cause instanceof ArtifactFileCleanupFailure
              ? (cause as ArtifactFileCleanupFailure<StableArtifactSnapshot>)
                  .fileCleanupFailure.outcome
              : cause instanceof ArtifactFileCancelled
                ? (cause as ArtifactFileCancelled<StableArtifactSnapshot>)
                    .fileCancellation.outcome
                : undefined;
          if (outcome?.kind === "completed")
            observed.artifact = sourceArtifact(input.path, outcome.value);
          throw cause;
        });
        const artifact = sourceArtifact(input.path, snapshot);
        observed.artifact = artifact;
        assertArtifactReadActive(options?.signal);
        const limit = this.outputBytes;
        const steps = readIl2cppMetadataForLinkingSteps(snapshot.bytes, {
          beforeRows: (counts) => {
            observed.counts = counts;
            if (countLowerBound(counts) > limit)
              throw reportLimit(input.path, limit);
          },
        });
        let step = steps.next();
        while (!step.done) {
          await this.yieldControl();
          assertArtifactReadActive(options?.signal);
          step = steps.next();
        }
        const { metadata: decoded, link } = step.value;
        const binaryPath = input.binary_path;
        if (
          serializedRowsLowerBound(decoded, limit, binaryPath !== undefined) >
          limit
        )
          throw reportLimit(input.path, limit);
        let linked: Pick<
          Il2cppMetadata,
          | "binary"
          | "method_addresses"
          | "return_types"
          | "field_types"
          | "parameter_types"
        > = {
          binary: null,
          method_addresses: [],
          return_types: [],
          field_types: [],
          parameter_types: [],
        };
        if (binaryPath !== undefined) {
          try {
            const binary = await readStableArtifact(
              binaryPath,
              BINARY_BYTES,
              options?.signal,
              undefined,
              this.#resources,
            );
            assertArtifactReadActive(options?.signal);
            const linking = linkIl2cppBinarySteps(
              binary.bytes,
              decoded,
              link,
              input.binary_architecture,
            );
            let linkStep = linking.next();
            while (!linkStep.done) {
              await this.yieldControl();
              assertArtifactReadActive(options?.signal);
              linkStep = linking.next();
            }
            linked = binaryReport(linkStep.value, {
              path: binaryPath,
              sha256: binary.sha256,
              bytes: binary.bytes.length,
            });
          } catch (cause: unknown) {
            const failure = failureFor(
              cause,
              binaryPath,
              options?.signal,
              "binary_path",
              BINARY_BYTES,
            );
            // The metadata itself was read; keep its source identity.
            if (failure.partialObservation === undefined)
              failure.retainPartialObservation(
                metadataSourceEvidence(artifact, observed.counts),
              );
            return err(failure);
          }
        }
        const report = {
          ...decoded,
          ...linked,
          artifact,
          limitations: [
            "Only unencrypted global-metadata.dat versions 24, 27, 29, 31 and 39 are decoded; names, counts and string literals are observed file content, not runtime behavior.",
            binaryPath === undefined
              ? "Native code addresses and IL2CPP binary registration are not recovered without binary_path."
              : "Method addresses come from the binary's code-generation module methodPointers, matched by module name, method count and metadata token; generic method instances, adjustor thunks and invokers are not linked, and a null address means the module records no body.",
            binaryPath === undefined
              ? "Field, parameter and return types are not recovered without binary_path; type indices refer to the native binary."
              : decoded.metadata_version === 27
                ? "Field, parameter and return type names are null for metadata version 27: versions 27.0 to 27.2 share that header number but place the Il2CppType byref flag differently, so a name could gain or lose & without warning; type indices are still reported."
                : "Field, parameter and return type names are rendered from the binary's Il2CppType table in a C#-like form (keywords for primitives, Namespace.Outer+Inner, generic parameters by metadata name); custom modifiers, array bounds and attributes are not reported.",
            ...(linked.binary !== null &&
            linked.binary.code_gen_modules_field === null
              ? [
                  "This binary keeps no static CodeRegistration, so the module array (code_gen_modules_array) was derived from the single x86-64 instruction that loads it, not read from a registration structure; the module records and method pointers themselves are read from the binary.",
                ]
              : []),
            "declaring_type for types is derived from the nestedTypes section, and member and parameter owners from the owners' index ranges; row positions are the metadata indices.",
          ],
        };
        if (jsonValueByteLength(report, limit) > limit)
          throw reportLimit(input.path, limit);
        const parsed = il2cppMetadataSchema.safeParse(report);
        if (!parsed.success)
          throw new AnalysisOutputError(
            OPERATION,
            "IL2CPP metadata reader produced invalid section ranges or report values.",
            { cause: parsed.error },
          );
        assertArtifactReadActive(options?.signal);
        return ok(parsed.data);
      });
    } catch (cause: unknown) {
      const failure = failureFor(cause, input.path);
      if (
        observed.artifact !== undefined &&
        failure.partialObservation === undefined
      )
        failure.retainPartialObservation(
          metadataSourceEvidence(observed.artifact, observed.counts),
        );
      return err(failure);
    } finally {
      this.#inspecting = false;
    }
  }
}
