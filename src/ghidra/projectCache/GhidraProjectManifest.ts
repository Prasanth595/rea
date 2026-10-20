import { isAbsolute } from "node:path";

import canonicalize from "canonicalize";
import { z } from "zod";

import { digestSchema } from "../../domain/digests.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
  type GhidraProjectCacheError,
  GhidraProjectCacheError as CacheError,
} from "./GhidraProjectCacheTypes.js";

const relativeProjectPathSchema = z
  .string()
  .min(1)
  .refine(
    (path) => !isAbsolute(path) && !path.split(/[\\/]/u).includes(".."),
    "must be a relative path without parent traversal",
  );

/** Target facts that bind a manifest to the analyzed executable. */
export const ghidraProjectManifestTargetSchema = z.strictObject({
  sha256: digestSchema,
  kind: z.string().min(1),
  format: z.string().min(1),
  architecture: z.string().min(1).nullable(),
  executable_role: z.string().min(1).nullable(),
});

export type GhidraProjectManifestTarget = z.infer<
  typeof ghidraProjectManifestTargetSchema
>;

/** One regular file copied into the stored project. */
export const ghidraProjectFileRecordSchema = z.strictObject({
  path: relativeProjectPathSchema,
  bytes: z.number().int().nonnegative(),
  sha256: digestSchema,
});

export type GhidraProjectFileRecord = z.infer<
  typeof ghidraProjectFileRecordSchema
>;

/** Canonical record of one stored, previously analyzed Ghidra program. */
export const ghidraProjectManifestSchema = z.strictObject({
  schema_version: z.literal(GHIDRA_PROJECT_CACHE_SCHEMA_VERSION),
  key: digestSchema,
  provider: z.strictObject({
    id: z.string().min(1),
    version: z.string().min(1),
  }),
  jvm: z.strictObject({ vm_name: z.string().min(1) }),
  platform: z.string().min(1),
  target: ghidraProjectManifestTargetSchema,
  import_profile_digest: digestSchema,
  program_name: z.string().min(1),
  program_sha256: digestSchema,
  project_files: z.array(ghidraProjectFileRecordSchema).min(1),
  project_digest: digestSchema,
  created_at: z.string().min(1),
  last_used_at: z.string().min(1),
  size_bytes: z.number().int().nonnegative(),
  producer: z.strictObject({
    rea_version: z.string().min(1),
    run_id: z.string().min(1),
  }),
});

export type GhidraProjectManifest = z.infer<typeof ghidraProjectManifestSchema>;

/** Verify and parse a manifest read from disk. */
export const parseGhidraProjectManifest = (
  value: unknown,
  path?: string,
): Result<GhidraProjectManifest, GhidraProjectCacheError> => {
  const parsed = ghidraProjectManifestSchema.safeParse(value);
  return parsed.success
    ? ok(parsed.data)
    : err(
        new CacheError(
          "manifest",
          "Stored Ghidra project manifest is invalid",
          path,
          { cause: parsed.error },
        ),
      );
};

/** Canonical, byte-stable manifest serialization with a trailing newline. */
export const serializeGhidraProjectManifest = (
  manifest: GhidraProjectManifest,
): string => {
  const encoded = canonicalize(manifest);
  if (encoded === undefined)
    throw new TypeError("Ghidra project manifest is not canonicalizable");
  return `${encoded}\n`;
};

/** Identity fields a manifest commits, for comparison with a requested key. */
export const ghidraProjectManifestIdentity = (
  manifest: GhidraProjectManifest,
): {
  readonly providerId: string;
  readonly providerVersion: string;
  readonly jvmVmName: string;
  readonly platform: NodeJS.Platform;
  readonly targetSha256: string;
  readonly importProfileDigest: string;
} => ({
  providerId: manifest.provider.id,
  providerVersion: manifest.provider.version,
  jvmVmName: manifest.jvm.vm_name,
  platform: manifest.platform as NodeJS.Platform,
  targetSha256: manifest.target.sha256,
  importProfileDigest: manifest.import_profile_digest,
});
