import type { JsonValue } from "../../domain/jsonValue.js";

/** Version of the store layout, key derivation, and manifest schema. */
export const GHIDRA_PROJECT_CACHE_SCHEMA_VERSION = 1;

/** Fixed Ghidra project name REA's headless open selects. */
export const GHIDRA_PROJECT_NAME = "rea-project";

/** Expanded-project marker file and data directory admitted by the store. */
export const GHIDRA_PROJECT_MARKER_FILE = `${GHIDRA_PROJECT_NAME}.gpr`;
export const GHIDRA_PROJECT_DATA_DIRECTORY = `${GHIDRA_PROJECT_NAME}.rep`;

/** Manifest file written beside each stored project. */
export const GHIDRA_PROJECT_MANIFEST_FILE = "manifest.json";

/** Subdirectories of the cache root. Kept free of a leading dot. */
export const GHIDRA_PROJECT_LOCK_DIRECTORY = "locks";
export const GHIDRA_PROJECT_STAGING_DIRECTORY = "staging";
export const GHIDRA_PROJECT_LEASE_DIRECTORY = "leases";

/**
 * Subdirectory of the cache root that holds the copies a root rebuild makes
 * before it publishes them.
 *
 * The copies are not stored entries: a stored entry is named by its digest,
 * so the store never counts them and the rebuild owns them instead.
 */
export const GHIDRA_PROJECT_REPAIR_STAGING_DIRECTORY = "repair-staging";

/** Immutable identity inputs used to derive a cache key. */
export interface GhidraProjectCacheIdentity {
  readonly providerId: string;
  readonly providerVersion: string;
  readonly jvmVmName: string;
  readonly platform: NodeJS.Platform;
  readonly targetSha256: string;
  readonly importProfileDigest: string;
}

/** Why a cache entry could not be read, trusted, or published. */
export type GhidraProjectCacheFailureReason =
  | "layout"
  | "manifest"
  | "identity"
  | "expired"
  | "io"
  | "busy"
  | "capacity"
  | "disabled";

/**
 * Expected store failure. Carries the reason and the affected path so a caller
 * can project it into Evidence without reinterpreting an error message. It
 * extends `Error` (not `AnalysisError`) to keep the store provider-independent.
 */
export class GhidraProjectCacheError extends Error {
  readonly _tag = "GhidraProjectCacheError";

  constructor(
    readonly reason: GhidraProjectCacheFailureReason,
    message: string,
    readonly path?: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "GhidraProjectCacheError";
  }

  /** Caller-safe facts retained through a provider projection. */
  get diagnostics(): Readonly<Record<string, JsonValue>> {
    return {
      reason: this.reason,
      ...(this.path === undefined ? {} : { path: this.path }),
    };
  }
}
