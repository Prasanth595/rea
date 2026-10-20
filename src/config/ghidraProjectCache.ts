import { z } from "zod";
import { isAbsolute, join } from "node:path";

/**
 * Selection for the persistent Ghidra project cache. `off` keeps the current
 * ephemeral import; `read` reuses a cached project when one matches but never
 * populates; `on` reuses and populates. The cache lets a later session reuse
 * analysis that was paid once instead of re-importing and re-analyzing.
 */
export const ghidraProjectCacheModes = ["off", "read", "on"] as const;

export type GhidraProjectCacheMode = (typeof ghidraProjectCacheModes)[number];

/** Default size ceiling for the on-disk project store. */
export const DEFAULT_GHIDRA_PROJECT_CACHE_MAX_BYTES = 10 * 1024 ** 3;

/** Parse the optional cache mode; an absent setting selects `off`. */
export const ghidraProjectCacheModeSchema = z
  .enum(ghidraProjectCacheModes)
  .default("off");

/** Parse the optional absolute cache root. */
export const ghidraProjectCacheDirectorySchema = z
  .string()
  .min(1)
  .refine(isAbsolute, "REA_GHIDRA_PROJECT_CACHE_DIR must be absolute");

/** Parse the optional positive byte ceiling. */
export const ghidraProjectCacheMaxBytesSchema = z
  .string()
  .regex(/^[1-9]\d*$/u, "must be a positive decimal integer")
  .transform(Number)
  .pipe(z.number().int().safe());

/** Parse the optional positive maximum entry age in days. */
export const ghidraProjectCacheMaxAgeDaysSchema = z
  .string()
  .regex(/^[1-9]\d*$/u, "must be a positive decimal integer")
  .transform(Number)
  .pipe(z.number().int().safe());

/** Resolved persistent project cache configuration. */
export interface GhidraProjectCacheConfig {
  readonly mode: GhidraProjectCacheMode;
  readonly directory: string;
  readonly maxBytes: number;
  /** Discard entries older than this many days; unset applies no age limit. */
  readonly maxAgeDays?: number;
}

/**
 * The cache lives under the managed-data root so `rea uninstall --purge-data`,
 * which removes only `<home>/.rea/cache` and `<home>/.rea/state`, also removes
 * it. A top-level `<home>/.rea/ghidra-projects` would survive a purge.
 */
export const defaultGhidraProjectCacheDirectory = (
  homeDirectory: string,
): string => join(homeDirectory, ".rea", "cache", "ghidra-projects");
