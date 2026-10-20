import { z } from "incur";
import type { Logger } from "pino";

import { CLI_COMMANDS } from "../cliCommandNames.js";
import { isCliOperationFailure, logCliCommand } from "../cliLogging.js";
import { parseConfig } from "../config/parseConfig.js";
import type { GhidraProjectCacheConfig } from "../config/ghidraProjectCache.js";
import {
  projectAnalysisError,
  type AnalysisErrorProjection,
} from "../domain/analysisErrorProjection.js";
import type { GhidraProjectCacheError } from "../ghidra/projectCache/GhidraProjectCacheTypes.js";
import { GhidraProjectStore } from "../ghidra/projectCache/GhidraProjectStore.js";
import type { CliInstance } from "./types.js";

/**
 * Inspect and maintain the managed Ghidra project cache. These commands are
 * read-only discovery plus explicit maintenance; they never open a target.
 */
export const registerCacheCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
): void => {
  const configured = parseConfig(environment);
  const resolve = (action: string) =>
    configured.ok
      ? configured.value.ghidraProjectCache
      : { error: action, ...projectAnalysisError(configured.error) };

  cli.command(CLI_COMMANDS.cacheList, {
    description: "List stored Ghidra projects reusable across sessions",
    run: () =>
      logCliCommand(logger, CLI_COMMANDS.cacheList, async () => {
        const resolved = resolve("Cache listing failed");
        return "error" in resolved ? resolved : await listCache(resolved);
      }),
  });

  cli.command(CLI_COMMANDS.cachePrune, {
    description:
      "Remove the oldest stored Ghidra projects beyond the size ceiling",
    run: () =>
      logCliCommand(logger, CLI_COMMANDS.cachePrune, async () => {
        const resolved = resolve("Cache prune failed");
        return "error" in resolved ? resolved : await pruneCache(resolved);
      }),
  });

  cli.command(CLI_COMMANDS.cacheRemove, {
    description: "Remove one stored Ghidra project by key",
    args: z.object({
      key: z.string().describe("Cache entry key reported by cache-list"),
    }),
    run: ({ args }) =>
      logCliCommand(logger, CLI_COMMANDS.cacheRemove, async () => {
        const resolved = resolve("Cache removal failed");
        return "error" in resolved
          ? resolved
          : await removeCache(resolved, args.key);
      }),
  });

  cli.command(CLI_COMMANDS.cacheVerify, {
    description:
      "Re-validate stored Ghidra projects and optionally remove corrupt entries",
    options: z.object({
      repair: z
        .boolean()
        .default(false)
        .describe("Remove entries whose manifest or digest is corrupt"),
    }),
    run: ({ options }) =>
      logCliCommand(
        logger,
        CLI_COMMANDS.cacheVerify,
        async () => {
          const resolved = resolve("Cache verification failed");
          return "error" in resolved
            ? resolved
            : await verifyCache(resolved, options.repair);
        },
        (value) =>
          isCliOperationFailure(value) ||
          (typeof value === "object" &&
            value !== null &&
            "failed_repairs" in value &&
            Array.isArray(value.failed_repairs) &&
            value.failed_repairs.length > 0),
      ),
  });
};

const storeFor = (config: GhidraProjectCacheConfig): GhidraProjectStore =>
  new GhidraProjectStore({
    root: config.directory,
    maxBytes: config.maxBytes,
    ...(config.maxAgeDays === undefined
      ? {}
      : { maxAgeDays: config.maxAgeDays }),
  });

/** Project an expected store failure into the shared CLI error envelope. */
const cacheErrorEnvelope = (
  label: string,
  error: GhidraProjectCacheError,
): { readonly error: string } & AnalysisErrorProjection => {
  const details = { ...error.diagnostics };
  switch (error.reason) {
    case "busy":
      return {
        error: label,
        code: "resource_constraint",
        category: "resource_constraint",
        message: error.message,
        retryable: true,
        remediation: {
          action:
            "Wait for the active publisher to finish, then retry the cache operation.",
        },
        details,
      };
    case "capacity":
      return {
        error: label,
        code: "resource_constraint",
        category: "resource_constraint",
        message: error.message,
        retryable: false,
        remediation: {
          action:
            "Remove stored projects with cache-remove or raise REA_GHIDRA_PROJECT_CACHE_MAX_BYTES.",
        },
        details,
      };
    case "disabled":
      return {
        error: label,
        code: "configuration_invalid",
        category: "invalid_input",
        message: error.message,
        retryable: false,
        remediation: {
          action:
            "Enable the cache with REA_GHIDRA_PROJECT_CACHE before maintaining it.",
        },
        details,
      };
    case "io":
      return {
        error: label,
        code: "unreadable_output",
        category: "execution_failure",
        message: error.message,
        retryable: false,
        remediation: {
          action:
            "Check read and write access to the reported cache path, then retry.",
        },
        details,
      };
    default:
      return {
        error: label,
        code: "artifact_operation_failed",
        category: "execution_failure",
        message: error.message,
        retryable: false,
        remediation: {
          action:
            "Remove the reported corrupt entry with cache-remove, or re-run cache-verify --repair, then retry.",
        },
        details,
      };
  }
};

const listCache = async (config: GhidraProjectCacheConfig) => {
  const listed = await storeFor(config).list();
  if (!listed.ok)
    return cacheErrorEnvelope("Cache listing failed", listed.error);
  const entries = listed.value;
  return {
    cache_directory: config.directory,
    mode: config.mode,
    max_bytes: config.maxBytes,
    entry_count: entries.length,
    total_bytes: entries.reduce((total, entry) => total + entry.size_bytes, 0),
    entries: entries.map((entry) => ({
      key: entry.key,
      program_name: entry.program_name,
      target_sha256: entry.target.sha256,
      provider_version: entry.provider.version,
      size_bytes: entry.size_bytes,
      created_at: entry.created_at,
    })),
  };
};

const pruneCache = async (config: GhidraProjectCacheConfig) => {
  const pruned = await storeFor(config).prune();
  if (!pruned.ok) return cacheErrorEnvelope("Cache prune failed", pruned.error);
  return {
    cache_directory: config.directory,
    max_bytes: config.maxBytes,
    removed_keys: pruned.value.removed,
    freed_bytes: pruned.value.bytes,
  };
};

const removeCache = async (config: GhidraProjectCacheConfig, key: string) => {
  const removed = await storeFor(config).remove(key);
  if (!removed.ok)
    return cacheErrorEnvelope("Cache removal failed", removed.error);
  return { cache_directory: config.directory, key, removed: removed.value };
};

const verifyCache = async (
  config: GhidraProjectCacheConfig,
  repair: boolean,
) => {
  const store = storeFor(config);
  const verified = await store.verify();
  if (!verified.ok)
    return cacheErrorEnvelope("Cache verification failed", verified.error);
  const results = verified.value;
  const invalid = results.filter((entry) => !entry.ok);
  const repaired: string[] = [];
  const failed: {
    readonly key: string;
    readonly error: GhidraProjectCacheError;
  }[] = [];
  if (repair)
    for (const entry of invalid) {
      const removed = await store.remove(entry.key);
      if (!removed.ok) failed.push({ key: entry.key, error: removed.error });
      else if (removed.value) repaired.push(entry.key);
    }
  return {
    cache_directory: config.directory,
    verified: results.length,
    ok: results.length - invalid.length,
    invalid: invalid.map((entry) => ({
      key: entry.key,
      issues: entry.issues,
    })),
    repaired,
    failed_repairs: failed.map(({ key, error }) => ({
      key,
      reason: error.reason,
      message: error.message,
      ...(error.path === undefined ? {} : { path: error.path }),
    })),
  };
};
