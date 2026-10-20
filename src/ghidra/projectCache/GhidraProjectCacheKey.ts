import { createHash } from "node:crypto";
import canonicalize from "canonicalize";

import { isDigest } from "../../domain/digests.js";
import {
  GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
  type GhidraProjectCacheIdentity,
} from "./GhidraProjectCacheTypes.js";

/**
 * Derive the cache key from identity inputs only. The key must never include a
 * cache entry's own manifest, or no entry could ever be looked up. Two sessions
 * that would produce the same analysis inputs derive the same key, which is
 * what makes a saved project reusable across sessions.
 */
export const ghidraProjectCacheKey = (
  identity: GhidraProjectCacheIdentity,
): string => {
  for (const [name, value] of [
    ["providerId", identity.providerId],
    ["providerVersion", identity.providerVersion],
    ["jvmVmName", identity.jvmVmName],
  ] as const)
    requireNonEmpty(name, value);
  requireDigest("targetSha256", identity.targetSha256);
  requireDigest("importProfileDigest", identity.importProfileDigest);
  const encoded = canonicalize({
    schema_version: GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
    provider: { id: identity.providerId, version: identity.providerVersion },
    jvm: { vm_name: identity.jvmVmName },
    platform: identity.platform,
    target_sha256: identity.targetSha256,
    import_profile_digest: identity.importProfileDigest,
  });
  if (encoded === undefined)
    throw new TypeError("Ghidra project cache identity is not canonicalizable");
  return createHash("sha256").update(encoded).digest("hex");
};

const requireDigest = (name: string, value: string): void => {
  if (!isDigest(value))
    throw new TypeError(`Ghidra project cache ${name} must be a sha256 digest`);
};

const requireNonEmpty = (name: string, value: string): void => {
  if (value.length === 0)
    throw new TypeError(`Ghidra project cache ${name} must not be empty`);
};
