import { mkdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { ghidraProjectCacheKey } from "../../src/ghidra/projectCache/GhidraProjectCacheKey.js";
import {
  GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
  type GhidraProjectCacheIdentity,
} from "../../src/ghidra/projectCache/GhidraProjectCacheTypes.js";
import {
  serializeGhidraProjectManifest,
  type GhidraProjectManifest,
} from "../../src/ghidra/projectCache/GhidraProjectManifest.js";
import { workspaceCliTest } from "../support/cli/workspaceCliFixture.js";

const identity = (targetSha256: string): GhidraProjectCacheIdentity => ({
  providerId: "ghidra",
  providerVersion: "12.1.4",
  jvmVmName: "OpenJDK 64-Bit Server VM",
  platform: "linux",
  targetSha256,
  importProfileDigest: "b".repeat(64),
});

/** A manifest that commits to the identity its cache key is derived from. */
const manifestFor = (
  id: GhidraProjectCacheIdentity,
): GhidraProjectManifest => ({
  schema_version: GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
  key: ghidraProjectCacheKey(id),
  provider: { id: id.providerId, version: id.providerVersion },
  jvm: { vm_name: id.jvmVmName },
  platform: id.platform,
  target: {
    sha256: id.targetSha256,
    kind: "executable",
    format: "elf",
    architecture: "x86_64",
    executable_role: null,
  },
  import_profile_digest: id.importProfileDigest,
  program_name: "fixture",
  program_sha256: id.targetSha256,
  project_files: [
    { path: "rea-project.rep/idata/db.gbf", bytes: 7, sha256: "c".repeat(64) },
  ],
  project_digest: "d".repeat(64),
  created_at: "2026-01-01T00:00:00.000Z",
  last_used_at: "2026-01-01T00:00:00.000Z",
  size_bytes: 7,
  producer: { rea_version: "6.4.0", run_id: "run-1" },
});

/** Write one stored project with the given manifest. */
const writeEntry = async (
  directory: string,
  key: string,
  manifest: GhidraProjectManifest,
): Promise<string> => {
  const entry = join(directory, key);
  await mkdir(join(entry, "rea-project.rep", "idata"), { recursive: true });
  await writeFile(join(entry, "rea-project.gpr"), "");
  await writeFile(join(entry, "rea-project.rep", "idata", "db.gbf"), "program");
  await writeFile(
    join(entry, "manifest.json"),
    serializeGhidraProjectManifest(manifest),
  );
  return entry;
};

// A damaged manifest names another entry's key. The prune must remove the
// entry it found, not the entry the manifest names, and must report the bytes
// it actually freed.
workspaceCliTest(
  "cache-prune removes a damaged entry by its own key and keeps the entry it names",
  async ({ cli, workspace }) => {
    const directory = await workspace.mkdir("cache");
    const named = identity("a".repeat(64));
    const damaged = identity("b".repeat(64));
    const namedKey = ghidraProjectCacheKey(named);
    const damagedKey = ghidraProjectCacheKey(damaged);
    await writeEntry(directory, namedKey, manifestFor(named));
    await writeEntry(directory, damagedKey, {
      ...manifestFor(damaged),
      key: namedKey,
    });

    const result = await cli.run({
      arguments: ["cache-prune", "--format", "json"],
      cwd: workspace.root,
      environment: {
        ...workspace.environment,
        REA_GHIDRA_PROJECT_CACHE: "read",
        REA_GHIDRA_PROJECT_CACHE_DIR: directory,
      },
    });

    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.json).toMatchObject({ removed_keys: [damagedKey] });
    const pruned = result.json as { readonly freed_bytes: number };
    expect(pruned.freed_bytes).toBeGreaterThan(0);
    await expect(stat(join(directory, damagedKey))).rejects.toThrow();
    await expect(stat(join(directory, namedKey))).resolves.toBeDefined();
  },
);
