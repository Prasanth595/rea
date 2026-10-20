import { mkdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { workspaceCliTest } from "../support/cli/workspaceCliFixture.js";

// A damaged entry leased by a recent hit cannot be repaired. The command must
// report that failure and exit unsuccessfully instead of looking repaired.
workspaceCliTest(
  "cache-verify --repair reports a corrupt entry it could not remove",
  async ({ cli, workspace }) => {
    const directory = await workspace.mkdir("cache");
    const key = "a".repeat(64);
    await mkdir(join(directory, key), { recursive: true });
    await writeFile(join(directory, key, "manifest.json"), "{");
    await mkdir(join(directory, "leases"), { recursive: true });
    await writeFile(
      join(directory, "leases", `${key}.lease`),
      new Date().toISOString(),
    );

    const result = await cli.run({
      arguments: ["cache-verify", "--repair", "--format", "json"],
      cwd: workspace.root,
      environment: {
        ...workspace.environment,
        REA_GHIDRA_PROJECT_CACHE: "read",
        REA_GHIDRA_PROJECT_CACHE_DIR: directory,
      },
    });

    expect(result.exitCode, result.stderr).toBe(1);
    expect(result.json).toMatchObject({
      cache_directory: directory,
      invalid: [{ key }],
      repaired: [],
      failed_repairs: [{ key, reason: "busy" }],
    });
    await expect(stat(join(directory, key))).resolves.toBeDefined();
  },
);

// A store failure is not a repair failure, so it must stay classified by the
// shared CLI error envelope rather than the repair-specific check.
workspaceCliTest(
  "cache-verify exits unsuccessfully when the cache root is unreadable",
  async ({ cli, workspace }) => {
    const directory = await workspace.write("cache", "not a directory");

    const result = await cli.run({
      arguments: ["cache-verify", "--format", "json"],
      cwd: workspace.root,
      environment: {
        ...workspace.environment,
        REA_GHIDRA_PROJECT_CACHE: "read",
        REA_GHIDRA_PROJECT_CACHE_DIR: directory,
      },
    });

    expect(result.exitCode, result.stderr).toBe(1);
    expect(result.json).toMatchObject({
      error: "Cache verification failed",
      code: "unreadable_output",
    });
  },
);

workspaceCliTest(
  "cache-verify exits unsuccessfully when the cache configuration is invalid",
  async ({ cli, workspace }) => {
    const result = await cli.run({
      arguments: ["cache-verify", "--format", "json"],
      cwd: workspace.root,
      environment: {
        ...workspace.environment,
        REA_GHIDRA_PROJECT_CACHE: "read",
        REA_GHIDRA_EXISTING_PROJECT: workspace.path("project"),
        REA_GHIDRA_EXISTING_PROGRAM: "program",
      },
    });

    expect(result.exitCode, result.stderr).toBe(1);
    expect(result.json).toMatchObject({
      error: "Cache verification failed",
      code: "configuration_invalid",
    });
  },
);
