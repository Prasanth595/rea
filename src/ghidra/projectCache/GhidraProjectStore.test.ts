import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { randomUUID } from "node:crypto";

import { ghidraProjectCacheKey } from "./GhidraProjectCacheKey.js";
import {
  GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
  type GhidraProjectCacheIdentity,
} from "./GhidraProjectCacheTypes.js";
import {
  serializeGhidraProjectManifest,
  type GhidraProjectManifest,
} from "./GhidraProjectManifest.js";
import {
  GhidraProjectStore,
  type GhidraProjectPublishInput,
} from "./GhidraProjectStore.js";

const identity = (): GhidraProjectCacheIdentity => ({
  providerId: "ghidra",
  providerVersion: "12.1.4",
  jvmVmName: "OpenJDK 64-Bit Server VM",
  platform: "linux",
  targetSha256: "a".repeat(64),
  importProfileDigest: "b".repeat(64),
});

const target = {
  sha256: "a".repeat(64),
  kind: "executable",
  format: "pe",
  architecture: "x86_64",
  executable_role: "shared-library",
} as const;

let root: string;
let source: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "rea-ghidra-cache-"));
  source = await mkdtemp(join(tmpdir(), "rea-ghidra-runtime-"));
  await mkdir(join(source, "rea-project.rep", "idata"), { recursive: true });
  await writeFile(join(source, "rea-project.gpr"), "");
  await writeFile(
    join(source, "rea-project.rep", "idata", "db.gbf"),
    Buffer.from("analyzed-program-bytes"),
  );
});

afterEach(async () => {
  await Promise.all([
    rm(root, { recursive: true, force: true }),
    rm(source, { recursive: true, force: true }),
  ]);
});

const newStore = (maxBytes = 1_000_000): GhidraProjectStore =>
  new GhidraProjectStore({ root, maxBytes, platform: "linux" });

const publishable = (
  store: GhidraProjectStore,
  reservation: Awaited<ReturnType<GhidraProjectStore["prepare"]>>,
): GhidraProjectPublishInput => {
  if (
    !reservation.ok ||
    reservation.value === null ||
    !reservation.value.stagingPath
  )
    throw new Error("expected a populate-capable reservation");
  return {
    reservation: reservation.value,
    identity: identity(),
    target,
    sourceProjectDirectory: source,
    programName: "target-abc123.dll",
    programSha256: "c".repeat(64),
    producer: { reaVersion: "6.4.0", runId: "run-1" },
  };
};

describe("GhidraProjectStore", () => {
  it("is disabled when the mode is off", async () => {
    const store = newStore();
    expect(await store.prepare({ identity: identity(), mode: "off" })).toEqual({
      ok: true,
      value: null,
    });
  });

  it("publishes a miss and serves a later hit with the stored program identity", async () => {
    const store = newStore();
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    expect(miss.ok && miss.value?.hit === false).toBe(true);
    const published = await store.publish(publishable(store, miss));
    expect(published.ok && published.value.published).toBe(true);

    const key = ghidraProjectCacheKey(identity());
    const manifest = JSON.parse(
      await readFile(join(root, key, "manifest.json"), "utf8"),
    ) as GhidraProjectManifest;
    expect(manifest.program_name).toBe("target-abc123.dll");
    expect(manifest.program_sha256).toBe("c".repeat(64));
    expect(manifest.project_files).toHaveLength(2);
    expect(
      manifest.project_files.some((file) =>
        file.path.endsWith("rea-project.rep/idata/db.gbf"),
      ),
    ).toBe(true);
    expect(manifest.size_bytes).toBeGreaterThan(0);

    const hit = await store.prepare({ identity: identity(), mode: "on" });
    expect(hit.ok).toBe(true);
    if (!hit.ok || hit.value === null) throw new Error("expected a hit");
    expect(hit.value.hit).toBe(true);
    expect(hit.value.programName).toBe("target-abc123.dll");
    expect(hit.value.stagingPath).toBeUndefined();
  });

  it("reserves no staging slot in read mode", async () => {
    const store = newStore();
    const miss = await store.prepare({ identity: identity(), mode: "read" });
    expect(miss.ok).toBe(true);
    if (!miss.ok || miss.value === null)
      throw new Error("expected a reservation");
    expect(miss.value.hit).toBe(false);
    expect(miss.value.stagingPath).toBeUndefined();
  });

  it("discards an entry that is not an expanded project and reports it", async () => {
    const store = newStore();
    const key = ghidraProjectCacheKey(identity());
    await mkdir(join(root, key), { recursive: true });
    await writeFile(join(root, key, "stray.txt"), "not a project");
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    expect(miss.ok && miss.value?.rejectedEntry?.error.reason).toBe("layout");
    expect(miss.ok && miss.value?.hit === false).toBe(true);
  });

  it("discards an entry whose manifest key does not match and reports it", async () => {
    const store = newStore();
    const key = ghidraProjectCacheKey(identity());
    await mkdir(join(root, key, "rea-project.rep"), { recursive: true });
    await writeFile(join(root, key, "rea-project.gpr"), "");
    await writeFile(
      join(root, key, "manifest.json"),
      serializeGhidraProjectManifest(manifestWithKey("9".repeat(64))),
    );
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    expect(miss.ok && miss.value?.rejectedEntry?.error.reason).toBe("identity");
  });

  it("does not overwrite an existing entry when another publisher won", async () => {
    const store = newStore();
    const key = ghidraProjectCacheKey(identity());
    await mkdir(join(root, key), { recursive: true });
    const stagingPath = join(root, "staging", randomUUID());
    await mkdir(stagingPath, { recursive: true });
    const result = await store.publish({
      reservation: {
        key,
        hit: false,
        entryPath: join(root, key),
        stagingPath,
        rootPreparation: { status: "ready" },
      },
      identity: identity(),
      target,
      sourceProjectDirectory: source,
      programName: "target-abc123.dll",
      programSha256: "c".repeat(64),
      producer: { reaVersion: "6.4.0", runId: "run-1" },
    });
    expect(result.ok && result.value.published).toBe(false);
    await expect(stat(stagingPath)).rejects.toThrow();
  });

  it("rejects a stored manifest whose identity fields do not derive its key", async () => {
    const store = newStore();
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    await store.publish(publishable(store, miss));
    const key = ghidraProjectCacheKey(identity());
    const manifest = JSON.parse(
      await readFile(join(root, key, "manifest.json"), "utf8"),
    ) as GhidraProjectManifest;
    manifest.import_profile_digest = "f".repeat(64);
    await writeFile(
      join(root, key, "manifest.json"),
      serializeGhidraProjectManifest(manifest),
    );
    const hit = await store.prepare({ identity: identity(), mode: "on" });
    expect(hit.ok && hit.value?.rejectedEntry?.error.reason).toBe("identity");
    expect(hit.ok && hit.value?.hit === false).toBe(true);
  });

  it.skipIf(process.platform === "win32")(
    "discards a stored entry containing a symbolic link",
    async () => {
      const store = newStore();
      const key = ghidraProjectCacheKey(identity());
      await mkdir(join(root, key, "rea-project.rep", "idata"), {
        recursive: true,
      });
      await writeFile(join(root, key, "rea-project.gpr"), "");
      await symlink(
        join(root, key, "rea-project.gpr"),
        join(root, key, "rea-project.rep", "linked.gpr"),
      );
      const miss = await store.prepare({ identity: identity(), mode: "on" });
      expect(miss.ok && miss.value?.rejectedEntry?.error.reason).toBe("layout");
      expect(miss.ok && miss.value?.hit === false).toBe(true);
    },
  );
});

describe("GhidraProjectStore root repair", () => {
  it("reports a rebuilt Windows root so the caller can state the repair", async () => {
    const parent = await mkdtemp(join(tmpdir(), "rea-ghidra-cache-win-"));
    const cacheRoot = join(parent, "cache");
    await mkdir(cacheRoot);
    await mkdir(join(cacheRoot, "stored"));
    // Only the root that was already there is not owner-only; the rebuilt one
    // passes the same native verification.
    let inspected = false;
    const store = new GhidraProjectStore({
      root: cacheRoot,
      maxBytes: 1_000_000,
      platform: "win32",
      rootHost: {
        async createPrivateDirectory(path) {
          await mkdir(path, { recursive: true });
          return path;
        },
        verifyPrivateDirectory() {
          if (!inspected) {
            inspected = true;
            throw new Error("Private object owner is not the current user");
          }
          return { privateDacl: true };
        },
      },
    });
    const prepared = await store.prepare({ identity: identity(), mode: "on" });
    expect(prepared.ok && prepared.value?.rootPreparation).toEqual({
      status: "repaired",
      preservedEntries: 1,
    });
    // The stored project survived the rebuild.
    await expect(stat(join(cacheRoot, "stored"))).resolves.toBeTruthy();
    await rm(parent, { recursive: true, force: true });
  });
});

describe("GhidraProjectStore maintenance", () => {
  it("removes a stored entry by key", async () => {
    const store = newStore();
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    const published = await store.publish(publishable(store, miss));
    expect(published.ok && published.value.published).toBe(true);
    const key = ghidraProjectCacheKey(identity());
    const removed = await store.remove(key);
    expect(removed.ok && removed.value).toBe(true);
    const listed = await store.list();
    if (!listed.ok) throw new Error("list failed");
    expect(listed.value).toHaveLength(0);
    const again = await store.remove(key);
    expect(again.ok && again.value).toBe(false);
    expect((await store.remove("not-a-key")).ok).toBe(false);
  });

  it("verifies a clean entry and detects a tampered one", async () => {
    const store = newStore();
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    await store.publish(publishable(store, miss));
    const key = ghidraProjectCacheKey(identity());
    const clean = await store.verify();
    if (!clean.ok) throw new Error("verify failed");
    expect(clean.value).toEqual([{ key, ok: true, issues: [] }]);
    await writeFile(
      join(root, key, "rea-project.rep", "idata", "db.gbf"),
      "tampered",
    );
    const verified = await store.verify();
    if (!verified.ok) throw new Error("verify failed");
    const [row] = verified.value;
    expect(row?.ok).toBe(false);
    expect(row?.issues.join(" ")).toMatch(/digest/u);
  });

  it("abandons a reserved staging slot", async () => {
    const store = newStore();
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    if (!miss.ok || miss.value === null || !miss.value.stagingPath)
      throw new Error("expected a staging slot");
    const stagingPath = miss.value.stagingPath;
    await mkdir(stagingPath, { recursive: true });
    await store.abandon(miss.value);
    await expect(stat(stagingPath)).rejects.toThrow();
  });

  it("prunes the oldest entries to satisfy a smaller ceiling", async () => {
    const store = newStore();
    const older = { ...identity(), targetSha256: "1".repeat(64) };
    const newer = { ...identity(), targetSha256: "2".repeat(64) };
    for (const [id, now] of [
      [older, "2020-01-01T00:00:00.000Z"],
      [newer, "2021-01-01T00:00:00.000Z"],
    ] as const) {
      const reservation = await store.prepare({ identity: id, mode: "on" });
      if (!reservation.ok || reservation.value === null)
        throw new Error("expected a reservation");
      const published = await store.publish({
        ...publishable(store, reservation),
        identity: id,
        target: { ...target, sha256: id.targetSha256 },
        now,
      });
      expect(published.ok).toBe(true);
    }
    const listed = await store.list();
    if (!listed.ok) throw new Error("list failed");
    expect(listed.value).toHaveLength(2);

    const [firstSize] = listed.value.map((entry) => entry.size_bytes);
    const smaller = newStore(firstSize ?? 1);
    const pruned = await smaller.prune();
    if (!pruned.ok) throw new Error("prune failed");
    expect(pruned.value.removed).toEqual([ghidraProjectCacheKey(older)]);
    const remaining = await smaller.list();
    if (!remaining.ok) throw new Error("list failed");
    expect(remaining.value.map((entry) => entry.key)).toEqual([
      ghidraProjectCacheKey(newer),
    ]);
  });

  it("prunes entries older than the configured age", async () => {
    const store = newStore();
    const dayMs = 86_400_000;
    const now = Date.now();
    const older = { ...identity(), targetSha256: "3".repeat(64) };
    const newer = { ...identity(), targetSha256: "4".repeat(64) };
    for (const [id, at] of [
      [older, new Date(now - 40 * dayMs).toISOString()],
      [newer, new Date(now - 1 * dayMs).toISOString()],
    ] as const) {
      const reservation = await store.prepare({ identity: id, mode: "on" });
      if (!reservation.ok || reservation.value === null)
        throw new Error("expected a reservation");
      const published = await store.publish({
        ...publishable(store, reservation),
        identity: id,
        target: { ...target, sha256: id.targetSha256 },
        now: at,
      });
      expect(published.ok).toBe(true);
    }
    const aged = new GhidraProjectStore({
      root,
      maxBytes: 1_000_000,
      maxAgeDays: 30,
      platform: "linux",
    });
    const pruned = await aged.prune();
    if (!pruned.ok) throw new Error("prune failed");
    expect(pruned.value.removed).toEqual([ghidraProjectCacheKey(older)]);
    const remaining = await aged.list();
    if (!remaining.ok) throw new Error("list failed");
    expect(remaining.value.map((entry) => entry.key)).toEqual([
      ghidraProjectCacheKey(newer),
    ]);
  });
});

describe("GhidraProjectStore repair leftovers", () => {
  /** The copies a root repair that stopped part-way left behind. */
  const interruptedCopies = async (): Promise<string> => {
    const copies = join(root, "repair-staging");
    await mkdir(join(copies, "entry"), { recursive: true });
    await writeFile(join(copies, "entry", "project"), Buffer.alloc(2048));
    return copies;
  };

  it("reclaims the copies an interrupted rebuild left behind and counts their bytes", async () => {
    const store = newStore();
    const copies = await interruptedCopies();

    const pruned = await store.prune();
    if (!pruned.ok) throw new Error(`prune failed: ${pruned.error.message}`);
    // The copies are not stored entries, so no entry key is removed for them.
    expect(pruned.value.removed).toEqual([]);
    // The bytes they occupied are reported as freed.
    expect(pruned.value.bytes).toBe(2048);
    await expect(stat(copies)).rejects.toThrow();
    await rm(copies, { recursive: true, force: true });
  });

  it("keeps the copies a running rebuild is making", async () => {
    const store = newStore();
    const copies = await interruptedCopies();
    // Another session holds the repair lock beside the root, so the copies it
    // is making are still in use.
    const lock = `${root}.repair`;
    await writeFile(lock, "held");
    try {
      const pruned = await store.prune();
      if (!pruned.ok) throw new Error(`prune failed: ${pruned.error.message}`);
      expect(pruned.value.removed).toEqual([]);
      expect(pruned.value.bytes).toBe(0);
      await expect(stat(copies)).resolves.toBeDefined();
    } finally {
      await rm(lock, { force: true });
      await rm(copies, { recursive: true, force: true });
    }
  });
});

describe("GhidraProjectStore entry age", () => {
  const dayMs = 86_400_000;
  const agedStore = (maxAgeDays?: number): GhidraProjectStore =>
    new GhidraProjectStore({
      root,
      maxBytes: 1_000_000,
      ...(maxAgeDays === undefined ? {} : { maxAgeDays }),
      platform: "linux",
    });

  /** Publish an entry whose manifest records `days` days of age. */
  const publishAged = async (
    store: GhidraProjectStore,
    id: GhidraProjectCacheIdentity,
    days: number,
  ): Promise<string> => {
    const reservation = await store.prepare({ identity: id, mode: "on" });
    if (!reservation.ok || reservation.value === null)
      throw new Error("expected a reservation");
    const published = await store.publish({
      ...publishable(store, reservation),
      identity: id,
      target: { ...target, sha256: id.targetSha256 },
      now: new Date(Date.now() - days * dayMs).toISOString(),
    });
    expect(published.ok && published.value.published).toBe(true);
    return ghidraProjectCacheKey(id);
  };

  it("does not reuse an entry older than the configured age", async () => {
    const store = newStore();
    const id = { ...identity(), targetSha256: "7".repeat(64) };
    const key = await publishAged(store, id, 40);

    const aged = agedStore(30);
    const miss = await aged.prepare({ identity: id, mode: "read" });
    expect(miss.ok && miss.value?.hit).toBe(false);
    expect(miss.ok && miss.value?.rejectedEntry?.error.reason).toBe("expired");
    expect(miss.ok && miss.value?.rejectedEntry?.discarded).toBe(true);
    // The expired entry is removed, so a later session can publish a fresh one.
    await expect(stat(join(root, key))).rejects.toThrow();
  });

  it("keeps an expired entry another session is still reading", async () => {
    const store = newStore();
    const id = { ...identity(), targetSha256: "8".repeat(64) };
    const key = await publishAged(store, id, 40);
    await mkdir(join(root, "leases"), { recursive: true });
    await writeFile(
      join(root, "leases", `${key}.lease`),
      new Date().toISOString(),
    );

    const aged = agedStore(30);
    const miss = await aged.prepare({ identity: id, mode: "read" });
    expect(miss.ok && miss.value?.hit).toBe(false);
    expect(miss.ok && miss.value?.rejectedEntry?.error.reason).toBe("expired");
    expect(miss.ok && miss.value?.rejectedEntry?.discarded).toBe(false);
    // The entry another session is copying stays in place.
    await expect(stat(join(root, key))).resolves.toBeDefined();
  });

  it("reuses an entry that is within the configured age", async () => {
    const store = newStore();
    const id = { ...identity(), targetSha256: "9".repeat(64) };
    await publishAged(store, id, 1);

    const aged = agedStore(30);
    const hit = await aged.prepare({ identity: id, mode: "read" });
    expect(hit.ok && hit.value?.hit).toBe(true);
    expect(hit.ok && hit.value?.rejectedEntry).toBeUndefined();
  });

  it("reuses an entry of any age when no maximum age is configured", async () => {
    const store = newStore();
    const id = { ...identity(), targetSha256: "b".repeat(64) };
    await publishAged(store, id, 400);

    const hit = await agedStore().prepare({ identity: id, mode: "read" });
    expect(hit.ok && hit.value?.hit).toBe(true);
  });

  it("refuses to reuse exactly the entries a prune would remove", async () => {
    const store = newStore();
    const older = { ...identity(), targetSha256: "c".repeat(64) };
    const newer = { ...identity(), targetSha256: "d".repeat(64) };
    await publishAged(store, older, 40);
    await publishAged(store, newer, 1);

    const aged = agedStore(30);
    const refused = await aged.prepare({ identity: older, mode: "read" });
    expect(refused.ok && refused.value?.hit).toBe(false);
    expect(refused.ok && refused.value?.rejectedEntry?.error.reason).toBe(
      "expired",
    );
    const reused = await aged.prepare({ identity: newer, mode: "read" });
    expect(reused.ok && reused.value?.hit).toBe(true);
    // The expired entry is gone and the fresh one is kept, the same set a
    // prune of this store would leave behind.
    const remaining = await aged.list();
    if (!remaining.ok) throw new Error("list failed");
    expect(remaining.value.map((entry) => entry.key)).toEqual([
      ghidraProjectCacheKey(newer),
    ]);
  });
});

describe("GhidraProjectStore damaged entries", () => {
  /** Publish one stored entry and return its cache key. */
  const publishEntry = async (
    store: GhidraProjectStore,
    id: GhidraProjectCacheIdentity,
    now?: string,
  ): Promise<string> => {
    const reservation = await store.prepare({ identity: id, mode: "on" });
    if (!reservation.ok || reservation.value === null)
      throw new Error("expected a reservation");
    const published = await store.publish({
      ...publishable(store, reservation),
      identity: id,
      target: { ...target, sha256: id.targetSha256 },
      ...(now === undefined ? {} : { now }),
    });
    if (!published.ok)
      throw new Error(`publish failed: ${published.error.message}`);
    return ghidraProjectCacheKey(id);
  };

  /** The bytes a stored directory occupies, measured the way a prune does. */
  const directoryBytes = async (path: string): Promise<number> => {
    let total = 0;
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      total += entry.isDirectory()
        ? await directoryBytes(child)
        : (await stat(child)).size;
    }
    return total;
  };

  /** Point a stored manifest at another entry's key. */
  const damageManifestKey = async (key: string, named: string) => {
    const manifest = JSON.parse(
      await readFile(join(root, key, "manifest.json"), "utf8"),
    ) as GhidraProjectManifest;
    manifest.key = named;
    await writeFile(
      join(root, key, "manifest.json"),
      serializeGhidraProjectManifest(manifest),
    );
  };

  /**
   * Publish a valid entry and a second entry whose manifest names the first
   * one's key. The damaged entry describes another analysis, so it is not
   * reusable and a prune must not act on the key it names.
   */
  const publishDamagedPair = async (
    store: GhidraProjectStore,
    damaged: GhidraProjectCacheIdentity,
    named: GhidraProjectCacheIdentity,
    now?: string,
  ): Promise<{ readonly damagedKey: string; readonly namedKey: string }> => {
    const damagedKey = await publishEntry(store, damaged, now);
    const namedKey = await publishEntry(store, named);
    await damageManifestKey(damagedKey, namedKey);
    return { damagedKey, namedKey };
  };

  it("prunes entries that have no readable manifest", async () => {
    const store = newStore();
    const malformed = "a".repeat(64);
    const missing = "b".repeat(64);
    await mkdir(join(root, malformed), { recursive: true });
    await writeFile(join(root, malformed, "manifest.json"), "{");
    await writeFile(
      join(root, malformed, "rea-project.gpr"),
      Buffer.alloc(4096),
    );
    await mkdir(join(root, missing), { recursive: true });
    await writeFile(join(root, missing, "rea-project.gpr"), Buffer.alloc(2048));

    const pruned = await store.prune();
    if (!pruned.ok) throw new Error(`prune failed: ${pruned.error.message}`);
    expect([...pruned.value.removed].sort()).toEqual(
      [malformed, missing].sort(),
    );
    expect(pruned.value.bytes).toBe(4096 + 1 + 2048);
    await expect(stat(join(root, malformed))).rejects.toThrow();
    await expect(stat(join(root, missing))).rejects.toThrow();
  });

  it("keeps a damaged entry leased by a recent hit until the lease lapses", async () => {
    const store = newStore();
    const key = "c".repeat(64);
    await mkdir(join(root, key), { recursive: true });
    await writeFile(join(root, key, "manifest.json"), "{");
    const lease = join(root, "leases", `${key}.lease`);
    await mkdir(join(root, "leases"), { recursive: true });
    await writeFile(lease, new Date().toISOString());

    const leased = await store.prune();
    if (!leased.ok) throw new Error("prune failed");
    expect(leased.value.removed).toEqual([]);
    await expect(stat(join(root, key))).resolves.toBeDefined();

    const stale = new Date(Date.now() - 31 * 60 * 1000);
    await utimes(lease, stale, stale);
    const pruned = await store.prune();
    if (!pruned.ok) throw new Error("prune failed");
    expect(pruned.value.removed).toEqual([key]);
    await expect(stat(join(root, key))).rejects.toThrow();
  });

  it("removes a damaged entry by its own key instead of the key it names", async () => {
    const store = newStore();
    const { damagedKey, namedKey } = await publishDamagedPair(
      store,
      { ...identity(), targetSha256: "1".repeat(64) },
      { ...identity(), targetSha256: "2".repeat(64) },
      new Date(Date.now() - 40 * 86_400_000).toISOString(),
    );
    const freed = await directoryBytes(join(root, damagedKey));
    const aged = new GhidraProjectStore({
      root,
      maxBytes: 1_000_000,
      maxAgeDays: 30,
      platform: "linux",
    });

    const pruned = await aged.prune();
    if (!pruned.ok) throw new Error("prune failed");
    expect(pruned.value.removed).toEqual([damagedKey]);
    // The reported bytes are the bytes of the entry that was removed.
    expect(pruned.value.bytes).toBe(freed);
    await expect(stat(join(root, damagedKey))).rejects.toThrow();
    // The entry the damaged manifest names is untouched.
    await expect(stat(join(root, namedKey))).resolves.toBeDefined();
  });

  it("trims size without removing the entry a damaged manifest names", async () => {
    const store = newStore();
    const { damagedKey, namedKey } = await publishDamagedPair(
      store,
      { ...identity(), targetSha256: "3".repeat(64) },
      { ...identity(), targetSha256: "4".repeat(64) },
    );
    const namedManifest = JSON.parse(
      await readFile(join(root, namedKey, "manifest.json"), "utf8"),
    ) as GhidraProjectManifest;
    // The ceiling holds the named entry alone, so the damaged entry must go.
    const smaller = newStore(namedManifest.size_bytes);

    const pruned = await smaller.prune();
    if (!pruned.ok) throw new Error("prune failed");
    expect(pruned.value.removed).toEqual([damagedKey]);
    await expect(stat(join(root, damagedKey))).rejects.toThrow();
    await expect(stat(join(root, namedKey))).resolves.toBeDefined();
  });

  it("does not list a damaged entry under the key its manifest names", async () => {
    const store = newStore();
    const { damagedKey, namedKey } = await publishDamagedPair(
      store,
      { ...identity(), targetSha256: "5".repeat(64) },
      { ...identity(), targetSha256: "6".repeat(64) },
    );

    const listed = await store.list();
    if (!listed.ok) throw new Error("list failed");
    expect(listed.value.map((entry) => entry.key)).toEqual([namedKey]);
    // The damaged entry is still reported by the integrity check.
    const verified = await store.verify();
    if (!verified.ok) throw new Error("verify failed");
    const rows = new Map(verified.value.map((entry) => [entry.key, entry.ok]));
    expect(rows.get(damagedKey)).toBe(false);
    expect(rows.get(namedKey)).toBe(true);
  });
});

describe("GhidraProjectStore resilience", () => {
  it("reports an unreadable cache root instead of an empty store", async () => {
    const container = await mkdtemp(join(tmpdir(), "rea-ghidra-cache-file-"));
    const root = join(container, "store");
    await writeFile(root, "not a directory");
    const store = new GhidraProjectStore({
      root,
      maxBytes: 1_000_000,
      platform: "linux",
    });
    const listed = await store.list();
    expect(listed.ok).toBe(false);
    expect(!listed.ok && listed.error.reason).toBe("io");
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "returns a typed prune failure when a damaged entry cannot be removed",
    async () => {
      const store = newStore();
      const key = "d".repeat(64);
      await mkdir(join(root, key), { recursive: true });
      await writeFile(join(root, key, "manifest.json"), "{");
      await chmod(root, 0o500);
      try {
        const pruned = await store.prune();
        expect(pruned.ok).toBe(false);
        if (!pruned.ok) {
          expect(pruned.error.reason).toBe("io");
          expect(pruned.error.message).toBe(
            "Ghidra project cache prune failed",
          );
          expect(pruned.error.path).toBe(root);
        }
        // A failed removal leaves the damaged entry in place.
        await expect(stat(join(root, key))).resolves.toBeDefined();
      } finally {
        await chmod(root, 0o700);
      }
      // Restoring write access lets a later prune finish the removal.
      const retried = await store.prune();
      if (!retried.ok)
        throw new Error(`retry prune failed: ${retried.error.message}`);
      expect(retried.value.removed).toEqual([key]);
      await expect(stat(join(root, key))).rejects.toThrow();
    },
  );

  it("reaps an abandoned staging copy but keeps a current one", async () => {
    const store = newStore();
    const abandoned = join(root, "staging", randomUUID());
    const current = join(root, "staging", randomUUID());
    await mkdir(abandoned, { recursive: true });
    await mkdir(current, { recursive: true });
    await writeFile(join(abandoned, "partial.gbf"), "partial");
    const stale = new Date(Date.now() - 2 * 60 * 60 * 1000);
    await utimes(abandoned, stale, stale);
    const pruned = await store.prune();
    expect(pruned.ok).toBe(true);
    await expect(stat(abandoned)).rejects.toThrow();
    await expect(stat(current)).resolves.toBeDefined();
  });

  it("protects a recently used entry from size trimming", async () => {
    const store = newStore();
    const older = { ...identity(), targetSha256: "5".repeat(64) };
    const newer = { ...identity(), targetSha256: "6".repeat(64) };
    for (const [id, now] of [
      [older, "2020-01-01T00:00:00.000Z"],
      [newer, "2021-01-01T00:00:00.000Z"],
    ] as const) {
      const reservation = await store.prepare({ identity: id, mode: "on" });
      if (!reservation.ok || reservation.value === null)
        throw new Error("expected a reservation");
      await store.publish({
        ...publishable(store, reservation),
        identity: id,
        target: { ...target, sha256: id.targetSha256 },
        now,
      });
    }
    // A hit leases the older entry for its runtime copy.
    const hit = await store.prepare({ identity: older, mode: "on" });
    if (!hit.ok) throw new Error(`prepare failed: ${hit.error.message}`);
    if (hit.value === null || hit.value.hit !== true)
      throw new Error(
        `expected a hit, reason=${hit.value?.rejectedEntry?.error.reason ?? "none"}`,
      );

    const listed = await store.list();
    if (!listed.ok) throw new Error("list failed");
    const [firstSize] = listed.value.map((entry) => entry.size_bytes);
    const smaller = newStore(firstSize ?? 1);
    const pruned = await smaller.prune();
    if (!pruned.ok) throw new Error("prune failed");
    expect(pruned.value.removed).toEqual([ghidraProjectCacheKey(newer)]);
    const remaining = await smaller.list();
    if (!remaining.ok) throw new Error("list failed");
    expect(remaining.value.map((entry) => entry.key)).toEqual([
      ghidraProjectCacheKey(older),
    ]);
  });

  it("refuses to remove an entry leased by a recent hit", async () => {
    const store = newStore();
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    await store.publish(publishable(store, miss));
    const key = ghidraProjectCacheKey(identity());
    const hit = await store.prepare({ identity: identity(), mode: "on" });
    expect(hit.ok && hit.value?.hit).toBe(true);
    const removed = await store.remove(key);
    expect(removed.ok).toBe(false);
    expect(!removed.ok && removed.error.reason).toBe("busy");
  });
});

const manifestWithKey = (key: string): GhidraProjectManifest => ({
  schema_version: GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
  key,
  provider: { id: "ghidra", version: "12.1.4" },
  jvm: { vm_name: "OpenJDK 64-Bit Server VM" },
  platform: "linux",
  target,
  import_profile_digest: "b".repeat(64),
  program_name: "target-abc123.dll",
  program_sha256: "c".repeat(64),
  project_files: [
    { path: "rea-project.rep/db.gbf", bytes: 1, sha256: "d".repeat(64) },
  ],
  project_digest: "e".repeat(64),
  created_at: "2026-01-01T00:00:00.000Z",
  last_used_at: "2026-01-01T00:00:00.000Z",
  size_bytes: 1,
  producer: { rea_version: "6.4.0", run_id: "run-1" },
});
