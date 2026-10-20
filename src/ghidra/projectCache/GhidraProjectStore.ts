import { randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join } from "node:path";

import { err, ok, type Result } from "../../domain/result.js";
import type { GhidraProjectCacheMode } from "../../config/ghidraProjectCache.js";
import {
  GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
  GHIDRA_PROJECT_LEASE_DIRECTORY,
  GHIDRA_PROJECT_LOCK_DIRECTORY,
  GHIDRA_PROJECT_MANIFEST_FILE,
  GHIDRA_PROJECT_STAGING_DIRECTORY,
  GhidraProjectCacheError,
  type GhidraProjectCacheIdentity,
} from "./GhidraProjectCacheTypes.js";
import { ghidraProjectCacheKey } from "./GhidraProjectCacheKey.js";
import {
  ensureGhidraProjectCacheRoot,
  reclaimGhidraProjectCacheRootRepairs,
  type GhidraProjectCacheRootHost,
  type GhidraProjectCacheRootPreparation,
} from "./GhidraProjectCacheRoot.js";
import {
  admitGhidraProjectDirectory,
  copyGhidraProjectDirectory,
  digestGhidraProjectDirectory,
  ghidraProjectDirectoryBytes,
} from "./GhidraProjectLayout.js";
import {
  ghidraProjectManifestIdentity,
  parseGhidraProjectManifest,
  serializeGhidraProjectManifest,
  type GhidraProjectManifest,
  type GhidraProjectManifestTarget,
} from "./GhidraProjectManifest.js";

const KEY_PATTERN = /^[a-f0-9]{64}$/u;
// A publisher that died mid-analysis can leave a lock behind. Steal one only
// after this age, and only once; a live publisher is not preempted.
const LOCK_STALE_MS = 10 * 60 * 1000;
// A copy interrupted by process exit leaves its staging directory behind. Reap
// one only after it has been silent for longer than any plausible copy.
const STAGING_STALE_MS = 60 * 60 * 1000;
// A hit records a lease so a concurrent `prune` cannot evict an entry that is
// still being read for its runtime copy. The protection lapses once the last
// reader stops refreshing the lease.
const LEASE_PROTECTED_MS = 30 * 60 * 1000;

/** A resolved cache lookup or a reserved staging slot for a fresh import. */
export interface GhidraProjectReservation {
  readonly key: string;
  readonly hit: boolean;
  readonly entryPath: string;
  /** Present only when the caller may populate the cache. */
  readonly stagingPath?: string;
  /** Present on a hit: the stored program name and its recorded digest. */
  readonly programName?: string;
  readonly programSha256?: string;
  /** An existing entry was present but not reused; a miss was served instead. */
  readonly rejectedEntry?: GhidraProjectRejection;
  /**
   * What preparing the cache root did. A rebuilt root is reported so the
   * caller can state that the cache was repaired rather than silently
   * disabled.
   */
  readonly rootPreparation: GhidraProjectCacheRootPreparation;
}

/**
 * Why a stored entry was not reused, and what happened to the entry itself.
 */
export interface GhidraProjectRejection {
  /** The typed reason the entry could not be reused. */
  readonly error: GhidraProjectCacheError;
  /**
   * The entry was removed. False when another session still holds the entry
   * for its runtime copy, so the entry was left in place.
   */
  readonly discarded: boolean;
}

export interface GhidraProjectPublishInput {
  readonly reservation: GhidraProjectReservation;
  readonly identity: GhidraProjectCacheIdentity;
  readonly target: GhidraProjectManifestTarget;
  /** The runtime project directory holding `rea-project.gpr` and `.rep`. */
  readonly sourceProjectDirectory: string;
  readonly programName: string;
  readonly programSha256: string;
  readonly producer: { readonly reaVersion: string; readonly runId: string };
  /** Injectable clock for deterministic tests. */
  readonly now?: string;
  readonly signal?: AbortSignal;
}

export interface GhidraProjectStoreOptions {
  readonly root: string;
  readonly maxBytes: number;
  /** Discard entries older than this many days; unset applies no age limit. */
  readonly maxAgeDays?: number;
  /** Platform override used by deterministic root-security tests. */
  readonly platform?: NodeJS.Platform;
  /** Native root-security host override used by deterministic tests. */
  readonly rootHost?: GhidraProjectCacheRootHost;
}

/** One row of a store-wide integrity verification. */
export interface GhidraProjectVerification {
  readonly key: string;
  readonly ok: boolean;
  readonly issues: readonly string[];
}

/** Outcome of a store-wide prune. */
export interface GhidraProjectPruneResult {
  readonly removed: readonly string[];
  readonly bytes: number;
}

/**
 * A stored entry whose manifest describes the directory that holds it. The key
 * is the scanned directory, never a key the manifest names, so every removal
 * targets the entry that was inspected.
 */
interface GhidraProjectEntry {
  readonly key: string;
  readonly manifest: GhidraProjectManifest;
}

/** Owns the on-disk store of previously analyzed Ghidra projects. */
export class GhidraProjectStore {
  readonly #root: string;
  readonly #maxBytes: number;
  readonly #maxAgeDays: number | undefined;
  readonly #platform: NodeJS.Platform;
  readonly #rootHost: GhidraProjectCacheRootHost | undefined;

  constructor(options: GhidraProjectStoreOptions) {
    this.#root = options.root;
    this.#maxBytes = options.maxBytes;
    this.#maxAgeDays = options.maxAgeDays;
    this.#platform = options.platform ?? process.platform;
    this.#rootHost = options.rootHost;
  }

  get root(): string {
    return this.#root;
  }

  /**
   * Resolve a hit, or reserve a staging slot for a miss. Returns `null` when
   * the mode is `off`, so the caller keeps its ephemeral behaviour.
   */
  async prepare(input: {
    readonly identity: GhidraProjectCacheIdentity;
    readonly mode: GhidraProjectCacheMode;
    readonly signal?: AbortSignal;
  }): Promise<
    Result<GhidraProjectReservation | null, GhidraProjectCacheError>
  > {
    if (input.mode === "off") return ok(null);
    const key = ghidraProjectCacheKey(input.identity);
    const entryPath = this.#entryPath(key);
    try {
      const rootPreparation = await ensureGhidraProjectCacheRoot(this.#root, {
        platform: this.#platform,
        ...(this.#rootHost === undefined ? {} : { host: this.#rootHost }),
      });
      input.signal?.throwIfAborted();
      const existing = await lstat(entryPath).catch(() => undefined);
      if (existing === undefined)
        return ok(this.#miss(key, entryPath, input.mode, rootPreparation));
      const admitted = await admitGhidraProjectDirectory(entryPath);
      if (!admitted.ok) {
        await this.#discard(entryPath);
        return ok({
          ...this.#miss(key, entryPath, input.mode, rootPreparation),
          rejectedEntry: { error: admitted.error, discarded: true },
        });
      }
      const entry = await this.#readEntry(key);
      if (!entry.ok) {
        await this.#discard(entryPath);
        return ok({
          ...this.#miss(key, entryPath, input.mode, rootPreparation),
          rejectedEntry: { error: entry.error, discarded: true },
        });
      }
      if (this.#expired(entry.value.manifest, Date.now())) {
        // An entry older than the configured maximum age is never reused. It
        // is removed so this session can rebuild it, unless another session
        // still holds it for its runtime copy.
        const retained = await this.#isLeased(key);
        if (!retained) await this.#discard(entryPath);
        return ok({
          ...this.#miss(key, entryPath, input.mode, rootPreparation),
          rejectedEntry: {
            error: new GhidraProjectCacheError(
              "expired",
              "Stored Ghidra project is older than the configured maximum age",
              entryPath,
            ),
            discarded: !retained,
          },
        });
      }
      await this.#touchLease(key);
      return ok({
        key,
        hit: true,
        entryPath,
        programName: entry.value.manifest.program_name,
        programSha256: entry.value.manifest.program_sha256,
        rootPreparation,
      });
    } catch (cause: unknown) {
      if (input.signal?.aborted === true) throw cause;
      if (cause instanceof GhidraProjectCacheError) return err(cause);
      return err(
        this.#io("Ghidra project cache lookup failed", entryPath, cause),
      );
    }
  }

  /** Publish a freshly analyzed project after a clean, complete session. */
  async publish(
    input: GhidraProjectPublishInput,
  ): Promise<Result<{ readonly published: boolean }, GhidraProjectCacheError>> {
    const stagingPath = input.reservation.stagingPath;
    if (stagingPath === undefined)
      return err(
        new GhidraProjectCacheError(
          "disabled",
          "Ghidra project cache publish requires a reserved staging slot",
          input.reservation.entryPath,
        ),
      );
    try {
      return await this.#withLock(
        input.reservation.key,
        input.signal,
        async () => {
          const existing = await lstat(input.reservation.entryPath).catch(
            () => undefined,
          );
          if (existing !== undefined) {
            // A concurrent publisher won; discard this copy rather than overwrite.
            await this.#discard(stagingPath);
            return ok({ published: false });
          }
          await copyGhidraProjectDirectory(
            input.sourceProjectDirectory,
            stagingPath,
            input.signal,
          );
          const admitted = await admitGhidraProjectDirectory(stagingPath);
          if (!admitted.ok) {
            await this.#discard(stagingPath);
            return admitted;
          }
          const digest = await digestGhidraProjectDirectory(
            stagingPath,
            input.signal,
          );
          const now = input.now ?? new Date().toISOString();
          const manifest: GhidraProjectManifest = {
            schema_version: GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
            key: input.reservation.key,
            provider: {
              id: input.identity.providerId,
              version: input.identity.providerVersion,
            },
            jvm: { vm_name: input.identity.jvmVmName },
            platform: input.identity.platform,
            target: input.target,
            import_profile_digest: input.identity.importProfileDigest,
            program_name: input.programName,
            program_sha256: input.programSha256,
            project_files: [...digest.files],
            project_digest: digest.projectDigest,
            created_at: now,
            last_used_at: now,
            size_bytes: digest.sizeBytes,
            producer: {
              rea_version: input.producer.reaVersion,
              run_id: input.producer.runId,
            },
          };
          await writeFile(
            join(stagingPath, GHIDRA_PROJECT_MANIFEST_FILE),
            serializeGhidraProjectManifest(manifest),
            { flag: "wx", mode: 0o600 },
          );
          await rename(stagingPath, input.reservation.entryPath);
          const pruned = await this.prune(input.signal);
          if (!pruned.ok) return err(pruned.error);
          return ok({ published: true });
        },
      );
    } catch (cause: unknown) {
      await this.#discard(stagingPath);
      if (input.signal?.aborted === true) throw cause;
      if (cause instanceof GhidraProjectCacheError) return err(cause);
      return err(
        this.#io(
          "Ghidra project cache publish failed",
          input.reservation.entryPath,
          cause,
        ),
      );
    }
  }

  /** Discard a reserved staging slot without publishing (failure/cancel). */
  async abandon(reservation: GhidraProjectReservation): Promise<void> {
    if (reservation.stagingPath !== undefined)
      await this.#discard(reservation.stagingPath);
  }

  /** Remove one stored entry by key. Returns whether an entry was removed. */
  async remove(key: string): Promise<Result<boolean, GhidraProjectCacheError>> {
    if (!KEY_PATTERN.test(key))
      return err(
        new GhidraProjectCacheError(
          "identity",
          "A Ghidra project cache key is a lowercase sha256 digest",
          key,
        ),
      );
    const entryPath = this.#entryPath(key);
    try {
      if (await this.#isLeased(key))
        return err(
          new GhidraProjectCacheError(
            "busy",
            "Stored Ghidra project is in use by another session",
            entryPath,
          ),
        );
      const existing = await lstat(entryPath).catch(() => undefined);
      if (existing === undefined) return ok(false);
      await this.#discard(entryPath);
      return ok(true);
    } catch (cause: unknown) {
      if (cause instanceof GhidraProjectCacheError) return err(cause);
      return err(
        this.#io("Ghidra project cache removal failed", entryPath, cause),
      );
    }
  }

  /**
   * Re-validate every stored entry: layout admission, manifest identity, and the
   * full per-file digest recorded at publish. Returns one row per entry; a row
   * with issues is corrupt and may be removed with {@link remove}.
   */
  async verify(
    signal?: AbortSignal,
  ): Promise<
    Result<readonly GhidraProjectVerification[], GhidraProjectCacheError>
  > {
    const keys = await this.#entryKeys(signal);
    if (!keys.ok) return keys;
    const results: GhidraProjectVerification[] = [];
    for (const key of keys.value)
      results.push(await this.#verifyEntry(key, signal));
    return ok(results);
  }

  async #verifyEntry(
    key: string,
    signal?: AbortSignal,
  ): Promise<GhidraProjectVerification> {
    const entryPath = this.#entryPath(key);
    const issues: string[] = [];
    const admitted = await admitGhidraProjectDirectory(entryPath);
    if (!admitted.ok) issues.push(admitted.error.message);
    const entry = await this.#readEntry(key);
    if (!entry.ok) {
      issues.push(entry.error.message);
    } else if (admitted.ok)
      issues.push(
        ...(await this.#digestIssues(entryPath, entry.value.manifest, signal)),
      );
    return { key, ok: issues.length === 0, issues };
  }

  async #digestIssues(
    entryPath: string,
    manifest: GhidraProjectManifest,
    signal?: AbortSignal,
  ): Promise<readonly string[]> {
    try {
      const digest = await digestGhidraProjectDirectory(entryPath, signal);
      const issues: string[] = [];
      if (digest.projectDigest !== manifest.project_digest)
        issues.push("Stored project digest does not match its manifest");
      if (digest.sizeBytes !== manifest.size_bytes)
        issues.push("Stored project size does not match its manifest");
      return issues;
    } catch (cause: unknown) {
      return [cause instanceof Error ? cause.message : String(cause)];
    }
  }

  /**
   * Read the manifest of one scanned entry and confirm that it describes the
   * directory it was found in. A manifest that names another key, or whose
   * identity no longer derives its key, belongs to a different analysis, so
   * the entry is damaged rather than reusable. This is the one place that
   * decides whether a stored manifest describes the directory that holds it.
   */
  async #readEntry(
    key: string,
  ): Promise<Result<GhidraProjectEntry, GhidraProjectCacheError>> {
    const entryPath = this.#entryPath(key);
    const manifest = await this.#readManifest(entryPath);
    if (!manifest.ok) return err(manifest.error);
    const identityError = this.#manifestIdentityError(
      manifest.value,
      key,
      entryPath,
    );
    if (identityError !== undefined) return err(identityError);
    return ok({ key, manifest: manifest.value });
  }

  /**
   * Recompute the cache key a stored manifest commits and compare it with the
   * entry directory. A manifest whose key or identity fields no longer derive
   * its directory describes different analysis than the entry claims, so it is
   * never accepted as a hit.
   */
  #manifestIdentityError(
    manifest: GhidraProjectManifest,
    key: string,
    entryPath: string,
  ): GhidraProjectCacheError | undefined {
    if (manifest.key !== key)
      return new GhidraProjectCacheError(
        "identity",
        "Stored Ghidra project manifest key does not match its directory",
        entryPath,
      );
    let derived: string;
    try {
      derived = ghidraProjectCacheKey(ghidraProjectManifestIdentity(manifest));
    } catch (cause: unknown) {
      return new GhidraProjectCacheError(
        "identity",
        "Stored Ghidra project manifest identity is invalid",
        entryPath,
        { cause },
      );
    }
    if (derived === key) return undefined;
    return new GhidraProjectCacheError(
      "identity",
      "Stored Ghidra project manifest identity does not match its cache key",
      entryPath,
    );
  }

  /**
   * Whether a stored entry is older than the configured maximum age. The
   * lookup and the prune share this rule, so an entry a lookup refuses to
   * reuse is the same entry a prune would remove. An unset maximum age applies
   * no age limit, and an unparsable timestamp keeps the entry.
   */
  #expired(manifest: GhidraProjectManifest, nowMs: number): boolean {
    if (this.#maxAgeDays === undefined) return false;
    const ageMs = nowMs - Date.parse(manifest.last_used_at);
    return Number.isFinite(ageMs) && ageMs > this.#maxAgeDays * 86_400_000;
  }

  /**
   * Every stored entry whose manifest describes its own directory. A damaged
   * entry is reported by `verify()` and reclaimed by `prune()`; it is never
   * listed under a key that names a different entry.
   */
  async list(
    signal?: AbortSignal,
  ): Promise<
    Result<readonly GhidraProjectManifest[], GhidraProjectCacheError>
  > {
    const keys = await this.#entryKeys(signal);
    if (!keys.ok) return keys;
    const manifests: GhidraProjectManifest[] = [];
    for (const key of keys.value) {
      const entry = await this.#readEntry(key);
      if (entry.ok) manifests.push(entry.value.manifest);
    }
    return ok(manifests);
  }

  /**
   * Remove stale entries and abandoned staging copies, then the oldest entries
   * until the store fits its ceiling. Entries a hit recently leased for its
   * runtime copy are protected from removal. An entry whose manifest cannot be
   * read, or whose manifest does not describe its own directory, is damaged,
   * so it contributes no listed size; it is removed here instead of escaping
   * the ceiling forever. Every removal targets the scanned directory, so a
   * damaged manifest never redirects a removal to another entry.
   *
   * The copies a root repair that stopped part-way left behind are reclaimed
   * as well: they are not stored entries, so no other part of the prune would
   * ever count or remove them. Their bytes are reported as freed.
   */
  async prune(
    signal?: AbortSignal,
  ): Promise<Result<GhidraProjectPruneResult, GhidraProjectCacheError>> {
    try {
      return await this.#prune(signal);
    } catch (cause: unknown) {
      if (signal?.aborted === true) throw cause;
      if (cause instanceof GhidraProjectCacheError) return err(cause);
      return err(
        this.#io("Ghidra project cache prune failed", this.#root, cause),
      );
    }
  }

  async #prune(
    signal?: AbortSignal,
  ): Promise<Result<GhidraProjectPruneResult, GhidraProjectCacheError>> {
    const keys = await this.#entryKeys(signal);
    if (!keys.ok) return keys;
    await this.#pruneStaging(signal);
    const reclaimed = await reclaimGhidraProjectCacheRootRepairs(this.#root);
    const protectedKeys = await this.#protectedKeys(signal);
    const removed: string[] = [];
    let freed = reclaimed.reduce((total, reclaim) => total + reclaim.bytes, 0);
    const drop = async (key: string, bytes: number): Promise<void> => {
      await this.#discard(this.#entryPath(key));
      removed.push(key);
      freed += bytes;
    };
    const entries: GhidraProjectEntry[] = [];
    for (const key of keys.value) {
      const entry = await this.#readEntry(key);
      if (entry.ok) {
        entries.push(entry.value);
        continue;
      }
      // A damaged entry cannot be discovered or counted through `list()`, and
      // its recorded size is untrustworthy. Measure it before removing so the
      // freed total stays useful without re-reading project contents. The
      // removal targets the scanned directory, never a key the manifest names.
      if (protectedKeys.has(key)) continue;
      await drop(key, await ghidraProjectDirectoryBytes(this.#entryPath(key)));
    }
    const nowMs = Date.now();
    const fresh: GhidraProjectEntry[] = [];
    for (const entry of entries) {
      if (protectedKeys.has(entry.key)) {
        fresh.push(entry);
        continue;
      }
      if (this.#expired(entry.manifest, nowMs))
        await drop(entry.key, entry.manifest.size_bytes);
      else fresh.push(entry);
    }
    let total = fresh.reduce(
      (sum, entry) => sum + entry.manifest.size_bytes,
      0,
    );
    if (total <= this.#maxBytes) return ok({ removed, bytes: freed });
    fresh.sort((left, right) =>
      left.manifest.last_used_at < right.manifest.last_used_at
        ? -1
        : left.manifest.last_used_at > right.manifest.last_used_at
          ? 1
          : left.key < right.key
            ? -1
            : 1,
    );
    for (const entry of fresh) {
      if (total <= this.#maxBytes) break;
      if (protectedKeys.has(entry.key)) continue;
      await drop(entry.key, entry.manifest.size_bytes);
      total -= entry.manifest.size_bytes;
    }
    return ok({ removed, bytes: freed });
  }

  #miss(
    key: string,
    entryPath: string,
    mode: GhidraProjectCacheMode,
    rootPreparation: GhidraProjectCacheRootPreparation,
  ): GhidraProjectReservation {
    return {
      key,
      hit: false,
      entryPath,
      ...(mode === "on" ? { stagingPath: this.#stagingPath() } : {}),
      rootPreparation,
    };
  }

  #entryPath(key: string): string {
    return join(this.#root, key);
  }

  #stagingPath(): string {
    return join(this.#root, GHIDRA_PROJECT_STAGING_DIRECTORY, randomUUID());
  }

  #lockPath(key: string): string {
    return join(this.#root, GHIDRA_PROJECT_LOCK_DIRECTORY, `${key}.lock`);
  }

  #leasePath(key: string): string {
    return join(this.#root, GHIDRA_PROJECT_LEASE_DIRECTORY, `${key}.lease`);
  }

  /** Record that a hit is in use so a concurrent prune leaves it alone. */
  async #touchLease(key: string): Promise<void> {
    const path = this.#leasePath(key);
    try {
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await writeFile(path, `${new Date().toISOString()}\n`, {
        encoding: "utf8",
        mode: 0o600,
      });
    } catch {
      // A lease is a best-effort eviction guard; a hit stays valid without it.
    }
  }

  /** Whether a recent hit leased this key for its runtime copy. */
  async #isLeased(key: string): Promise<boolean> {
    const stats = await lstat(this.#leasePath(key)).catch(() => undefined);
    return (
      stats !== undefined && Date.now() - stats.mtimeMs <= LEASE_PROTECTED_MS
    );
  }

  /** Keys a recent hit leased for its runtime copy, refreshed as leases renew. */
  async #protectedKeys(signal?: AbortSignal): Promise<ReadonlySet<string>> {
    const directory = join(this.#root, GHIDRA_PROJECT_LEASE_DIRECTORY);
    const entries = await readdir(directory, { withFileTypes: true }).catch(
      () => [],
    );
    const protectedKeys = new Set<string>();
    const nowMs = Date.now();
    for (const entry of entries) {
      signal?.throwIfAborted();
      if (!entry.isFile() || !entry.name.endsWith(".lease")) continue;
      const key = entry.name.slice(0, -".lease".length);
      if (!KEY_PATTERN.test(key)) continue;
      const path = join(directory, entry.name);
      const stats = await lstat(path).catch(() => undefined);
      if (stats === undefined) continue;
      if (nowMs - stats.mtimeMs <= LEASE_PROTECTED_MS) protectedKeys.add(key);
      else await rm(path, { force: true }).catch(() => undefined);
    }
    return protectedKeys;
  }

  /** Remove staging copies abandoned by an interrupted publish. */
  async #pruneStaging(signal?: AbortSignal): Promise<readonly string[]> {
    const directory = join(this.#root, GHIDRA_PROJECT_STAGING_DIRECTORY);
    const entries = await readdir(directory, { withFileTypes: true }).catch(
      () => [],
    );
    const removed: string[] = [];
    const nowMs = Date.now();
    for (const entry of entries) {
      signal?.throwIfAborted();
      const path = join(directory, entry.name);
      const stats = await lstat(path).catch(() => undefined);
      if (stats === undefined) continue;
      if (nowMs - stats.mtimeMs <= STAGING_STALE_MS) continue;
      await rm(path, { recursive: true, force: true }).catch(() => undefined);
      removed.push(entry.name);
    }
    return removed;
  }

  async #readManifest(
    entryPath: string,
  ): Promise<Result<GhidraProjectManifest, GhidraProjectCacheError>> {
    let raw: string;
    try {
      raw = await readFile(
        join(entryPath, GHIDRA_PROJECT_MANIFEST_FILE),
        "utf8",
      );
    } catch (cause: unknown) {
      return err(
        this.#io(
          "Stored Ghidra project manifest is unreadable",
          entryPath,
          cause,
        ),
      );
    }
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch (cause: unknown) {
      return err(
        new GhidraProjectCacheError(
          "manifest",
          "Stored Ghidra project manifest is not valid JSON",
          entryPath,
          { cause },
        ),
      );
    }
    return parseGhidraProjectManifest(value, entryPath);
  }

  async #entryKeys(
    signal?: AbortSignal,
  ): Promise<Result<readonly string[], GhidraProjectCacheError>> {
    let entries;
    try {
      entries = await readdir(this.#root, { withFileTypes: true });
    } catch (cause: unknown) {
      // Only a missing root is an empty store; any other failure is reported so
      // `cache-list`, `cache-verify`, and `cache-prune` do not look empty.
      if (isNotFound(cause)) return ok([]);
      return err(
        this.#io("Ghidra project cache root is unreadable", this.#root, cause),
      );
    }
    signal?.throwIfAborted();
    return ok(
      entries
        .filter((entry) => entry.isDirectory() && KEY_PATTERN.test(entry.name))
        .map((entry) => entry.name)
        .sort(),
    );
  }

  async #withLock<Value>(
    key: string,
    signal: AbortSignal | undefined,
    body: () => Promise<Value>,
  ): Promise<Value> {
    const lockPath = this.#lockPath(key);
    await mkdir(join(this.#root, GHIDRA_PROJECT_LOCK_DIRECTORY), {
      recursive: true,
      mode: 0o700,
    });
    await this.#acquireLock(lockPath);
    try {
      signal?.throwIfAborted();
      return await body();
    } finally {
      await rm(lockPath, { recursive: true, force: true });
    }
  }

  async #acquireLock(lockPath: string): Promise<void> {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const handle = await open(lockPath, "wx", 0o600);
        await handle.close();
        return;
      } catch (cause: unknown) {
        if (!isAlreadyExists(cause)) throw cause;
        if (attempt === 1) throw cause;
        const age = await lstat(lockPath).then(
          (stats) => Date.now() - stats.mtimeMs,
          () => Number.POSITIVE_INFINITY,
        );
        if (age < LOCK_STALE_MS)
          throw new GhidraProjectCacheError(
            "busy",
            "Another session is publishing this Ghidra project",
            lockPath,
            { cause },
          );
        await rm(lockPath, { recursive: true, force: true });
      }
    }
  }

  async #discard(path: string): Promise<void> {
    await rm(path, { recursive: true, force: true });
  }

  #io(message: string, path: string, cause: unknown): GhidraProjectCacheError {
    return new GhidraProjectCacheError("io", message, path, { cause });
  }
}

const isAlreadyExists = (cause: unknown): boolean =>
  cause instanceof Error &&
  "code" in cause &&
  (cause as { readonly code?: string }).code === "EEXIST";

const isNotFound = (cause: unknown): boolean =>
  cause instanceof Error &&
  "code" in cause &&
  (cause as { readonly code?: string }).code === "ENOENT";
