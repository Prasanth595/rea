import { createReadStream, createWriteStream } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  rm,
  utimes,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { pipeline } from "node:stream/promises";

import { z } from "zod";

import {
  requireWindowsNativeAuthority,
  type WindowsNativeAuthority,
} from "../../windows/WindowsNativeLoader.js";
import { ghidraProjectDirectoryBytes } from "./GhidraProjectLayout.js";
import {
  GHIDRA_PROJECT_REPAIR_STAGING_DIRECTORY,
  GhidraProjectCacheError,
} from "./GhidraProjectCacheTypes.js";

const nativeIdentitySchema = z
  .object({ privateDacl: z.literal(true) })
  .passthrough();
const createdRuntimeSchema = z
  .object({ path: z.string().min(1), handle: z.unknown() })
  .passthrough();

/** Name of the durable directory created inside a native runtime root. */
const DURABLE_ROOT_LEAF = "root";

/**
 * Suffix of the file beside the cache root that serialises a repair.
 *
 * The lock lives beside the root because the repair replaces the root itself,
 * so a lock inside it would not survive the replacement.
 */
const REPAIR_LOCK_SUFFIX = ".repair";

/**
 * A repair lock that has been silent for longer than this belongs to a
 * session that died, and is taken over so one crash does not disable the
 * cache for good.
 */
const REPAIR_LOCK_STALE_MS = 10 * 60 * 1000;

/** Native operations that establish and verify a durable private cache root. */
export interface GhidraProjectCacheRootHost {
  /**
   * Create a private directory at `path` and return its path.
   *
   * The directory must carry a protected, owner-only DACL and must not stay
   * sealed by an open native handle: Windows refuses a path-based rename into
   * a sealed directory, so a sealed root would refuse the stored projects the
   * store moves into it and the entries it publishes.
   */
  createPrivateDirectory(path: string): Promise<string>;
  /** Throw unless `path` is an owner-only directory with a protected DACL. */
  verifyPrivateDirectory(path: string): unknown;
}

/**
 * What preparing the cache root did.
 *
 * A root that native verification refused is rebuilt as a private directory
 * rather than disabling the cache, so a caller can report the repair and the
 * stored projects that survived it.
 */
export type GhidraProjectCacheRootPreparation =
  | { readonly status: "ready" }
  | {
      /** A root that was not owner-only was rebuilt as a private directory. */
      readonly status: "repaired";
      /** The stored children carried over from the previous root. */
      readonly preservedEntries: number;
      /**
       * The set-aside root that survived the rebuild. It still holds a copy
       * of the stored projects that the principals its DACL admits can read,
       * so it is reported instead of left unmentioned.
       */
      readonly leftoverRoot?: string;
    };

const systemRootHost = (): GhidraProjectCacheRootHost => {
  const native = (): WindowsNativeAuthority => requireWindowsNativeAuthority();
  return {
    async createPrivateDirectory(path: string): Promise<string> {
      const authority = native();
      const observed = authority.call("runtime_create", [
        dirname(path),
        "rea-ghidra-cache-",
      ]);
      const runtime = createdRuntimeSchema.safeParse(observed);
      if (!runtime.success)
        throw new Error(
          `REA Windows native runtime root is invalid: ${runtime.error.message}`,
        );
      try {
        // The runtime root stays sealed by the handle that owns it. A child
        // created relative to the runtime root carries the same private DACL
        // and is not sealed, so the durable directory can be written by path.
        authority.call("runtime_mkdir", [
          runtime.data.handle,
          DURABLE_ROOT_LEAF,
        ]);
        await rename(join(runtime.data.path, DURABLE_ROOT_LEAF), path);
        return path;
      } finally {
        // The runtime root is empty once the durable directory is in place.
        // Closing it releases the native handles without touching the cache.
        try {
          authority.call("runtime_close", [runtime.data.handle]);
        } catch {
          // The handles are released when the runtime wrapper is collected.
        }
      }
    },
    verifyPrivateDirectory(path: string): unknown {
      const verified = native().call("cutter_bridge_verify_directory", [path]);
      nativeIdentitySchema.parse(verified);
      return verified;
    },
  } satisfies GhidraProjectCacheRootHost;
};

const isNotFound = (cause: unknown): boolean =>
  typeof cause === "object" &&
  cause !== null &&
  "code" in cause &&
  cause.code === "ENOENT";

const isAlreadyExists = (cause: unknown): boolean =>
  typeof cause === "object" &&
  cause !== null &&
  "code" in cause &&
  cause.code === "EEXIST";

const rootError = (
  message: string,
  path: string,
  cause?: unknown,
): GhidraProjectCacheError =>
  new GhidraProjectCacheError(
    "io",
    message,
    path,
    cause === undefined ? undefined : { cause },
  );

const assertDirectory = async (root: string): Promise<void> => {
  const stats = await lstat(root).catch((cause: unknown) => {
    if (isNotFound(cause))
      throw rootError("Ghidra project cache root does not exist", root, cause);
    throw cause;
  });
  if (!stats.isDirectory() || stats.isSymbolicLink())
    throw rootError(
      "Ghidra project cache root must be a directory, not a link",
      root,
    );
};

const ensurePosixRoot = async (root: string): Promise<void> => {
  await mkdir(root, { recursive: true, mode: 0o700 });
  await assertDirectory(root);
  // mkdir does not tighten an existing directory. Only POSIX exposes owner
  // bits to Node, and a widened root would expose every stored project.
  if (process.getuid === undefined) return;
  const before = await lstat(root);
  if ((before.mode & 0o077) === 0) return;
  await chmod(root, 0o700);
  const after = await lstat(root);
  if ((after.mode & 0o077) !== 0)
    throw rootError(
      "Ghidra project cache root permissions could not be made owner-only",
      root,
    );
};

/**
 * Move the current root aside so the configured path is free while the
 * replacement is built.
 *
 * The previous root keeps the stored projects until the replacement is in
 * place, so a failed repair restores it instead of losing the cache.
 */
const quarantineRoot = async (root: string): Promise<string> => {
  const parent = dirname(root);
  const name = basename(root);
  for (let attempt = 1; attempt <= 64; attempt += 1) {
    const candidate = join(parent, `${name}.previous-${attempt}`);
    const taken = await lstat(candidate).catch(() => undefined);
    if (taken !== undefined) continue;
    await rename(root, candidate);
    return candidate;
  }
  throw rootError(
    "Ghidra project cache root could not be set aside for repair",
    root,
  );
};

/**
 * Copy every child of `from` into `to`.
 *
 * The copy is deliberate. A relocated child keeps the permissions it was
 * created with, so a child of a shared root stays readable by the principals
 * its DACL admits even inside a private root: Windows accounts hold
 * SeChangeNotifyPrivilege, which bypasses the traverse check on the private
 * parent. A copy created inside the private root inherits the root's
 * owner-only DACL, so the preserved projects are private like the root that
 * holds them.
 *
 * `keepAlive` runs before every entry that is copied, so a repair that holds
 * a lock for a long copy can keep the lock from looking abandoned.
 *
 * `skip` names a child that is not carried over. The copies a repair that
 * stopped part-way left behind are not stored entries, and publishing them
 * would place a directory where this repair publishes its own copies.
 */
const copyDirectoryContent = async (
  from: string,
  to: string,
  keepAlive: () => Promise<void>,
  skip: string,
): Promise<number> => {
  const names = await readdir(from);
  let copied = 0;
  for (const name of names) {
    if (name === skip) continue;
    await keepAlive();
    await copyCacheEntry(join(from, name), join(to, name), keepAlive);
    copied += 1;
  }
  return copied;
};

/**
 * Copy one stored entry into the repair staging, refusing what it cannot
 * hold.
 */
const copyCacheEntry = async (
  from: string,
  to: string,
  keepAlive: () => Promise<void>,
): Promise<void> => {
  await keepAlive();
  const stats = await lstat(from);
  if (stats.isSymbolicLink())
    throw rootError(
      "Ghidra project cache root holds a link that cannot be copied into a private directory",
      from,
    );
  if (stats.isDirectory()) {
    await mkdir(to, { recursive: true, mode: 0o700 });
    for (const name of await readdir(from))
      await copyCacheEntry(join(from, name), join(to, name), keepAlive);
    await utimes(to, stats.atime, stats.mtime);
    return;
  }
  if (!stats.isFile())
    throw rootError(
      "Ghidra project cache root holds an entry that cannot be copied into a private directory",
      from,
    );
  await pipeline(
    createReadStream(from),
    createWriteStream(to, { flags: "wx", mode: 0o600 }),
  );
  await utimes(to, stats.atime, stats.mtime);
};

/**
 * Publish every copied project at its final path inside the private root.
 *
 * A copy is renamed into place, so a session never finds an unfinished
 * project at the path it reads: a repair that stops part-way leaves the
 * copied projects in the staging directory instead of publishing a truncated
 * one. A name a concurrent publisher already took keeps the published entry
 * and discards the copy, so a repair never replaces a project a live session
 * stored.
 */
const publishPreservedProjects = async (
  staging: string,
  root: string,
): Promise<void> => {
  for (const name of await readdir(staging)) {
    const copied = join(staging, name);
    const published = join(root, name);
    try {
      await rename(copied, published);
    } catch (cause: unknown) {
      const existing = await lstat(published).catch(() => undefined);
      if (existing === undefined) throw cause;
      // A concurrent publisher won the name; its entry is the live one.
      await rm(copied, { recursive: true, force: true });
    }
  }
};

/** Path of the file that serialises a root repair between sessions. */
const repairLockPath = (root: string): string =>
  join(dirname(root), `${basename(root)}${REPAIR_LOCK_SUFFIX}`);

/**
 * Path of the directory that holds the copies of the preserved projects.
 *
 * The path is inside the store root, because the root is the one directory
 * REA owns: the cache root is the store's own directory, so a directory
 * inside it is REA's to create and to reclaim. A directory beside the root
 * would sit in a directory the caller chose, where reclaiming it could
 * delete a sibling REA never created.
 *
 * The copies are found by their own name and are never mistaken for a stored
 * project, because a stored entry is named by its digest.
 */
const repairStagingPath = (root: string): string =>
  join(root, GHIDRA_PROJECT_REPAIR_STAGING_DIRECTORY);

/**
 * How long the repair lock beside the root has been silent.
 *
 * A lock that does not exist is as old as it can be: no session holds it.
 */
const repairLockAge = async (root: string): Promise<number> =>
  await lstat(repairLockPath(root)).then(
    (stats) => Date.now() - stats.mtimeMs,
    () => Number.POSITIVE_INFINITY,
  );

/** A held repair lock and what taking it proved about the root. */
interface RepairLock {
  /** The file that serialises the repair. */
  readonly path: string;
  /**
   * Another session held the lock, so the root may have been created or
   * rebuilt while this session waited for it.
   */
  readonly contended: boolean;
}

/**
 * Take the repair lock without waiting for it.
 *
 * Returns `undefined` when another live session holds the lock, so a caller
 * that only reclaims what a repair left behind steps aside instead of
 * reporting a busy root. A lock a dead session left behind is taken over, so
 * one crash does not leave the copies of a repair on the disk for good.
 */
const tryAcquireRepairLock = async (
  root: string,
): Promise<RepairLock | undefined> => {
  const path = repairLockPath(root);
  const take = async (): Promise<void> => {
    const handle = await open(path, "wx", 0o600);
    await handle.close();
  };
  try {
    await take();
    return { path, contended: false };
  } catch (cause: unknown) {
    if (!isAlreadyExists(cause)) throw cause;
  }
  // A lock a live session holds is not stolen.
  if ((await repairLockAge(root)) < REPAIR_LOCK_STALE_MS) return undefined;
  await rm(path, { force: true });
  try {
    await take();
  } catch (cause: unknown) {
    if (!isAlreadyExists(cause)) throw cause;
    // Another session took the abandoned lock over first.
    return undefined;
  }
  return { path, contended: true };
};

/**
 * Take the repair lock, so only one session changes the cache root.
 *
 * A lock a live session holds is not stolen: the caller reports the root as
 * busy instead of changing a root another session is rebuilding, so no
 * session can read or discard a project while it is still being copied. A
 * lock that has been silent for longer than any plausible repair belongs to a
 * session that died, and is taken over so one crash does not disable the
 * cache for good.
 */
const acquireRepairLock = async (root: string): Promise<RepairLock> => {
  const lock = await tryAcquireRepairLock(root);
  if (lock !== undefined) return lock;
  throw new GhidraProjectCacheError(
    "busy",
    "Another session is rebuilding the Ghidra project cache root",
    repairLockPath(root),
  );
};

/** Release the repair lock so another session can rebuild the root. */
const releaseRepairLock = async (path: string): Promise<void> => {
  await rm(path, { force: true }).catch(() => undefined);
};

/** Keep the repair lock alive while the preserved projects are copied. */
const keepRepairLockAlive = async (lock: string): Promise<void> => {
  const now = new Date();
  await utimes(lock, now, now).catch(() => undefined);
};

/** A repair copy directory that was reclaimed, and the bytes it held. */
export interface GhidraProjectCacheRootReclaim {
  /** The reclaimed directory inside the cache root. */
  readonly path: string;
  /** The bytes the reclaimed copies occupied. */
  readonly bytes: number;
}

/**
 * Reclaim the copies a repair that stopped part-way left behind.
 *
 * A repair copies the stored projects into a staging directory inside the
 * root and publishes each one by a rename. A session that stops while it
 * copies leaves that directory behind, and the next session accepts the
 * private root as ready, so the copies stay there for good: they are not
 * stored entries, so no prune counts or removes them.
 *
 * The copies are reclaimed under the repair lock beside the root, so a
 * repair that is still running keeps them: reclaiming them would break the
 * repair that is copying them, and a reclamation that measured the copies
 * while another session recreated them would delete that session's live
 * copies. A lock that has been silent for longer than any plausible repair
 * belongs to a session that died, so the copies it left are reclaimed with
 * it. A copy that cannot be removed stays in place rather than being
 * reported as reclaimed.
 */
export const reclaimGhidraProjectCacheRootRepairs = async (
  root: string,
): Promise<readonly GhidraProjectCacheRootReclaim[]> => {
  const path = repairStagingPath(root);
  // No repair left copies behind, so there is nothing to reclaim and no
  // reason to take the lock.
  if ((await lstat(path).catch(() => undefined)) === undefined) return [];
  // A lock that cannot be taken leaves the copies in place: reclaiming what
  // a repair left behind is an opportunistic cleanup, and failing it must
  // not disable the cache.
  const lock = await tryAcquireRepairLock(root).catch(() => undefined);
  if (lock === undefined) return [];
  try {
    // The repair that owned the copies may have published and removed them
    // while this session waited for the lock.
    if ((await lstat(path).catch(() => undefined)) === undefined) return [];
    const bytes = await ghidraProjectDirectoryBytes(path);
    const removed = await rm(path, { recursive: true, force: true }).then(
      () => true,
      () => false,
    );
    return removed ? [{ path, bytes }] : [];
  } finally {
    await releaseRepairLock(lock.path);
  }
};

/** What rebuilding a root that was not owner-only achieved. */
interface WindowsRootRepair {
  /** The stored children copied into the private replacement. */
  readonly preserved: number;
  /** The set-aside root that survived the rebuild, when one did. */
  readonly leftover: string | undefined;
}

/**
 * Rebuild a root that native verification refused as a private directory.
 *
 * A root that is not owner-only keeps every stored project readable by the
 * principals its DACL admits, and the store cannot use it at all. The stored
 * children are copied into a private root that replaces it, so the cache
 * keeps working instead of being disabled for the whole session, and the
 * copies are private like the root that holds them.
 *
 * The copies are made in a private staging directory inside the private root
 * and published one at a time, so a repair that stops part-way never leaves
 * an unfinished project at the path a session reads. The staging directory
 * is named by the store, so the copies a repair that stopped part-way left
 * behind are found and reclaimed instead of filling the disk.
 */
const replaceWindowsRoot = async (
  root: string,
  host: GhidraProjectCacheRootHost,
  lock: string,
): Promise<WindowsRootRepair> => {
  const previous = await quarantineRoot(root);
  try {
    await host.createPrivateDirectory(root);
  } catch (failure: unknown) {
    throw await rebuildFailure(root, previous, failure);
  }
  try {
    // The copy writes into the replacement, so the destination must be the
    // directory the native boundary created and not a link in its place.
    await assertDirectory(root);
  } catch (failure: unknown) {
    throw await rebuildFailure(root, previous, failure);
  }
  try {
    // The replacement is verified before a stored project is copied into it,
    // so a root that is not owner-only never receives the preserved projects.
    host.verifyPrivateDirectory(root);
  } catch (verification: unknown) {
    const restored = await restoreQuarantinedRoot(previous, root);
    throw rootError(
      repairFailureMessage(
        "Ghidra project cache root could not be verified as owner-only",
        previous,
        restored,
      ),
      root,
      verification,
    );
  }
  const staging = repairStagingPath(root);
  let preserved: number;
  try {
    // The copies are made in a private directory of their own, so they carry
    // an owner-only DACL while they are copied and are never mistaken for a
    // stored project.
    await host.createPrivateDirectory(staging);
    preserved = await copyDirectoryContent(
      previous,
      staging,
      () => keepRepairLockAlive(lock),
      GHIDRA_PROJECT_REPAIR_STAGING_DIRECTORY,
    );
    await publishPreservedProjects(staging, root);
  } catch (failure: unknown) {
    throw await rebuildFailure(root, previous, failure);
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined);
  }
  // The set-aside root is redundant once every stored project is published in
  // the private replacement. A root that survives the removal still holds a
  // copy the principals it admits can read, so its path is reported.
  return { preserved, leftover: await removeQuarantinedRoot(previous) };
};

/**
 * Report a repair that could not complete, keeping the stored projects.
 *
 * The set-aside root holds every stored project until the replacement is in
 * place, so it is put back when the repair fails. When it cannot be put
 * back, both directories stay in place and the caller reports their paths.
 */
const rebuildFailure = async (
  root: string,
  previous: string,
  failure: unknown,
): Promise<GhidraProjectCacheError> => {
  const restored = await restoreQuarantinedRoot(previous, root);
  return rootError(
    repairFailureMessage(
      "Ghidra project cache root is not an owner-only directory and could not be rebuilt as a private directory",
      previous,
      restored,
    ),
    root,
    failure,
  );
};

/** Name the set-aside root when the stored projects stay where they were. */
const repairFailureMessage = (
  summary: string,
  previous: string,
  restored: boolean,
): string =>
  restored
    ? summary
    : `${summary}; the previous root is preserved at ${previous}`;

/**
 * Put the set-aside root back when a repair cannot complete.
 *
 * The replacement holds copies of the set-aside root's children, never the
 * only copy of a stored project, so it can be removed without losing one.
 * The set-aside root keeps every stored project until the replacement is in
 * place, so it is put back here. Returns whether the configured path holds
 * the previous root again; when it does not, the caller reports where the
 * stored projects were preserved.
 */
const restoreQuarantinedRoot = async (
  previous: string,
  root: string,
): Promise<boolean> => {
  const removed = await rm(root, { recursive: true, force: true }).then(
    () => true,
    () => false,
  );
  if (!removed) return false;
  try {
    await rename(previous, root);
    return true;
  } catch {
    return false;
  }
};

/**
 * Remove the set-aside root once the private replacement holds every project.
 *
 * Returns the path of a root that survived the removal. It still holds a
 * copy of the stored projects that the principals it admits can read, so the
 * caller reports it instead of leaving it unmentioned.
 */
const removeQuarantinedRoot = async (
  previous: string,
): Promise<string | undefined> => {
  const removed = await rm(previous, { recursive: true, force: true }).then(
    () => true,
    () => false,
  );
  return removed ? undefined : previous;
};

/**
 * What the cache root is now: a verified private root, a root that has to be
 * rebuilt as a private directory, or a root that does not exist yet.
 */
const inspectWindowsRoot = async (
  root: string,
  host: GhidraProjectCacheRootHost,
): Promise<"ready" | "rebuild" | "missing"> => {
  const existing = await lstat(root).catch((cause: unknown) => {
    if (isNotFound(cause)) return undefined;
    throw cause;
  });
  if (existing === undefined) return "missing";
  if (!existing.isDirectory() || existing.isSymbolicLink())
    throw rootError(
      "Ghidra project cache root must be a directory, not a link",
      root,
    );
  try {
    host.verifyPrivateDirectory(root);
    return "ready";
  } catch {
    // POSIX tightens a widened root in place. Windows cannot express an
    // owner-only DACL, so the root is rebuilt as a private directory and the
    // stored projects are copied into it.
    return "rebuild";
  }
};

/** Create the cache root through the native private-DACL boundary. */
const createWindowsRoot = async (
  root: string,
  host: GhidraProjectCacheRootHost,
): Promise<void> => {
  try {
    await host.createPrivateDirectory(root);
  } catch (cause: unknown) {
    // A concurrent initializer may have won the name. Accept only a root that
    // then passes the same private-DACL verification.
    const raced = await lstat(root).catch(() => undefined);
    if (raced === undefined)
      throw rootError(
        "Ghidra project cache root could not be created privately",
        root,
        cause,
      );
  }
  await assertDirectory(root);
  try {
    host.verifyPrivateDirectory(root);
  } catch (cause: unknown) {
    throw rootError(
      "Ghidra project cache root could not be verified as owner-only",
      root,
      cause,
    );
  }
};

const ensureWindowsRoot = async (
  root: string,
  host: GhidraProjectCacheRootHost,
): Promise<GhidraProjectCacheRootPreparation> => {
  // Only the leaf is private. Its protected, inheritable DACL covers every
  // staging copy, entry, lease, and lock created beneath it.
  await mkdir(dirname(root), { recursive: true });
  const initial = await inspectWindowsRoot(root, host);
  if (initial === "ready") return { status: "ready" };
  // Creating or replacing the root changes what every other session sees, so
  // it happens under the repair lock. A session that finds the lock held does
  // not change a root another session is rebuilding.
  const lock = await acquireRepairLock(root);
  try {
    // Another session held the lock, so it may have created or rebuilt the
    // root while this one waited for it.
    const state = lock.contended
      ? await inspectWindowsRoot(root, host)
      : initial;
    if (state === "ready") return { status: "ready" };
    if (state === "rebuild") {
      const repair = await replaceWindowsRoot(root, host, lock.path);
      return {
        status: "repaired",
        preservedEntries: repair.preserved,
        ...(repair.leftover === undefined
          ? {}
          : { leftoverRoot: repair.leftover }),
      };
    }
    await createWindowsRoot(root, host);
    return { status: "ready" };
  } finally {
    await releaseRepairLock(lock.path);
  }
};

/**
 * Prepare the cache root for the platform that holds it.
 *
 * A POSIX root is created owner-only and an existing widened root is
 * tightened. A Windows root is created through the native protected-DACL
 * boundary, and a root that does not pass that verification is rebuilt as a
 * private directory, because POSIX mode bits do not set a Windows DACL.
 */
const prepareCacheRoot = async (
  root: string,
  options: {
    readonly platform?: NodeJS.Platform;
    readonly host?: GhidraProjectCacheRootHost;
  },
): Promise<GhidraProjectCacheRootPreparation> => {
  if ((options.platform ?? process.platform) === "win32")
    return await ensureWindowsRoot(root, options.host ?? systemRootHost());
  await ensurePosixRoot(root);
  return { status: "ready" };
};

/**
 * Establish the durable cache root before any project bytes are written.
 *
 * POSIX roots are created owner-only and existing widened roots are tightened.
 * Windows roots are created through the native protected-DACL boundary; an
 * existing root that does not pass it is rebuilt as a private directory that
 * keeps the stored projects, because POSIX mode bits do not set a Windows
 * DACL.
 *
 * The copies a repair that stopped part-way left behind are reclaimed here,
 * so they cannot outlive the session that left them: the next session
 * accepts the private root as ready, and nothing else would ever remove
 * them.
 */
export const ensureGhidraProjectCacheRoot = async (
  root: string,
  options: {
    readonly platform?: NodeJS.Platform;
    readonly host?: GhidraProjectCacheRootHost;
  } = {},
): Promise<GhidraProjectCacheRootPreparation> => {
  try {
    const preparation = await prepareCacheRoot(root, options);
    await reclaimGhidraProjectCacheRootRepairs(root);
    return preparation;
  } catch (cause: unknown) {
    if (cause instanceof GhidraProjectCacheError) throw cause;
    throw rootError(
      "Ghidra project cache root could not be prepared",
      root,
      cause,
    );
  }
};
