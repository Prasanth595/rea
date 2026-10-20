import { existsSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import {
  access,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  ensureGhidraProjectCacheRoot,
  type GhidraProjectCacheRootHost,
} from "./GhidraProjectCacheRoot.js";

const roots: string[] = [];
const tempRoot = async (): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), "rea-ghidra-cache-root-"));
  roots.push(root);
  return root;
};

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

/** A native host that creates the durable root directly and always verifies. */
const privateRootHost = (
  overrides: Partial<GhidraProjectCacheRootHost> = {},
): GhidraProjectCacheRootHost => ({
  async createPrivateDirectory(root) {
    await mkdir(root, { recursive: true });
    return root;
  },
  verifyPrivateDirectory() {
    return { privateDacl: true };
  },
  ...overrides,
});

describe("POSIX cache root", () => {
  it("creates a directory before a project is stored", async () => {
    const parent = await tempRoot();
    const root = join(parent, "nested", "cache");
    await expect(
      ensureGhidraProjectCacheRoot(root, { platform: "linux" }),
    ).resolves.toEqual({ status: "ready" });
    await expect(
      lstat(root).then((stats) => stats.isDirectory()),
    ).resolves.toBe(true);
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "tightens an existing group- or world-accessible root",
    async () => {
      const root = await tempRoot();
      await chmod(root, 0o755);
      await ensureGhidraProjectCacheRoot(root, { platform: "linux" });
      const stats = await lstat(root);
      expect(stats.mode & 0o077).toBe(0);
    },
  );

  it("rejects a root that is a link", async () => {
    const parent = await tempRoot();
    const target = join(parent, "target");
    const root = join(parent, "cache");
    await mkdir(target);
    await symlink(target, root);
    await expect(
      ensureGhidraProjectCacheRoot(root, { platform: "linux" }),
    ).rejects.toMatchObject({ reason: "io", path: root });
  });
});

describe("Windows cache root", () => {
  it("creates the leaf through the native private-DACL boundary", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    const created: string[] = [];
    const verified: string[] = [];
    await ensureGhidraProjectCacheRoot(root, {
      platform: "win32",
      host: privateRootHost({
        async createPrivateDirectory(path) {
          created.push(path);
          await mkdir(path, { recursive: true });
          return path;
        },
        verifyPrivateDirectory(path) {
          verified.push(path);
          return { privateDacl: true };
        },
      }),
    });
    await expect(
      lstat(root).then((stats) => stats.isDirectory()),
    ).resolves.toBe(true);
    expect(created).toEqual([root]);
    expect(verified).toEqual([root]);
  });

  it("accepts an existing root only after native verification", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    await writeFile(join(root, "entry"), "private");
    const verified: string[] = [];
    await ensureGhidraProjectCacheRoot(root, {
      platform: "win32",
      host: privateRootHost({
        async createPrivateDirectory() {
          throw new Error("an existing root must not be recreated");
        },
        verifyPrivateDirectory(path) {
          verified.push(path);
          return { privateDacl: true };
        },
      }),
    });
    expect(verified).toEqual([root]);
    await expect(readFile(join(root, "entry"), "utf8")).resolves.toBe(
      "private",
    );
  });
});

describe("Windows cache root repair", () => {
  it("rebuilds an existing root that is not owner-only", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    await writeFile(join(root, "entry"), "stored");
    const created: string[] = [];
    const verified: string[] = [];
    // Only the root that was already there is not owner-only; the rebuilt one
    // passes the same native verification.
    let inspected = false;
    const outcome = await ensureGhidraProjectCacheRoot(root, {
      platform: "win32",
      host: privateRootHost({
        async createPrivateDirectory(path) {
          created.push(path);
          await mkdir(path, { recursive: true });
          return path;
        },
        verifyPrivateDirectory(path) {
          verified.push(path);
          if (!inspected) {
            inspected = true;
            throw new Error("Private object owner is not the current user");
          }
          return { privateDacl: true };
        },
      }),
    });
    expect(outcome).toEqual({ status: "repaired", preservedEntries: 1 });
    // The stored project survives the rebuild.
    await expect(readFile(join(root, "entry"), "utf8")).resolves.toBe("stored");
    expect(created).toEqual([root, join(root, "repair-staging")]);
    expect(verified).toEqual([root, root]);
    // The set-aside root is removed after the replacement is in place.
    await expect(readdir(parent)).resolves.toEqual(["cache"]);
  });

  it("copies the preserved projects into the private root", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    await mkdir(join(root, "staging"));
    await writeFile(join(root, "staging", "project"), "stored");
    await writeFile(join(root, "entry"), "stored");
    const original = await lstat(join(root, "entry"));
    // Only the root that was already there is not owner-only; the rebuilt one
    // passes the same native verification.
    let inspected = false;
    const outcome = await ensureGhidraProjectCacheRoot(root, {
      platform: "win32",
      host: privateRootHost({
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
      }),
    });
    expect(outcome).toEqual({ status: "repaired", preservedEntries: 2 });
    // The stored projects are carried over.
    await expect(readFile(join(root, "entry"), "utf8")).resolves.toBe("stored");
    await expect(
      readFile(join(root, "staging", "project"), "utf8"),
    ).resolves.toBe("stored");
    // The preserved projects are recreated inside the private root, so they
    // carry its owner-only DACL instead of the permissions the shared root
    // gave them. A filesystem that reports no inode number cannot show it.
    const preserved = await lstat(join(root, "entry"));
    if (original.ino !== 0) expect(preserved.ino).not.toBe(original.ino);
  });

  it("restores the previous root when the rebuild cannot start", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    await writeFile(join(root, "entry"), "stored");
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
          async createPrivateDirectory() {
            throw new Error("the native boundary is unavailable");
          },
          verifyPrivateDirectory() {
            throw new Error("Private object owner is not the current user");
          },
        }),
      }),
    ).rejects.toMatchObject({
      reason: "io",
      path: root,
      message: expect.stringContaining(
        "could not be rebuilt as a private directory",
      ),
    });
    // The previous root keeps the stored project and its name.
    await expect(readFile(join(root, "entry"), "utf8")).resolves.toBe("stored");
    await expect(readdir(parent)).resolves.toEqual(["cache"]);
  });

  it("keeps the stored project when the rebuilt root is not owner-only", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    await writeFile(join(root, "entry"), "stored");
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
          async createPrivateDirectory(path) {
            await mkdir(path, { recursive: true });
            return path;
          },
          verifyPrivateDirectory() {
            throw new Error("Private DACL contains unexpected trustees");
          },
        }),
      }),
    ).rejects.toMatchObject({
      reason: "io",
      path: root,
      message: expect.stringContaining("could not be verified as owner-only"),
    });
    // The stored project is in the rebuilt root; it is never discarded.
    await expect(readFile(join(root, "entry"), "utf8")).resolves.toBe("stored");
    await expect(readdir(parent)).resolves.toEqual(["cache"]);
  });

  it("rejects a linked root before verification", async () => {
    const parent = await tempRoot();
    const target = join(parent, "target");
    const root = join(parent, "cache");
    await mkdir(target);
    await symlink(target, root);
    let verified = false;
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
          async createPrivateDirectory() {
            throw new Error("a linked root must not be recreated");
          },
          verifyPrivateDirectory() {
            verified = true;
            return { privateDacl: true };
          },
        }),
      }),
    ).rejects.toMatchObject({ reason: "io", path: root });
    expect(verified).toBe(false);
  });
});

describe("Windows cache root repair coordination", () => {
  it("publishes a preserved project only after it is copied", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    const entry = join(root, "entry");
    await mkdir(entry);
    // A stored project with enough files that the copy runs long enough to
    // be observed while it is in progress.
    const files = 200;
    for (let index = 0; index < files; index += 1)
      await writeFile(join(entry, `file-${index}`), "stored");
    let rebuilt = false;
    const repair = ensureGhidraProjectCacheRoot(root, {
      platform: "win32",
      host: privateRootHost({
        async createPrivateDirectory(path) {
          rebuilt = true;
          await mkdir(path, { recursive: true });
          return path;
        },
        verifyPrivateDirectory() {
          // The root that was already there is not owner-only; the rebuilt
          // one passes the same native verification.
          if (!rebuilt)
            throw new Error("Private object owner is not the current user");
          return { privateDacl: true };
        },
      }),
    });
    let settled = false;
    void repair.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    // A project that is published at its final path must be complete: a
    // session that finds a half-copied project there would read it as a
    // cache hit.
    let incomplete: string | undefined;
    let locked = false;
    while (!settled) {
      await new Promise((resolve) => setTimeout(resolve, 1));
      const beside = await readdir(parent).catch((): string[] => []);
      if (beside.includes("cache.repair")) locked = true;
      const names = await readdir(root).catch((): string[] => []);
      if (!names.includes("entry")) continue;
      const published = await readdir(join(root, "entry")).catch(() => []);
      if (published.length !== files)
        incomplete = `a published project held ${published.length} of ${files} files`;
    }
    await expect(repair).resolves.toEqual({
      status: "repaired",
      preservedEntries: 1,
    });
    expect(incomplete).toBeUndefined();
    // The repair holds a lock while it runs, so another session cannot read
    // or discard the projects it is copying.
    expect(locked).toBe(true);
    await expect(readdir(join(root, "entry"))).resolves.toHaveLength(files);
  });

  it("keeps a project a concurrent publisher already stored", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    await writeFile(join(root, "entry"), "stored");
    let rebuilt = false;
    const outcome = await ensureGhidraProjectCacheRoot(root, {
      platform: "win32",
      host: privateRootHost({
        async createPrivateDirectory(path) {
          rebuilt = true;
          await mkdir(path, { recursive: true });
          if (path !== root) return path;
          // A concurrent publisher stored a project under the same name while
          // the rebuild was running.
          await mkdir(join(path, "entry"), { recursive: true });
          await writeFile(join(path, "entry", "project"), "published");
          return path;
        },
        verifyPrivateDirectory() {
          if (!rebuilt)
            throw new Error("Private object owner is not the current user");
          return { privateDacl: true };
        },
      }),
    });
    expect(outcome).toEqual({ status: "repaired", preservedEntries: 1 });
    // The project a live session stored is kept, and the copy is discarded.
    await expect(
      readFile(join(root, "entry", "project"), "utf8"),
    ).resolves.toBe("published");
  });
});

describe("Windows cache root repair locking", () => {
  it("refuses to rebuild a root another session is rebuilding", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    await writeFile(join(root, "entry"), "stored");
    // Another session holds the repair lock.
    await writeFile(join(parent, "cache.repair"), "held");
    const created: string[] = [];
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
          async createPrivateDirectory(path) {
            created.push(path);
            await mkdir(path, { recursive: true });
            return path;
          },
          verifyPrivateDirectory() {
            throw new Error("Private object owner is not the current user");
          },
        }),
      }),
    ).rejects.toMatchObject({
      reason: "busy",
      message: expect.stringContaining("Another session is rebuilding"),
    });
    // The root another session is rebuilding is left exactly as it was.
    expect(created).toEqual([]);
    await expect(readFile(join(root, "entry"), "utf8")).resolves.toBe("stored");
  });

  it("takes over a repair lock a dead session left behind", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    await writeFile(join(root, "entry"), "stored");
    const lock = join(parent, "cache.repair");
    await writeFile(lock, "abandoned");
    // The lock is older than any plausible repair, so the session that left
    // it behind is gone.
    const abandoned = new Date(Date.now() - 60 * 60 * 1000);
    await utimes(lock, abandoned, abandoned);
    let rebuilt = false;
    const outcome = await ensureGhidraProjectCacheRoot(root, {
      platform: "win32",
      host: privateRootHost({
        async createPrivateDirectory(path) {
          rebuilt = true;
          await mkdir(path, { recursive: true });
          return path;
        },
        verifyPrivateDirectory() {
          if (!rebuilt)
            throw new Error("Private object owner is not the current user");
          return { privateDacl: true };
        },
      }),
    });
    expect(outcome).toEqual({ status: "repaired", preservedEntries: 1 });
    await expect(readFile(join(root, "entry"), "utf8")).resolves.toBe("stored");
    // The lock is released once the repair completes.
    await expect(access(lock)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("releases the repair lock when the repair cannot complete", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    await writeFile(join(root, "entry"), "stored");
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
          async createPrivateDirectory() {
            throw new Error("the native boundary is unavailable");
          },
          verifyPrivateDirectory() {
            throw new Error("Private object owner is not the current user");
          },
        }),
      }),
    ).rejects.toMatchObject({ reason: "io", path: root });
    // The lock does not outlive the repair, so the next session can retry.
    await expect(access(join(parent, "cache.repair"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });
});

describe("Windows cache root repair failures", () => {
  it("keeps every stored project when the repair cannot copy it into the private root", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    const shared = join(parent, "shared");
    await mkdir(root);
    await mkdir(shared);
    await writeFile(join(root, "entry"), "stored");
    // A link cannot be carried into the private root: it would keep naming
    // the shared directory it points at.
    await symlink(shared, join(root, "shared"), "dir");
    let inspected = false;
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
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
        }),
      }),
    ).rejects.toMatchObject({
      reason: "io",
      path: root,
      message: expect.stringContaining(
        "could not be rebuilt as a private directory",
      ),
    });
    // Nothing is discarded: the previous root is back with every stored
    // project, and the entry that could not be copied is still there.
    await expect(readFile(join(root, "entry"), "utf8")).resolves.toBe("stored");
    const link = await lstat(join(root, "shared"));
    expect(link.isSymbolicLink()).toBe(true);
    await expect(readdir(parent)).resolves.toEqual(["cache", "shared"]);
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "keeps both roots and reports where the stored projects are when the repair cannot complete",
    async () => {
      const parent = await tempRoot();
      const root = join(parent, "cache");
      const shared = join(parent, "shared");
      await mkdir(root);
      await mkdir(shared);
      await writeFile(join(root, "entry"), "stored");
      await symlink(shared, join(root, "shared"), "dir");
      let inspected = false;
      await expect(
        ensureGhidraProjectCacheRoot(root, {
          platform: "win32",
          host: privateRootHost({
            async createPrivateDirectory(path) {
              await mkdir(path, { recursive: true });
              // Only the replacement cannot be removed, so both roots stay.
              // The staging directory that holds the copies is created like
              // any other private directory, or the repair could never
              // remove it.
              if (path !== root) return path;
              await mkdir(join(path, "held"));
              await writeFile(join(path, "held", "project"), "held");
              await chmod(join(path, "held"), 0o500);
              return path;
            },
            verifyPrivateDirectory() {
              if (!inspected) {
                inspected = true;
                throw new Error("Private object owner is not the current user");
              }
              return { privateDacl: true };
            },
          }),
        }),
      ).rejects.toMatchObject({
        reason: "io",
        path: root,
        message: expect.stringContaining("the previous root is preserved at"),
      });
      // The set-aside root keeps every stored project, and the message names
      // it because the replacement could not be removed.
      await expect(
        readFile(join(parent, "cache.previous-1", "entry"), "utf8"),
      ).resolves.toBe("stored");
      await expect(
        lstat(join(parent, "cache.previous-1", "shared")).then((stats) =>
          stats.isSymbolicLink(),
        ),
      ).resolves.toBe(true);
      // Restore the permissions the fixture held so the tree can be removed.
      await chmod(join(root, "held"), 0o700);
    },
  );

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "reports the set-aside root that could not be removed",
    async () => {
      const parent = await tempRoot();
      const root = join(parent, "cache");
      await mkdir(root);
      await mkdir(join(root, "entry"));
      await writeFile(join(root, "entry", "project"), "stored");
      // The stored project cannot be removed while its directory is
      // read-only, so the set-aside root survives the rebuild.
      await chmod(join(root, "entry"), 0o500);
      let inspected = false;
      const outcome = await ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
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
        }),
      });
      expect(outcome).toEqual({
        status: "repaired",
        preservedEntries: 1,
        leftoverRoot: join(parent, "cache.previous-1"),
      });
      // The private replacement holds the stored project.
      await expect(
        readFile(join(root, "entry", "project"), "utf8"),
      ).resolves.toBe("stored");
      // The set-aside root still holds a copy the principals it admits can
      // read, which is why its path is reported.
      await expect(
        readFile(join(parent, "cache.previous-1", "entry", "project"), "utf8"),
      ).resolves.toBe("stored");
      // Restore the permissions the fixture held so the tree can be removed.
      await chmod(join(parent, "cache.previous-1", "entry"), 0o700);
    },
  );
});

describe("Windows cache root repair leftovers", () => {
  /**
   * A private root beside the copies a repair that stopped part-way left
   * behind, and the directory that holds them.
   */
  const interruptedRepair = async (): Promise<{
    readonly parent: string;
    readonly root: string;
    readonly copies: string;
  }> => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    const copies = join(root, "repair-staging");
    await mkdir(join(copies, "entry"), { recursive: true });
    await writeFile(join(copies, "entry", "project"), "copied");
    return { parent, root, copies };
  };

  it("reclaims the copies a repair that stopped part-way left behind", async () => {
    const { root, copies } = await interruptedRepair();
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost(),
      }),
    ).resolves.toEqual({ status: "ready" });
    // The private root is accepted as ready, so nothing else would ever
    // remove the copies the repair left behind.
    await expect(lstat(copies)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("leaves the copies a running repair is making alone", async () => {
    const { parent, root, copies } = await interruptedRepair();
    // Another session holds the repair lock, so its copies are still in use.
    await writeFile(join(parent, "cache.repair"), "held");
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost(),
      }),
    ).resolves.toEqual({ status: "ready" });
    await expect(
      lstat(copies).then((stats) => stats.isDirectory()),
    ).resolves.toBe(true);
  });

  it("reclaims the copies a dead session's repair left behind", async () => {
    const { parent, root, copies } = await interruptedRepair();
    const lock = join(parent, "cache.repair");
    await writeFile(lock, "abandoned");
    // The lock is older than any plausible repair, so the session that left
    // it behind is gone.
    const abandoned = new Date(Date.now() - 60 * 60 * 1000);
    await utimes(lock, abandoned, abandoned);
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost(),
      }),
    ).resolves.toEqual({ status: "ready" });
    await expect(lstat(copies)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("keeps a directory beside the root that REA did not create", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await mkdir(root);
    // The cache root is a path the caller chose, so a sibling of it can hold
    // anything. REA never created this one and does not own it.
    const sibling = join(parent, "cache.repair-staging");
    await mkdir(sibling);
    await writeFile(join(sibling, "project"), "not REA's");
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost(),
      }),
    ).resolves.toEqual({ status: "ready" });
    // The reclamation only removes state inside the store root, so the
    // unrelated directory and its contents survive.
    await expect(readFile(join(sibling, "project"), "utf8")).resolves.toBe(
      "not REA's",
    );
  });

  it("reclaims the copies while it holds the repair lock", async () => {
    const { parent, root, copies } = await interruptedRepair();
    // Enough copies that the reclamation takes several steps, so the lock it
    // holds can be observed while it runs.
    for (let index = 0; index < 100; index += 1)
      await writeFile(join(copies, `copy-${index}`), "copied");
    const lock = join(parent, "cache.repair");
    const reclamation = ensureGhidraProjectCacheRoot(root, {
      platform: "win32",
      host: privateRootHost(),
    });
    let settled = false;
    void reclamation.then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    // The copies are reclaimed under the repair lock, so a repair that
    // starts while they are measured cannot lose them to the reclamation.
    let held = false;
    while (!settled) {
      await new Promise((resolve) => setImmediate(resolve));
      if (existsSync(lock)) held = true;
    }
    await expect(reclamation).resolves.toEqual({ status: "ready" });
    expect(held).toBe(true);
    await expect(lstat(copies)).rejects.toMatchObject({ code: "ENOENT" });
    // The lock is released once the copies are gone, so the next session can
    // rebuild the root.
    await expect(access(lock)).rejects.toMatchObject({ code: "ENOENT" });
  });
});

describe("Windows cache root admission", () => {
  it("rejects an existing root that is not a directory", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await writeFile(root, "not a directory");
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
          async createPrivateDirectory() {
            throw new Error("a file root must not be recreated");
          },
          verifyPrivateDirectory() {
            throw new Error("a file root must not be verified");
          },
        }),
      }),
    ).rejects.toMatchObject({
      reason: "io",
      path: root,
      message: expect.stringContaining("must be a directory"),
    });
  });

  it("reports a root that could not be created privately", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    const created: string[] = [];
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
          async createPrivateDirectory(path) {
            // The native leaf is reported but never created, so the rename
            // fails and no root appears.
            created.push(path);
            throw new Error("the native boundary is unavailable");
          },
          verifyPrivateDirectory() {
            throw new Error("an unverified root must not be accepted");
          },
        }),
      }),
    ).rejects.toMatchObject({
      reason: "io",
      path: root,
      message: expect.stringContaining("could not be created privately"),
    });
    expect(created).toHaveLength(1);
    await expect(access(root)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects a created root that native verification does not confirm", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
          async createPrivateDirectory(path) {
            await mkdir(path, { recursive: true });
            return path;
          },
          verifyPrivateDirectory() {
            throw new Error("unexpected trustee");
          },
        }),
      }),
    ).rejects.toMatchObject({
      reason: "io",
      path: root,
      message: expect.stringContaining("could not be verified as owner-only"),
    });
  });
});

describe("Windows cache root concurrency", () => {
  it("accepts a root a concurrent initializer created only after native verification", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    const created: string[] = [];
    const verified: string[] = [];
    await ensureGhidraProjectCacheRoot(root, {
      platform: "win32",
      host: privateRootHost({
        async createPrivateDirectory(path) {
          created.push(path);
          // The concurrent initializer wins the name and holds a populated
          // directory, so the durable root cannot be renamed over it.
          mkdirSync(root, { recursive: true });
          writeFileSync(join(root, "entry"), "private");
          throw new Error("the name was taken by a concurrent initializer");
        },
        verifyPrivateDirectory(path) {
          verified.push(path);
          return { privateDacl: true };
        },
      }),
    });
    // A durable root was attempted, so the rename was tried and lost.
    expect(created).toHaveLength(1);
    expect(verified).toEqual([root]);
    // The root the concurrent initializer owns is kept, not replaced.
    await expect(readFile(join(root, "entry"), "utf8")).resolves.toBe(
      "private",
    );
  });

  it("rejects a root a concurrent initializer created that is not owner-only", async () => {
    const parent = await tempRoot();
    const root = join(parent, "cache");
    const created: string[] = [];
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
          async createPrivateDirectory(path) {
            created.push(path);
            // The concurrent initializer wins the name with a shared directory.
            mkdirSync(root, { recursive: true });
            writeFileSync(join(root, "entry"), "shared");
            throw new Error("the name was taken by a concurrent initializer");
          },
          verifyPrivateDirectory() {
            throw new Error("unexpected trustee");
          },
        }),
      }),
    ).rejects.toMatchObject({
      reason: "io",
      path: root,
      message: expect.stringContaining("could not be verified as owner-only"),
    });
    expect(created).toHaveLength(1);
  });

  it("rejects a linked root a concurrent initializer created", async () => {
    const parent = await tempRoot();
    const target = join(parent, "target");
    const root = join(parent, "cache");
    const created: string[] = [];
    const verified: string[] = [];
    await expect(
      ensureGhidraProjectCacheRoot(root, {
        platform: "win32",
        host: privateRootHost({
          async createPrivateDirectory(path) {
            created.push(path);
            // The concurrent initializer wins the name with a link.
            mkdirSync(target);
            symlinkSync(target, root, "dir");
            throw new Error("the name was taken by a concurrent initializer");
          },
          verifyPrivateDirectory(path) {
            verified.push(path);
            return { privateDacl: true };
          },
        }),
      }),
    ).rejects.toMatchObject({
      reason: "io",
      path: root,
      message: expect.stringContaining("must be a directory"),
    });
    // A link is refused before native verification.
    expect(verified).toEqual([]);
    expect(created).toHaveLength(1);
  });
});
