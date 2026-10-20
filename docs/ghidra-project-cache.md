# Ghidra project cache

A fresh Ghidra import plus auto-analysis is paid on every `open_binary`. Large
targets can need many minutes, and an MCP restart re-pays it. The project cache
stores a previously analyzed program under REA's managed data directory and
reuses it in a later session for the same target and analysis inputs.

The fresh-import path runs `analyzeHeadless` with `-readOnly -deleteProject`, so
Ghidra never saves the program and nothing is reused. The cache instead imports
once **without** `-readOnly`, keeps the saved project, and opens it later with
`-process -noanalysis -readOnly` — the same read-only open the manual
pre-imported-project workflow uses (see
[installation](installation.md#opening-a-pre-imported-ghidra-project)).

## Enabling

| Variable                                | Meaning                                                  | Default                             |
| --------------------------------------- | -------------------------------------------------------- | ----------------------------------- |
| `REA_GHIDRA_PROJECT_CACHE`              | `off`, `read` (reuse only), or `on` (reuse and populate) | `off`                               |
| `REA_GHIDRA_PROJECT_CACHE_DIR`          | absolute cache root                                      | `<home>/.rea/cache/ghidra-projects` |
| `REA_GHIDRA_PROJECT_CACHE_MAX_BYTES`    | size ceiling; oldest entries are pruned first            | 10 GiB                              |
| `REA_GHIDRA_PROJECT_CACHE_MAX_AGE_DAYS` | discard entries older than this many days                | unset (no age limit)                |

The cache and `REA_GHIDRA_EXISTING_PROJECT` are mutually exclusive: both select
saved project state, and combining them is a configuration error.

```powershell
$env:REA_GHIDRA_PROJECT_CACHE = "on"
```

`rea uninstall --purge-data` removes the cache, because it lives under
`<home>/.rea/cache`.

## Identity

A stored project is selected by a key derived from the target SHA-256, the
Ghidra provider version, the JVM, the platform, and the final import profile
digest (language, loader, seeds, disabled analyzers, extensions, and the
provider-pinned lanes). A change to any result-affecting input selects a
different key, so a rebuilt Ghidra or a different import profile never reuses a
stale project.

For a REA-managed session the committed analysis profile is **open-mode
independent**: how the program was obtained (fresh import or cache hit) is
provenance, not analysis identity. A cache miss and a later cache hit therefore
commit the same profile digest for one target, so a retained analysis snapshot
([Save and reuse analysis snapshots](cli.md#save-and-reuse-analysis-snapshots))
replays in the later session.

## Lifecycle and safety

- The cache root is owner-only. A POSIX root is created `0700` (or tightened
  before use); on Windows the root is created through REA's native
  protected-DACL boundary. An existing Windows root that does not pass that
  verification is rebuilt as a private directory that keeps the stored
  projects, because a root that other principals can read is unusable for the
  store. The rebuild copies the stored projects into the private replacement,
  so they carry its owner-only DACL instead of the permissions the shared root
  gave them. The rebuild keeps the previous root until every project is
  copied, and a rebuild that cannot complete leaves the stored projects where
  they were.
- The rebuild copies each stored project into a private staging directory
  inside the root and publishes it by an atomic rename, so a project is never
  visible at its final path while it is still being copied. A rebuild that
  stops part-way therefore leaves no half-copied project that a later session
  could read as a cache hit; the next session imports the target again and
  rebuilds it.
- A rebuild that is interrupted leaves its unfinished copies in that staging
  directory. The store never counts them, because they are not stored entries,
  so the next session and `cache-prune` reclaim them instead of letting them
  fill the disk for good. The copies of a rebuild that is still running are
  left alone: the rebuild holds a lock beside the root, and the reclamation
  takes that same lock before it measures and removes the copies, so it can
  never delete the copies of a rebuild that is running. A lock left behind by
  a session that died is treated as abandoned, and the copies it left are
  reclaimed with it.
- The staging directory is inside the cache root, which is the one directory
  REA owns, so the reclamation only removes state REA created. A directory
  beside the root is left alone, even when it carries the name of the staging
  directory.
- One session rebuilds the root at a time. The rebuild holds a lock beside the
  root, and a session that finds the lock held reports the root as busy
  instead of reading or discarding a project another session is copying. A
  lock left behind by a session that died is taken over once it has been
  silent for longer than any plausible rebuild.
- **Miss** imports writable into a private runtime project; when the session
  closes after a clean, complete, mutation-free analysis the saved project is
  copied into the cache and published by an atomic rename under a per-key lock.
  A concurrent publisher that loses the race discards its copy.
- **Hit** copies the stored project into the private runtime and opens it
  read-only; the stored entry is never modified.
- A session that issued a database mutation (`annotate_native_function`, name
  writes) does not publish, so client annotations are never served to a later
  session as engine analysis.
- Entries are admitted only as an expanded Ghidra project (a regular
  `rea-project.gpr` marker and a `rea-project.rep` directory) with no
  symlink/reparse; an unreadable or mismatched entry is discarded and reported,
  and the session rebuilds instead.
- On a hit REA verifies the manifest and the cheap identity fields; the full
  per-file digest is recorded at publish for integrity checks rather than
  re-hashed on every open.
- An entry older than `REA_GHIDRA_PROJECT_CACHE_MAX_AGE_DAYS` is never reused.
  The lookup refuses it and removes it, so the session rebuilds the project
  with a fresh import that can replace it in the store. An entry another
  session is still reading is left in place, and the refusal is reported in
  the session Evidence. The lookup and `cache-prune` apply the same age rule.

## Managing the cache

```sh
rea cache-list            # stored projects, sizes, and keys
rea cache-verify          # re-check manifests and digests
rea cache-verify --repair # also remove corrupt entries
rea cache-prune           # enforce the size ceiling now
rea cache-remove <key>    # drop one stored project
```

`cache-list` reports the cache directory, mode, ceiling, and each entry's key,
stored program name, target digest, provider version, size, and creation time.
`cache-verify` re-admits each entry and re-hashes its files against the recorded
project digest, reporting any mismatch. Add `--format json` for machine-readable
output. Listing and verification are read-only; prune, remove, and
`--repair` are the only cache mutations, and none of them opens a target. A
corrupt entry that `--repair` cannot remove (for example while another session
holds a recent lease) is reported under `failed_repairs`, and the command exits
unsuccessfully. Prune also removes entries whose manifest is unreadable, so a
damaged directory cannot escape the size ceiling, and the unfinished copies an
interrupted root rebuild left behind, so they cannot escape it either. The
`freed_bytes` it reports cover both.

## Limitations

The stored project is bound to the target bytes, provider, JVM, and import
profile it was built from. Saved project analysis can differ for identical
executable bytes, so the cache reuses a specific saved program rather than
claiming equivalence to a hypothetical fresh run. A cache hit reports that the
provider did not import or re-analyze the target in that session.

## Measured reuse

Windows Ghidra P0, Ghidra 12.1.4, JDK 21, alternating
`rea analyze <target> --provider ghidra` with `REA_GHIDRA_PROJECT_CACHE=on`:

| Target                 | First open (import + analysis) | Second open (cache hit) |
| ---------------------- | ------------------------------ | ----------------------- |
| `engine2.dll` (6.8 MB) | 256.8 s                        | 13.1 s                  |
| minimal PE fixture     | 17.4 s                         | 11.1 s                  |

The hit is confirmed by the session limitation "Ghidra analysis was reused from
a local project cache…" on the returned Evidence, and by an analysis profile
that records `project_cache` and no `import_mode`. Elapsed wall-clock includes
Node and JVM startup, a fixed cost that dominates a small target; the saving
scales with analysis size.
