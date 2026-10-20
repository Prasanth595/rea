# Persistent Ghidra project cache + cross-session identity (#1048 follow-up)

Status: **draft plan** (uncommitted; no code written yet). Revised after an
independent code review and a scope decision to include identity rebinding.

## Problem

Every Ghidra session pays the full import + auto-analysis. The fresh-import path
emits `-import <snapshot> -readOnly -deleteProject` (`src/ghidra/GhidraLauncher.ts`
661-722) into an ephemeral project deleted on close. Ghidra's own README is
explicit: with `-readOnly` in `-import` mode, "imported files will NOT be saved
to the project" (`support/analyzeHeadlessREADME.md` 273-276). Nothing is
persisted, so the cost is re-paid on every `open_binary`, CLI call, MCP restart,
and config hot-reload.

Two problems compound:

1. **Time** — large targets re-analyze every session (a 39 MB DLL with ~77k
   procedures ≈ 20 min). #2358/#2150 allow a _manual_ pre-import selected with
   `-process`, but that is unmanaged and needs an env edit.
2. **Continuity** — even with a saved project, saved analysis is not reusable:
   `docs/installation.md` 702-707 says exported analysis snapshots cannot be
   reused by a later session "even with the same project", because
   `GhidraProvider.resolveAnalysisProfile` (`GhidraProvider.ts` 256-278) injects
   `existing_project: {program_name, session_id: randomUUID()}`, and
   `GhidraAnalysisProfile.ts` 241-244 sets `import_mode` to a different value for
   import vs existing-project. `analysisProfilesEqual`
   (`domain/analysisProfile.ts` 57-64) therefore never matches across modes. An
   agent cannot resume its prior findings.

## Outcome

REA automatically reuses the analyzed program from a previous session for the
same **target + concrete provider/Ghidra/JVM + import profile**, storing full
Ghidra projects under `<home>/.rea/cache/ghidra-projects`, and makes the
analysis identity **open-mode independent** for REA-managed sessions so an
agent's prior analysis snapshots replay across sessions. A second open becomes a
project copy plus `-process <program> -noanalysis -readOnly` (seconds), not a
re-import (minutes), and previously retained observations load again.

## Non-goals (v1)

- Reuse across a different target digest, import profile, provider, Ghidra
  version, or JVM.
- Many programs in one project; one analyzed program per cache entry.
- Cross-machine sharing. The store is local and owner-only.
- Replacing the provider-neutral **analysis snapshot**
  (`AnalysisSnapshotCache.ts`), which caches Evidence JSON, not the database;
  this plan makes those snapshots _replayable_, not redundant.
- Making the **manual** `REA_GHIDRA_EXISTING_PROJECT` path replayable — an
  operator-provided project is not manifest-verified, so it keeps its random
  session identity and stays deliberately non-replayable.

## What already exists (reuse, do not duplicate)

- **Existing-project launch path (#2358):** `GhidraExistingProject`
  (`src/config/ghidraExistingProject.ts`), `copyExistingGhidraProject`
  (`GhidraLauncher.ts` 873-935), the launcher existing branch (661-722), invoked
  at 239-246. Copy-first into the private runtime.
- **PR #2150 (local branch only):** `1984fd403` requires a regular
  `rea-project.gpr` marker + a `rea-project.rep` directory and rejects `.grez`;
  `853814b3f` serializes copies. The cache publish path must emit/verify this
  expanded form regardless of merge order.
- **`GhidraLaunch.projectRoot`** already exists (`GhidraLauncher.ts` 69) and is
  retained in `GhidraClient.#launch` (99, 660) — the publish source is available.
- **Persistent home:** `<home>/.rea`; `homeDirectoryFromEnvironment`
  (`src/config/homeDirectory.ts`). `purgeManagedData` removes **only**
  `cache/` and `state/` under it (`Uninstall.ts` 285, 564-595), so the store
  must live under `<home>/.rea/cache/…`.
- **Identity machinery:** target `sha256` (`GhidraTargetSnapshot.ts`), profile
  resolution/`createAnalysisProfile`, installation inspection incl. `javaVmName`
  (`GhidraInstallation.ts` 326, 549-557), snapshot binding/equality
  (`domain/analysisSnapshot.ts` 389-406, `domain/analysisProfile.ts`).
- **Client-factory seam** for behaviour tests (`GhidraProviderClientFactory`).
- **No existing PR/branch/commit implements a persistent Ghidra project store**
  (searched all refs and sources). #2358 is the substrate.

## Design

### Provenance vs identity (the rebinding)

`import_mode` and `existing_project.session_id` describe _how_ the program was
obtained; they are provenance, not analysis semantics. Move them out of the
digest-bearing `parameters` and report them in Evidence/diagnostics. Then:

- A **REA-managed cache session** (hit _or_ miss) commits a stable
  `project_cache: { key }` parameter, so both modes produce the same
  `analysis_profile` and `analysisProfilesEqual` matches. Prior snapshots replay.
  - `key` is computed from the **pre-marker** intent profile, so there is no
    circularity (the key never depends on `project_cache`).
- The **manual** existing-project path is unchanged: it keeps
  `existing_project: {program_name, session_id: randomUUID()}`, so its state is
  never treated as a reusable identity.
- Bump a profile contract-revision marker so pre-change snapshots are rejected
  with an explicit reason rather than silently mismatching.

**Honest limitation:** the binding is the import intent (target + provider +
Ghidra/JVM + import semantics) plus the managed cache key, not the exact
analyzed bytes. Until eviction the cache serves the same saved project, so
replay is exact. After an eviction + re-import the analysis can differ
(`installation.md` 704); `program_sha256` is recorded in the manifest and
surfaced by `rea cache verify`, and a later increment can bind snapshots to a
bridge-reported program-state digest.

Blast radius: `GhidraAnalysisProfile.ts` (two `import_mode` sites),
`GhidraProvider.ts` (drop the managed `existing_project`; add `project_cache`),
tests (`GhidraProvider.behavior.test.ts` 243/627/2257/2277/2337,
`GhidraMipsProfile.test.ts` 383, `GhidraSnapshotCache.test.ts`), and docs
(`ghidra-provider.md`, `installation.md` 702-734, `windows-ghidra-p0.md`).

### Identity key

```
key = sha256(canonical_json({
  schema_version: 1,
  provider: { id: "ghidra", version },      // Ghidra application version
  jvm:      { vm_name },                     // javaVmName (result-affecting)
  platform,
  target_sha256,
  import_profile_digest                      // FINAL intent profile digest, no project_cache
}))
```

`import_profile_digest` is the digest of the final **ephemeral intent** profile:
`resolveGhidraAnalysisProfile` output after the caller merges
`analysis_extensions`/`analysis_seeds`/PSP/MIPS-soft-float lanes
(`GhidraProvider.ts` 238-278), with `import_mode`/`existing_project`/
`project_cache` excluded. The key depends only on inputs.

### Manifest (canonical JSON beside the project)

```jsonc
{
  "schema_version": 1, "key": "<hex>",
  "provider": { "id": "ghidra", "version": "12.1.4" },
  "jvm": { "vm_name": "OpenJDK 64-Bit Server VM" },
  "platform": "win32",
  "target": { "sha256": "…", "kind": "executable", "format": "pe",
              "architecture": "x86_64", "executable_role": "shared-library" },
  "import_profile_digest": "…",
  "program_name": "target-<sha12>.dll",   // sessionInfo.target.name
  "program_sha256": "…",                   // full digest, computed at publish
  "project_files": [ { "path": "rea-project.rep/…", "bytes": N, "sha256": "…" } ],
  "project_digest": "…",
  "created_at": "…", "last_used_at": "…", "size_bytes": N,
  "producer": { "rea_version": "…", "run_id": "…" }
}
```

### On-disk layout

```
<home>/.rea/cache/ghidra-projects/         # under cache/ so uninstall --purge-data removes it
  locks/<key>.lock
  staging/<uuid>/rea-project.gpr + rea-project.rep     # dot-free leaf
  <key>/manifest.json + rea-project.gpr + rea-project.rep
```

No shared `index.json` in v1 (cross-process write hazard); list/prune derive by
scanning manifests. Ghidra rejects project-path elements beginning with "."
(`GhidraSessionRoot.ts` 4-8), so the dot-prefixed cache path is never handed to
`analyzeHeadless`: publish copies out of the dot-free runtime, hits copy in
(`copyExistingGhidraProject`), preserving copy-first.

### Lifecycle

```
open_binary(target)
  ├─ always resolve the EPHEMERAL INTENT profile (existingProject = false)
  │    + merge extensions/seeds -> import_profile_digest
  ├─ key = ghidraProjectCacheKey(provider, jvm, platform, target_sha256, intent digest)
  ├─ store.prepare({key, mode}) ->
  │     HIT  => launcher.existingProject = { projectPath: <key>, programName: manifest.program_name }
  │             commit profile {... intent, project_cache:{key} }; publishable = false
  │     MISS => launcher.saveImportedProject = true (omit -readOnly / -deleteProject)
  │             commit profile {... intent, project_cache:{key} }; publishable = true
  │     disabled => current ephemeral behaviour, no project_cache marker (regression)
  └─ close:
        HIT  : runtime copy deleted; cache untouched
        MISS : publish gate passes -> copy launch.projectRoot -> staging, digests, manifest,
               atomic rename into <key>, prune; else abandon staging
```

- **Profile-resolution split (required):** the provider currently passes
  `existingProject` from config into `resolveGhidraAnalysisProfile`
  (`GhidraProvider.ts` 212), which errors with language/analyzers
  (`GhidraAnalysisProfile.ts` 80-98). Always resolve the ephemeral intent
  profile; then look up the store; then commit the mode-appropriate profile.
- **Hit** opens `-process -noanalysis -readOnly`; entries are never mutated.
- **Publish gate (all required):** handshake succeeded (`#ready`),
  `analysis_complete && !analysis_timed_out`, no client mutating operation this
  session, and `!forceStop`.
  - _Why:_ a miss drops `-readOnly` so Ghidra saves. On Linux/macOS the bridge
    reports `read_only = !transport.equals("unix-socket")`
    (`ReaGhidraBridge.java` 453), so annotations are enabled and would be
    published and served to all later sessions as analysis. Bridge-internal
    repairs (no-return fix, soft-float storage, seeds) legitimately persist.
- **Publish seam:** `GhidraClient.#cleanup`, after the successful
  `process.stop()` block and **before** `this.#launch = undefined`
  (`GhidraClient.ts` ~812-815), using `this.#launch.projectRoot` and
  `sessionInfo.target.name`.

### Concurrency

Hits are read-only copies; a hit holds a per-key read lock only for its copy.
Prune skips locked entries. Concurrent misses analyze independently and publish
atomically; the rename loser (EEXIST/ENOTEMPTY) discards staging. Single-flight
collapsing is deferred.

### Verification on hit (perf-sensitive)

Cheap checks only: manifest schema/`key`/target/profile/JVM/platform match,
expanded `.gpr`+`.rep` present, no symlink/reparse, sizes within bounds. The
bridge independently verifies the loaded program's executable SHA-256 against
the admitted target (`installation.md` 731-733). Full `project_files` digests
are checked by `rea cache verify`, not per open (AGENTS.md: avoid unnecessary
work).

### Eviction

v1 keeps a size cap `REA_GHIDRA_PROJECT_CACHE_MAX_BYTES` (default e.g. 10 GiB)
and prunes by `last_used_at` on publish; never evict a locked entry.

### Configuration (additive, opt-in)

| Variable                             | Meaning                                       | Default                             |
| ------------------------------------ | --------------------------------------------- | ----------------------------------- |
| `REA_GHIDRA_PROJECT_CACHE`           | `off` \| `read` \| `on` (`on` also populates) | `off`                               |
| `REA_GHIDRA_PROJECT_CACHE_DIR`       | absolute cache root                           | `<home>/.rea/cache/ghidra-projects` |
| `REA_GHIDRA_PROJECT_CACHE_MAX_BYTES` | size cap                                      | 10 GiB                              |

Reject combining `REA_GHIDRA_PROJECT_CACHE` with
`REA_GHIDRA_EXISTING_PROJECT`/`REA_GHIDRA_EXISTING_PROGRAM`. Import-time
settings keep feeding the **key** but are not passed to the launcher on a hit;
extend the parse-time conflict matrix (`parseConfig.ts` 49-111) deliberately.

### CLI / MCP / discovery

- `project_cache: { key, status: "hit"|"miss"|"disabled", program_sha256 }` in
  `open_binary`/`binary_session`, plus a hit limitation string.
- Update hardcoded ephemerality: `GhidraProviderCapabilities.ts` 30-31, 73, 81;
  `project_ephemeral === true` (`GhidraSessionValues.ts` 189,
  `ReaGhidraBridge.java` 344-348); `docs/ghidra-provider.md` 3-6;
  `docs/installation.md` 564-567/702-734; `docs/windows-ghidra-p0.md`.
- **Discovery (agent ergonomics):** a cheap pre-open cache summary so an agent
  can see what is warm without opening it. Deferred if trimming the first PR,
  but needed for "effortless" multi-session work.

## Agent-ergonomics note

With replay, a managed-cache session restores prior observations; without a
discovery surface an agent still cannot tell what is warm before opening, and
env-only enablement is weak. Follow-ups: discovery summary, and an
`open_binary`/server-default toggle (changes the "ephemeral database" authority
statement; needs CONTRIBUTING.md contribution-scope sign-off).

## Relationship to existing work

- Builds on #2358 (substrate); adopts #2150's expanded-project admission.
- No prior persistence PR exists; this is the first.
- Issue #1048 frames it; persistence is the natural generalisation.

## Security and authority

- Store is REA-owned and owner-only under the home (`cache/` is purgeable).
  POSIX creates `0700` and tightens an existing widened root. Windows creates
  the durable root through the native protected-DACL boundary and rebuilds an
  existing root that does not pass native verification as a private directory
  before any read or write. The rebuild copies the stored projects into the
  private replacement so they carry its owner-only DACL, and it keeps the
  previous root until every project is copied, so a rebuild that cannot
  complete leaves the stored projects where they were. Each project is copied
  into a private staging directory inside the root and published by an atomic
  rename, so no session reads a half-copied project, and a lock beside the root
  keeps one session from rebuilding the root while another reads or discards a
  project. The copies an interrupted rebuild leaves behind are reclaimed by the
  next session and by `cache-prune`, because they are not stored entries and no
  other rule would ever remove them; the reclamation holds the same lock
  before it measures and removes the copies, so it never removes the copies of
  a rebuild that is running, and it only removes state inside the cache root,
  which is the one directory REA owns.
- Admission mirrors existing-project rules; entries are derived data, never
  executed. Corrupt/foreign entry: rebuild as a miss **but always record the
  typed integrity failure** and never present a rebuilt entry as an untouched
  hit.

## Verification

- **Unit:** key coverage; manifest canonicalization + `schema_version`;
  admission (expanded `.gpr`+`.rep`, symlinks/reparse, size bounds);
  staging/publish/abandon + `EEXIST`; prune/lock interaction; tamper rejection;
  **profile equality across hit/miss for a managed session** and inequality vs
  the manual path.
- **Behaviour** via `GhidraProviderClientFactory`: first open = miss + publish
  with no `-readOnly`/`-deleteProject`; second open = hit with
  `-process … -noanalysis -readOnly` and zero import; a snapshot exported by the
  miss replays on the hit; changed profile/JVM/Ghidra version = miss; a
  mutating-op session = abandon; corrupt entry = miss + reason; `off` =
  ephemeral regression; manual existing-project remains non-replayable.
- **Real-provider lanes:** extend `verify:ghidra` / `verify:ghidra:windows` for
  cold vs warm reuse, target-digest-unchanged, snapshot replay, and cleanup;
  record cold vs warm elapsed/CPU/peak process-family memory (AGENTS.md).

## Risks

- **Intent-bound identity:** replay binds to intent + cache key, not exact
  bytes; documented, with `program_sha256` recorded and `rea cache verify` to
  detect drift.
- **Copy cost:** hundreds of MB per hit; still far below analysis. Copy, never
  hardlink (Ghidra could mutate a shared inode).
- **Disk growth:** bounded by the cap.
- **Annotations published as analysis:** closed by the mutation gate.
- **`.grez` vs expanded:** publish must produce the expanded `.gpr`+`.rep`.

## Open decisions (remaining)

1. Corrupt entry: rebuild + typed integrity failure (recommended) vs fail
   closed.
2. Mode naming (`_CACHE` vs `_STORE`); default `off` (recommended).
3. Discovery surface shape and whether an `open_binary` toggle replaces env-only
   opt-in (authority sign-off).
4. Seed-from-existing-project (`rea cache import`) as a follow-up.
