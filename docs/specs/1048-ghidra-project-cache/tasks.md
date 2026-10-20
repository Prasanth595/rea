# Tasks

## Status

- Done: config/home (1), provider-independent store (2), identity rebinding
  (3), launcher save flag (4), client publish/hit wiring (5), provider
  restructure (6), evidence/doc surface (7), real-provider measurement (8),
  and the `rea cache-list|cache-verify|cache-prune|cache-remove` discovery and
  maintenance CLI.
- Measured on Windows Ghidra P0: `engine2.dll` first open 256.8 s, cache hit
  13.1 s (recorded in `docs/ghidra-project-cache.md`). Adding a cache assertion
  to the `verify:ghidra*` lane scripts remains for CI coverage.
- Deferred: a bridge-reported program-state digest, seed-from-project
  (`rea cache import`), an `open_binary`/server-default toggle, and #2150 copy
  serialization.
- The default `off` path is unchanged; the Ghidra source-test folder is now
  green on Windows (platform-specific tests fixed/skipped).

One PR, opt-in and reviewable: a persistent Ghidra project cache plus the
identity rebinding that makes prior snapshots replay across sessions.

1. **Config + home (no behaviour change).** `REA_GHIDRA_PROJECT_CACHE`
   (`off|read|on`), `REA_GHIDRA_PROJECT_CACHE_DIR` (default
   `<home>/.rea/cache/ghidra-projects`), `REA_GHIDRA_PROJECT_CACHE_MAX_BYTES` in
   `src/config/environment.ts`; extend the conflict matrix in `parseConfig.ts`;
   add the `AppConfig` field. Unit tests.

2. **Store `src/ghidra/projectCache/` (provider-independent).** Key function
   (final intent digest + provider + JVM + platform + target, excluding
   `project_cache`); manifest schema + canonical serialization; admission
   (expanded `rea-project.gpr` + `rea-project.rep`, no symlink/reparse, size
   bounds); `staging/<uuid>` + atomic publish + per-key lock; size-cap prune;
   typed integrity failures. Unit tests incl. tamper and `EEXIST`.

3. **Identity rebinding.** Move `import_mode` out of the digest-bearing profile
   (`GhidraAnalysisProfile.ts` 150, 241-244) into provenance; for managed-cache
   sessions add a stable `project_cache: { key }` parameter (hit and miss);
   keep the manual existing-project path non-replayable; bump a contract
   revision marker. Update the profile tests.

4. **Launcher option.** `GhidraHeadlessLauncherOptions.saveImportedProject?: true`
   emits `[]` instead of `["-readOnly","-deleteProject"]` (`GhidraLauncher.ts`
   720-722).

5. **Client publish/hit wiring.** Optional `projectPersistence` on
   `GhidraClientOptions`; publish in `#cleanup` after `process.stop()` and
   before `#launch = undefined`, gated on `#ready`,
   `analysis_complete && !analysis_timed_out`, no mutating op, and
   `!forceStop`; abandon on failure/cancel.

6. **Provider restructure.** Always resolve the ephemeral intent profile; look
   up the store; commit the mode-appropriate profile; on a hit pass
   `existingProject`; keep import-time settings feeding the key only.

7. **Evidence + docs.** `project_cache` status field and hit limitation; update
   `GhidraProviderCapabilities.ts` 30-31/73/81, the `project_ephemeral`
   acknowledgement, `docs/ghidra-provider.md`, `docs/installation.md`
   564-567/702-734, `docs/windows-ghidra-p0.md`; add `docs/ghidra-project-cache.md`.

8. **Verification + measurement.** Behaviour tests via
   `GhidraProviderClientFactory` incl. miss-exported snapshot replaying on the
   hit; extend `verify:ghidra` / `verify:ghidra:windows`; record cold vs warm
   elapsed/CPU/peak memory.

## Deferred (follow-ups)

- `rea cache list|remove|prune|verify` CLI and the pre-open discovery surface.
- LRU eviction beyond the size cap; single-flight miss collapsing.
- Bridge-reported program-state digest to tighten replay beyond intent.
- Seed-from-existing-project (`rea cache import`).
- `open_binary`/server-default enablement (authority sign-off).
- #2150-specific copy serialization once that branch lands.
