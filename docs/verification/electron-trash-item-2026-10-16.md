# Electron trash boundary verification — 2026-10-16

Fix #3474 reuses chengwudi1's ready PR #3559 and original commit
`553b816d97b489bf038c026979d4ce5a9af5e7b1`. Fresh main is
`d5be402fb3dbfc56ac9854c27b5538df20cc2437`; merge integration is `2207e9d9`.
The final runnable verification source is `955d77a0`. Original authorship and both
requested co-author trailers are retained.

The production change adds `trashItem` to the existing shell return-contract
table. Its promise rejects before native dispatch, matching the existing refusal
policy and Electron's [asynchronous API contract](https://www.electronjs.org/docs/latest/api/shell#shelltrashitempath).
Synchronous shell results remain covered by the same owner. CLI/MCP, schemas,
capture authority and retained-event budgets are unchanged.

## Controlled full-hook regression

The new staged-hook regression fails with the fresh-main shell table: the native
trash stub runs and its promise resolves. The fixed table passes **88 focused
hook/projection/MCP cases**. These validate three asynchronous rejections, native
dispatch suppression, two synchronous return contracts, shape-only retention and
the shared timeline schema. The old direct-boundary mock-context test is removed;
the stronger staged test covers its behavior. Core sources match the integration
commit; the test run preceded creation of that merge commit.

`npm run check:fast` passes both tasks. The initial uncached run takes 92.567 s
wall / 91.811527 s payload-exit CPU / 4,352,585,728 B cgroup peak. The final run
takes 15.270 s / 13.675078 s / 829,698,048 B, with one task cached; this is not a
speed comparison. Both have verified payload-exit observation and no OOM.

## Real shipped application control

Inputs are unchanged official VSCodium **1.140.06880** Linux x64 and an explicit
official generic Electron **43.7.3**, with embedded Node **24.21.0**. The archive
hashes, source pins, invocation and driver wall time are in the adjacent JSON.
The generic ELF is byte-identical to the original `codium` ELF; adjacent resource
layouts differ. This does not establish standard packaged-launch compatibility.

The real Explorer context menu deletes an owned **22,177 B copy of the REA
README**, SHA-256 `6856a965e4b6cc3ca7b4211c7cfa63fc59e6aa638b30bdb38c46a5eb3e4cfdb2`.
The app's actual native file service executes. No app callbacks or IPC handlers
are replaced. Both controls use the same transparent native-call observer,
forwarding the original receiver, arguments and return object, and the same
production `patchShell` factory. A bounded atomic **test recorder** retains the
producer facts; these are not product Evidence or a full capture timeline.

| Observed outcome                                       |                  Base boundary | Fixed boundary |
| ------------------------------------------------------ | -----------------------------: | -------------: |
| Native `trashItem` invocations matching the owned file |                              1 |              0 |
| Blocked attempts matching the owned file               |                              0 |              1 |
| Recorder drops                                         |                              0 |              0 |
| Owned file unchanged after the blocked operation       | Not established by this oracle |            Yes |
| Owned application windows closed                       |                            Yes |            Yes |

The baseline runtime checkout is `360626434`, whose boundary bytes exactly match
fresh main `d5be402f`; its README and compiled shared-environment module also match
the candidate. The verifier, runner, Node and selected Electron hashes are
identical across the final pair. The baseline deliberately fails the protection
oracle. **Native OS Trash completion is not established**; a native invocation
does not prove the filesystem operation succeeded.

The baseline resource scope takes **16.392 s**, payload-exit CPU **16.114818 s**,
peak **1,173,217,280 B**, with verified payload-exit observation. The candidate
takes **15.030 s**, observed CPU **14.738146 s**, peak **1,092,239,360 B**;
its complete-family observation is **unverified**, so those are observed prefix
counters. The baseline waits five seconds for absent blocked evidence. These
are not equivalent successful tasks and do not establish a speed improvement.

Each trial uses fresh private configuration, state and workspace mounts with an
unchanged HOME, a read-only host root and existing mount targets. Filesystem and
toolchain caches are warm. The recorder has 16 slots and requires zero drops;
atomic replacement avoids partial JSON reads. Browser-page operations and the
file recorder avoid the main Inspector handles that failed in earlier attempts.

## Verification limits and preserved failures

The accepted real-app test exercises **production shell boundary + actual app
UI**. The full hook/provider/CLI/MCP workflow is **NOT_EXECUTED** there. The
controlled 88-case suite verifies the separate full-hook recording composition;
it does not prove a real MCP provider run. Real Windows/macOS and full `check:pr`
were not executed. Agent/billed tokens, context/schema costs, cold-system runs and
warm-repeat costs are unmeasured. No token or speed benefit is claimed.

Earlier full-hook attempts found standard packaged preload absent, main
Inspector evaluation contexts destroyed, and an `External navigation is blocked`
exception during VSCodium startup. The actual blocked URL was not retained.
Startup/navigation issues #2974/#4494 and cleanup #4282 remain separate; raw
listener mutation #4513 remains unfixed. These failures are not bypassed in the
production hook. Superseded test transports were removed, and the Joplin verifier
was restored unchanged. Their original source checkpoints remain in Git history.

The JSON keeps these earlier cohorts separately, including a missing private
state directory, the menu-label mismatch, Xvfb temporary-directory cleanup
failures and the stopped paired-run orchestrator. One trial was **NOT_EXECUTED**
because memory admission refused its budget plus host reserve. A later observed
headroom change satisfied admission; no guard was overridden. Explicit owned
Xauthority files avoid the failed automatic-directory cleanup in the final pair.

## Reproduce

Use the pinned Node/npm toolchain, `npm ci`, `npm run build:cached`, and existing
Linux systemd user scopes, bwrap, Xvfb and xauth. The runner requires existing
user `.config`/`.local` mount targets and creates no host configuration directories.
Acquire and checksum-verify the official inputs recorded in JSON, then run:

```sh
taskset -c 10 python3 experiments/analysis-efficiency/vscodium-shell-run.py \
  --runtime-root /absolute/selected-rea-checkout \
  --node /absolute/pinned-node \
  --executable /absolute/generic-electron43.7.3 \
  --application /absolute/VSCodium/resources/app \
  --output /tmp/owned-verification-output --memory-gib 8
```

Keep the current verifier/runner for both controls; select the baseline checkout
with `--runtime-root`. The runner saves source hashes, explicit invocation and
driver wall time in its new owned trial. Large downloadable applications,
runtimes, profiles, screenshots and raw logs are temporary and excluded from Git.

The saved resource wrapper preserves its **4 GiB default** and adds the already
used explicit **8 GiB** budget: 6 GiB early stop, no swap, one CPU, 192 tasks and
4 GiB host reserve. A real default-4-GiB smoke run passes. All heavy work is serial.
Counters are at payload exit with the observer alive, not final whole-scope
counters; peak includes file cache. External owned-scope cleanup is separate
from provider cleanup. All recorded owned scopes are checked inactive/dead.
