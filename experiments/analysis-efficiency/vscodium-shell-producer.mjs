#!/usr/bin/env node
// Real UI + production shell patch, with a test recorder. This does not exercise
// the full hook/provider: packaged startup and navigation are separate gaps.
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { pathToFileURL } from "node:url";
import { _electron } from "playwright-core";

const { values } = parseArgs({
  options: Object.fromEntries(
    ["runtime-root", "executable", "application", "trial-root"].map((key) => [
      key,
      { type: "string" },
    ]),
  ),
});
for (const key of ["runtime-root", "executable", "application", "trial-root"])
  assert.ok(values[key], `Missing --${key}`);
const runtime = resolve(values["runtime-root"]);
const trial = resolve(values["trial-root"]);
const { safeElectronEnvironment } = await import(
  pathToFileURL(
    join(runtime, "dist/browser/PlaywrightElectronActiveProvider.js"),
  )
);
assert.equal(
  (await readFile(join(trial, "OWNED-BY-REA-3474"), "utf8")).trim(),
  "REA3474 owned disposable verification trial",
);
const started = performance.now();
const profile = join(trial, "profile");
const workspace = join(trial, "workspace");
const extensions = join(trial, "extensions");
await mkdir(join(profile, "User"), { recursive: true });
await mkdir(workspace);
await mkdir(extensions);
const target = join(workspace, "README-copy.md");
const original = await readFile(join(runtime, "README.md"));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const inputHash = hash(original);
await writeFile(target, original, { flag: "wx" });
const settings = {
  "files.enableTrash": true,
  "explorer.confirmDelete": false,
  "workbench.startupEditor": "none",
  "window.menuStyle": "custom",
  "window.titleBarStyle": "custom",
  "security.workspace.trust.enabled": false,
  "update.mode": "none",
  "telemetry.telemetryLevel": "off",
  "extensions.autoCheckUpdates": false,
  "extensions.autoUpdate": false,
};
await writeFile(join(profile, "User/settings.json"), JSON.stringify(settings), {
  flag: "wx",
});
const boundary = join(trial, "electron-active-hook-boundaries.cjs");
await copyFile(
  join(runtime, "scripts/electron-active-hook-boundaries.cjs"),
  boundary,
);
const boundaryHash = hash(await readFile(boundary));
assert.equal(
  boundaryHash,
  hash(
    await readFile(
      join(runtime, "scripts/electron-active-hook-boundaries.cjs"),
    ),
  ),
);
const preload = join(trial, "shell-producer-preload.cjs");
const observationPath = join(trial, "shell-producer-observation.json");
await writeFile(
  preload,
  `const electron = require("electron");
const fs = require("node:fs");
const { createElectronActiveBoundaryPatches } = require(${JSON.stringify(boundary)});
const events = []; let dropped = 0;
let nativeCalls = 0, nativeOwnedCalls = 0;
const observation = ${JSON.stringify(observationPath)};
let engine = null;
const publish = () => {
  fs.writeFileSync(observation + ".tmp", JSON.stringify({ engine, events, dropped,
    native_calls: { total: nativeCalls, matching_owned_path: nativeOwnedCalls } }));
  fs.renameSync(observation + ".tmp", observation);
};
const unused = () => { throw new Error("Unexpected non-shell observer path"); };
if (typeof electron.shell.trashItem !== "function") throw new Error("Missing real shell.trashItem");
const nativeTrash = electron.shell.trashItem;
const invoke = Reflect.apply;
electron.shell.trashItem = function observedNativeTrash(...args) {
  try { return invoke(nativeTrash, this, args); }
  finally {
    nativeCalls += 1;
    if (args.length === 1 && args[0] === ${JSON.stringify(target)}) nativeOwnedCalls += 1;
    publish();
  }
};
createElectronActiveBoundaryPatches({
  identity: unused, patchEmitter: unused, processType: unused, recordIpc: unused, shape: unused,
  recordRuntime(kind, event, phase, meta) {
    if (kind !== "shell-attempt" || event !== "trashItem") return;
    if (events.length >= 16) dropped += 1;
    else events.push({ kind, event, phase, error: meta.error,
      argument_count: meta.argument_shape_values.length,
      matches_owned_path: meta.argument_shape_values[0] === ${JSON.stringify(target)} });
    publish();
  }
}).patchShell(electron.shell);
const ready = () => {
  engine = { node: process.versions.node, electron: process.versions.electron,
    application_path: electron.app.getAppPath(),
    full_hook_installed: typeof globalThis.__reaElectronActiveSnapshot === "function" };
  publish();
};
publish();
if (electron.app.isReady()) ready(); else electron.app.once("ready", ready);
`,
  { flag: "wx" },
);

let application;
let page;
let probe;
let engine;
let closeStatus = "not-launched";
let failure;
let observation;
const pageErrors = [];
const readObservation = async () =>
  JSON.parse(await readFile(observationPath, "utf8"));
try {
  application = await _electron.launch({
    executablePath: resolve(values.executable),
    env: safeElectronEnvironment(process.env, randomUUID()),
    args: [
      "-r",
      preload,
      resolve(values.application),
      "--no-sandbox",
      "--disable-gpu",
      "--new-window",
      "--skip-welcome",
      "--skip-release-notes",
      "--disable-extensions",
      `--user-data-dir=${profile}`,
      `--extensions-dir=${extensions}`,
      workspace,
    ],
    timeout: 30_000,
  });
  // Browser pages and the atomic recorder do not depend on a cached main-process
  // Inspector handle, which has failed during this application's startup.
  const context = application.context();
  page =
    context.pages()[0] ??
    (await context.waitForEvent("page", { timeout: 20_000 }));
  page.on("pageerror", (cause) => {
    if (pageErrors.length < 5) pageErrors.push(String(cause).slice(0, 600));
  });
  await page.locator(".monaco-workbench").waitFor({ timeout: 20_000 });
  const row = page.getByRole("treeitem", { name: /README-copy\.md/ }).first();
  await row.waitFor({ timeout: 15_000 });
  const before = await readObservation();
  observation = before;
  engine = before.engine;
  assert.equal(engine.application_path, resolve(values.application));
  assert.equal(engine.full_hook_installed, false);
  assert.deepEqual(before.events, []);
  assert.equal(before.dropped, 0);
  assert.deepEqual(before.native_calls, { total: 0, matching_owned_path: 0 });
  await row.click({ button: "right" });
  await page
    .getByRole("menuitem", { name: /^Delete(?:\s*Del)?$/ })
    .click({ timeout: 5_000 });
  let after = await readObservation();
  const expires = performance.now() + 5_000;
  while (after.events.length === 0 && performance.now() < expires) {
    await page.waitForTimeout(50);
    after = await readObservation();
  }
  observation = after;
  assert.deepEqual(after, {
    engine,
    native_calls: { total: 0, matching_owned_path: 0 },
    events: [
      {
        kind: "shell-attempt",
        event: "trashItem",
        phase: "blocked",
        error: true,
        argument_count: 1,
        matches_owned_path: true,
      },
    ],
    dropped: 0,
  });
  assert.equal(hash(await readFile(target)), inputHash);
  assert.deepEqual(pageErrors, []);
  probe = {
    input_path: target,
    input_sha256: inputHash,
    input_bytes: original.length,
    before_trash_count: 0,
    file_unchanged: true,
    observation: after,
    page_errors: pageErrors,
  };
} catch (cause) {
  failure = String(cause);
  if (page) {
    await page
      .screenshot({ path: join(trial, "failure.png") })
      .catch(() => undefined);
    const labels = await page
      .locator('[role="treeitem"], [role="menuitem"]')
      .evaluateAll((nodes) =>
        nodes.slice(0, 30).map((node) => ({
          role: node.getAttribute("role"),
          label: (
            node.getAttribute("aria-label") ??
            node.textContent ??
            ""
          ).slice(0, 150),
        })),
      )
      .catch(() => []);
    console.log(JSON.stringify({ ui_failure: failure, labels }));
  }
} finally {
  if (application) {
    let timer;
    closeStatus = await Promise.race([
      (async () => {
        const closed = application
          .waitForEvent("close", { timeout: 4_000 })
          .then(
            () => true,
            () => false,
          );
        for (const window of application.context().pages())
          await window.close();
        assert.ok(await closed, "Application close remained unverified");
        return "window-close-completed";
      })().catch(() => "window-close-unverified"),
      new Promise((resolve) => {
        timer = setTimeout(() => resolve("deadline"), 5_000);
      }),
    ]);
    clearTimeout(timer);
  }
}
console.log(
  JSON.stringify({
    scope: "production-shell-boundary-with-test-recorder",
    runtime,
    executable: resolve(values.executable),
    application: resolve(values.application),
    boundary_sha256: boundaryHash,
    engine,
    settings,
    elapsed_ms: performance.now() - started,
    probe: probe ?? null,
    observation: observation ?? null,
    failure: failure ?? null,
    close_status: closeStatus,
    scenario_ok: probe !== undefined,
    full_hook_provider_workflow: "NOT_EXECUTED",
  }),
);
process.exit(probe && closeStatus === "window-close-completed" ? 0 : 1);
