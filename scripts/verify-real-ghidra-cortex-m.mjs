import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import { cortexM0Fixture } from "../tests/conformance/ghidra/cortexM0.fixture.mjs";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

if (
  process.argv.length !== 2 ||
  !["linux", "darwin"].includes(process.platform)
)
  throw new Error(
    "Cortex-M verification requires Linux or macOS; no arguments are accepted.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error("Set GHIDRA_INSTALL_DIR to an existing Ghidra installation.");
const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-cortex-m-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const env = {
  ...process.env,
  TMPDIR: runtime,
  TMP: runtime,
  TEMP: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-cortex-m-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
let report;
try {
  await client.connect(transport);
  const cases = [];
  for (const base of [0, 0x08000000]) cases.push(await verifyCase(base));
  assert.deepEqual(
    (await readdir(runtime)).filter((name) => name.startsWith("rea-ghidra-")),
    [],
    "Owned Ghidra runtime survived close",
  );
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-cortex-m",
    host: process.platform,
    cases,
    cli_mcp_load_image_parity: true,
    thumb_context_verified: true,
    decompilation: true,
    generic_arm_unchanged: true,
    original_unchanged: true,
  };
} catch (error) {
  if (stderr.trim()) process.stderr.write(stderr);
  throw error;
} finally {
  await client.close();
  await transport.close();
  await rm(workspace, { recursive: true, force: true });
}
const verifierRun = await completeVerifierRun(run);
assert.equal(verifierRun.process_lineage.status, "verified");
assert.deepEqual(verifierRun.process_lineage.descendants, []);
process.stdout.write(
  JSON.stringify({
    verifier_run: verifierRun,
    ...report,
    cleanup: "complete",
  }) + "\n",
);

async function verifyCase(base) {
  const address = (offset) => `0x${(base + offset).toString(16)}`;
  const bytes = cortexM0Fixture(base);
  const digest = createHash("sha256").update(bytes).digest("hex");
  const path = join(workspace, `cortex-${base.toString(16)}.bin`);
  await writeFile(path, bytes);
  const selection = {
    path,
    format: "raw-binary",
    architecture: "arm",
    processor_variant: "cortex-m",
    base_address: address(0),
    entry_point: address(0x40),
  };
  const opened = await call("open_binary", selection);
  assert.equal(opened.processor_variant, "cortex-m");
  const image = await evidence("inspect_native_load_image", {}, digest);
  assert.equal(image.provider.id, "ghidra");
  assert.equal(
    image.normalized_result.status,
    "verified",
    JSON.stringify(image),
  );
  assert.equal(image.normalized_result.language_id, "ARM:LE:32:Cortex");
  assert.equal(image.normalized_result.base_address, address(0));
  assert.deepEqual(image.normalized_result.entry, {
    address: address(0x40),
    file_offset: 0x40,
  });
  assert.ok(
    image.normalized_result.checks.some(
      (check) =>
        check.name === "entry_context.TMode" &&
        check.matched &&
        check.observed === "0x1",
    ),
  );
  const status = await call("binary_session");
  assert.equal(status.processor_variant, "cortex-m");
  const memory = await evidence(
    "read_bytes",
    { address: address(0), length: bytes.length },
    digest,
  );
  assert.equal(memory.normalized_result.bytes_hex, bytes.toString("hex"));
  const instruction = await evidence(
    "inspect_native_instruction",
    { address: address(0x44) },
    digest,
  );
  assert.equal(instruction.normalized_result.mnemonic.toLowerCase(), "bl");
  assert.deepEqual(instruction.normalized_result.flow.direct_destinations, [
    address(0x56),
  ]);
  const procedures = await evidence("list_procedures", {}, digest);
  assert.ok(
    procedures.normalized_result.some((item) => item.address === address(0x40)),
  );
  assert.ok(
    !procedures.normalized_result.some((item) => item.address === address(0)),
    "Vector table became a function",
  );
  const helper = await evidence(
    "procedure_pseudo_code",
    { procedure: address(0x56) },
    digest,
  );
  assert.match(helper.normalized_result, /\+\s*(?:3|0x3)\b/u);
  const caller = await evidence(
    "procedure_pseudo_code",
    { procedure: address(0x40) },
    digest,
  );
  assert.match(caller.normalized_result, /==\s*(?:10|0xa)\b/iu);
  assert.match(caller.normalized_result, /return\s+0\s*;/u);
  const byOffset = await evidence(
    "procedure_pseudo_code",
    { procedure: "file-offset:0x56" },
    digest,
  );
  assert.equal(byOffset.normalized_result, helper.normalized_result);
  const odd = await client.callTool({
    name: "open_binary",
    arguments: { ...selection, entry_point: address(0x41) },
  });
  assert.equal(odd.isError, true);
  assert.match(JSON.stringify(odd.content), /odd Thumb function pointer/u);
  assert.equal(
    (await call("binary_session")).analysis_run.run_id,
    status.analysis_run.run_id,
  );
  const { processor_variant: _variant, ...genericSelection } = selection;
  await call("open_binary", genericSelection);
  const genericStatus = await call("binary_session");
  assert.equal(
    genericStatus.analysis_provider_binding.analysis_profile.parameters
      .language_id,
    "ARM:LE:32:v7",
  );
  assert.notEqual(
    genericStatus.analysis_provider_binding.analysis_profile.digest,
    image.analysis_profile.digest,
  );
  assert.equal(genericStatus.processor_variant, undefined);
  await call("close_binary");
  const cli = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      "inspect-native-load-image",
      path,
      "--target-format",
      "raw-binary",
      "--architecture",
      "arm",
      "--processor-variant",
      "cortex-m",
      "--base-address",
      address(0),
      "--entry-point",
      address(0x40),
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const cliImage = parseEvidence(JSON.parse(cli.stdout));
  assert.equal(cliImage.analysis_profile.digest, image.analysis_profile.digest);
  assert.deepEqual(cliImage.normalized_result, image.normalized_result);
  assert.deepEqual(await readFile(path), bytes);
  return {
    base: address(0),
    entry: address(0x40),
    sha256: digest,
    bytes: bytes.length,
    provider: image.provider,
    thumb_mode: 1,
    vector_table_not_a_function: true,
  };
}

async function invoke(name, args = {}) {
  const result = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  return { raw: result, value: requireMcpOperationResult(result, name) };
}

async function call(name, args = {}) {
  return (await invoke(name, args)).value;
}

async function evidence(name, args, digest) {
  const parsed = parseEvidence(
    (await invoke(name, args)).raw.structuredContent,
  );
  assert.equal(parsed.subject.digest.sha256, digest);
  return parsed;
}
