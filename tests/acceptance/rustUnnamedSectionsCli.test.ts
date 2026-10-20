import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";

import { toolContract } from "../../src/contracts/toolContracts.js";
import { createRustImage, RUSTC_HASH } from "../fixtures/rust/image.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

const cases = (["CLI", "stdio MCP"] as const).flatMap((surface) =>
  (["named", "unnamed", "no-names"] as const).map((mode) => ({
    surface,
    mode,
  })),
);

cliTest.for(cases)(
  "retains read-only compiler evidence in $mode ELF sections through $surface",
  async ({ surface, mode }, { cli }) => {
    const root = await createTestTempDirectory("rea-rust-unnamed-sections-");
    const bytes = createRustImage({ format: "elf", omitSection: true });
    if (mode !== "named") bytes.writeUInt32LE(0, 384);
    if (mode === "no-names") {
      bytes.writeUInt16LE(0, 62);
      bytes.fill(0, 320, 384);
    }
    const mcp = surface === "stdio MCP" ? await connectLocalToolsMcp() : null;
    const inspect = async (path: string) => {
      if (mcp !== null) {
        const response = await mcp.call("inspect_rust_binary", { path });
        expect(response.isError, JSON.stringify(response)).not.toBe(true);
        return toolContract("inspect_rust_binary").outputSchema.parse(
          response.structuredContent,
        ).normalized_result;
      }
      const response = await cli.run({
        arguments: ["inspect-rust-binary", path, "--json"],
      });
      expect(response.exitCode, response.stderr).toBe(0);
      return toolContract("inspect_rust_binary").outputSchema.parse(
        response.json,
      ).normalized_result;
    };
    const path = join(root, "readonly.elf");
    await writeFile(path, bytes);
    const report = await inspect(path);
    expect(report.artifact).toEqual({
      path,
      bytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    expect(report.auditable_metadata).toBeNull();
    expect(report.rustc_commit).toEqual({
      evidence_kind: "inferred",
      hashes: [{ hash: RUSTC_HASH, file_offset: 2048 }],
    });
    const writable = Buffer.from(bytes);
    writable.writeBigUInt64LE(3n, 384 + 8);
    const writablePath = join(root, "writable.elf");
    await writeFile(writablePath, writable);
    const control = await inspect(writablePath);
    expect(control.auditable_metadata).toBeNull();
    expect(control.rustc_commit).toBeNull();
  },
);
