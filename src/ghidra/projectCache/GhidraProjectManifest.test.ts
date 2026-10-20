import { describe, expect, it } from "vitest";

import {
  ghidraProjectManifestIdentity,
  parseGhidraProjectManifest,
  serializeGhidraProjectManifest,
  type GhidraProjectManifest,
} from "./GhidraProjectManifest.js";

const manifest = (): GhidraProjectManifest => ({
  schema_version: 1,
  key: "a".repeat(64),
  provider: { id: "ghidra", version: "12.1.4" },
  jvm: { vm_name: "OpenJDK 64-Bit Server VM" },
  platform: "linux",
  target: {
    sha256: "b".repeat(64),
    kind: "executable",
    format: "pe",
    architecture: "x86_64",
    executable_role: "shared-library",
  },
  import_profile_digest: "c".repeat(64),
  program_name: "target-abc123.dll",
  program_sha256: "d".repeat(64),
  project_files: [
    {
      path: "rea-project.rep/idata/00/db.gbf",
      bytes: 10,
      sha256: "e".repeat(64),
    },
  ],
  project_digest: "f".repeat(64),
  created_at: "2026-01-01T00:00:00.000Z",
  last_used_at: "2026-01-01T00:00:00.000Z",
  size_bytes: 10,
  producer: { rea_version: "6.4.0", run_id: "run-1" },
});

describe("ghidra project manifest", () => {
  it("round-trips through canonical serialization", () => {
    const encoded = serializeGhidraProjectManifest(manifest());
    expect(encoded.endsWith("\n")).toBe(true);
    const parsed = parseGhidraProjectManifest(JSON.parse(encoded));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.value).toEqual(manifest());
    expect(
      serializeGhidraProjectManifest(parsed.ok ? parsed.value : manifest()),
    ).toBe(encoded);
  });

  it("rejects an unknown field, a bad digest, and parent traversal", () => {
    expect(parseGhidraProjectManifest({ ...manifest(), extra: true }).ok).toBe(
      false,
    );
    expect(parseGhidraProjectManifest({ ...manifest(), key: "short" }).ok).toBe(
      false,
    );
    const traversal = manifest();
    traversal.project_files[0]!.path = "../escape.gbf";
    expect(parseGhidraProjectManifest(traversal).ok).toBe(false);
  });

  it("projects the identity fields a key is derived from", () => {
    expect(ghidraProjectManifestIdentity(manifest())).toEqual({
      providerId: "ghidra",
      providerVersion: "12.1.4",
      jvmVmName: "OpenJDK 64-Bit Server VM",
      platform: "linux",
      targetSha256: "b".repeat(64),
      importProfileDigest: "c".repeat(64),
    });
  });
});
