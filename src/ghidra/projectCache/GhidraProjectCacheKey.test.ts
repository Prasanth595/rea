import { describe, expect, it } from "vitest";

import { ghidraProjectCacheKey } from "./GhidraProjectCacheKey.js";
import type { GhidraProjectCacheIdentity } from "./GhidraProjectCacheTypes.js";

const identity = (): GhidraProjectCacheIdentity => ({
  providerId: "ghidra",
  providerVersion: "12.1.4",
  jvmVmName: "OpenJDK 64-Bit Server VM",
  platform: "linux",
  targetSha256: "a".repeat(64),
  importProfileDigest: "b".repeat(64),
});

describe("ghidraProjectCacheKey", () => {
  it("is a deterministic lowercase sha256 over the identity", () => {
    const key = ghidraProjectCacheKey(identity());
    expect(key).toMatch(/^[a-f0-9]{64}$/u);
    expect(ghidraProjectCacheKey(identity())).toBe(key);
  });

  it.each<[string, Partial<GhidraProjectCacheIdentity>]>([
    ["provider version", { providerVersion: "12.1.5" }],
    ["jvm", { jvmVmName: "Eclipse Adoptium" }],
    ["platform", { platform: "win32" }],
    ["target digest", { targetSha256: "c".repeat(64) }],
    ["import profile digest", { importProfileDigest: "d".repeat(64) }],
  ])("changes when the %s changes", (_label, override) => {
    expect(ghidraProjectCacheKey({ ...identity(), ...override })).not.toBe(
      ghidraProjectCacheKey(identity()),
    );
  });

  it("rejects an invalid digest or an empty identity field", () => {
    expect(() =>
      ghidraProjectCacheKey({ ...identity(), targetSha256: "short" }),
    ).toThrow(/sha256 digest/u);
    expect(() =>
      ghidraProjectCacheKey({ ...identity(), providerVersion: "" }),
    ).toThrow(/must not be empty/u);
  });
});
