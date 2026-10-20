import { describe, expect, it } from "vitest";

import { openBinaryInputSchema } from "./sessionLifecycleInputs.js";

describe("open_binary raw-binary input contract", () => {
  it("accepts an explicit Cortex profile and rejects unregistered variants", () => {
    const input = {
      path: "/tmp/cortex.bin",
      format: "raw-binary",
      architecture: "arm",
      entry_point: "0x1002",
      base_address: "0x1000",
    };
    expect(
      openBinaryInputSchema.safeParse({
        ...input,
        processor_variant: "cortex-m",
      }).success,
    ).toBe(true);
    expect(
      openBinaryInputSchema.safeParse({ ...input, processor_variant: "thumb" })
        .success,
    ).toBe(false);
  });
  it("accepts header detection without architecture", () => {
    expect(
      openBinaryInputSchema.safeParse({ path: "/tmp/fixture.bin" }).success,
    ).toBe(true);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/legacy.com",
        format: "dos-com",
      }).success,
    ).toBe(true);
  });
  it("accepts raw-binary with architecture and entry", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(true);
  });
  it("rejects raw-binary without architecture or entry", () => {
    const parsed = openBinaryInputSchema.safeParse({
      path: "/tmp/ecu.bin",
      format: "raw-binary",
    });
    expect(parsed.success).toBe(false);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
      }).success,
    ).toBe(false);
  });
  it("rejects architecture without format=raw-binary", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        architecture: "arm",
        entry_point: "0x8000000",
      }).success,
    ).toBe(false);
  });
  it("accepts an explicit base only for a raw load", () => {
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        format: "raw-binary",
        architecture: "arm",
        entry_point: "0x1004",
        base_address: "0x1000",
      }).success,
    ).toBe(true);
    expect(
      openBinaryInputSchema.safeParse({
        path: "/tmp/ecu.bin",
        base_address: "0x1000",
      }).success,
    ).toBe(false);
    const rejected = openBinaryInputSchema.safeParse({
      path: "/tmp/ecu.bin",
      base_address: "0x1000",
    });
    if (rejected.success) throw new Error("Expected base selection rejection");
    expect(rejected.error.issues[0]?.path).toEqual(["base_address"]);
  });
});
