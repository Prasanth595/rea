import { describe, expect, it } from "vitest";

import {
  ghidraHeadlessArguments,
  type GhidraHeadlessArgumentOptions,
} from "./GhidraLauncher.js";

const base = (): GhidraHeadlessArgumentOptions => ({
  platform: "linux",
  projectRoot: "/runtime/project",
  targetPath: "/runtime/target.bin",
  bridgeScriptPath: "/rea/bridge/ReaGhidraBridge.java",
  descriptorPath: "/runtime/session.json",
  ghidraLogPath: "/runtime/ghidra.log",
  scriptLogPath: "/runtime/script.log",
});

describe("ghidraHeadlessArguments import persistence", () => {
  it("discards a default ephemeral import", () => {
    const args = ghidraHeadlessArguments(base());
    expect(args).toContain("-readOnly");
    expect(args).toContain("-deleteProject");
    expect(args).not.toContain("-noanalysis");
  });

  it("saves a fresh import when requested, without read-only or delete", () => {
    const args = ghidraHeadlessArguments({
      ...base(),
      saveImportedProject: true,
    });
    expect(args).toContain("-import");
    expect(args).not.toContain("-readOnly");
    expect(args).not.toContain("-deleteProject");
    expect(args).not.toContain("-noanalysis");
  });

  it("opens an existing project without analysis", () => {
    const args = ghidraHeadlessArguments({
      ...base(),
      existingProject: { programName: "target-abc.dll" },
    });
    expect(args).toContain("-process");
    expect(args).toContain("-noanalysis");
    expect(args).toContain("-readOnly");
  });

  it("rejects a saved import combined with an existing project", () => {
    expect(() =>
      ghidraHeadlessArguments({
        ...base(),
        existingProject: { programName: "target-abc.dll" },
        saveImportedProject: true,
      }),
    ).toThrow(/cannot be combined/u);
  });
});
