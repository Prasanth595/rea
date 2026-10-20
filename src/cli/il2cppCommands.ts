import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { z } from "incur";
import { lstat, open, unlink } from "node:fs/promises";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";
import {
  ghidraDefaultBase,
  il2cppGhidraSeeds,
} from "../domain/il2cpp/il2cppGhidraSeeds.js";
import { il2cppMetadataSchema } from "../domain/il2cpp/il2cppMetadata.js";
import { createIl2cppMetadataService } from "../composition/il2cpp.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import {
  analysisEvidenceDeliveryOptions,
  deliverCliAnalysisEvidence,
} from "./analysisEvidenceDelivery.js";

/** Write seeds for a linked report at Ghidra's default load base unless overridden. */
const writeSeeds = async (
  result: unknown,
  path: string,
  seedBase: string | undefined,
) => {
  const report = il2cppMetadataSchema.parse(result);
  if (report.binary === null)
    throw new Error("--ghidra-seeds needs --binary to link method addresses");
  const seeds = il2cppGhidraSeeds(
    report,
    seedBase === undefined
      ? ghidraDefaultBase(report.binary)
      : BigInt(seedBase),
  );
  // Create only (never replace), and remove the file again if writing fails so
  // no partial seed list is left for Ghidra to apply.
  const file = await open(path, "wx");
  try {
    await file.writeFile(seeds.text);
  } catch (cause) {
    // Remove only the file this call created, not one renamed into its place.
    const created = await file.stat().catch(() => undefined);
    await file.close().catch(() => undefined);
    const current = await lstat(path).catch(() => undefined);
    if (
      created !== undefined &&
      current !== undefined &&
      created.dev === current.dev &&
      created.ino === current.ino
    )
      await unlink(path).catch(() => undefined);
    throw cause;
  }
  await file.close();
};

/** CLI and MCP share inspection; one-shot summaries preserve a complete Evidence file. */
export const registerIl2cppCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.inspectIl2cppMetadata, {
    description:
      "Inventory IL2CPP global-metadata.dat images, types and methods, optionally linking method addresses from the native binary",
    args: z.object({
      path: z
        .string()
        .describe("Local global-metadata.dat (version 24, 27, 29, 31 or 39)"),
    }),
    options: z.object({
      ...analysisEvidenceDeliveryOptions,
      binary: z
        .string()
        .optional()
        .describe(
          "Matching native binary (Mach-O GameAssembly.dylib, PE GameAssembly.dll or ELF libil2cpp.so) to link method addresses; read only",
        ),
      architecture: z
        .enum(["arm64", "amd64"])
        .optional()
        .describe("Slice of a universal Mach-O binary"),
      ghidraSeeds: z
        .string()
        .optional()
        .describe(
          "Also write REA_GHIDRA_SEED_FILE function seeds named Type$$Method for every linked method; needs --binary",
        ),
      seedBase: z
        .string()
        .regex(/^0x[0-9a-fA-F]{1,16}$/u)
        .optional()
        .describe(
          "Address Ghidra loads the binary at; seeds are seed-base + RVA (default: Ghidra's loader default, 0x100000 for an ELF linked at 0, else the link base)",
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectIl2cppMetadata, async () => {
          const service = createIl2cppMetadataService();
          return deliverCliAnalysisEvidence({
            run: async () => {
              // Check before decoding so an existing seed file is reported
              // as such instead of failing after the analysis finished.
              const seedPath =
                options.ghidraSeeds === undefined
                  ? undefined
                  : absoluteCallerPath(options.ghidraSeeds);
              if (seedPath !== undefined && options.binary === undefined)
                return err(
                  new AnalysisInputError("inspect_il2cpp_metadata", undefined, [
                    {
                      path: ["ghidra_seeds"],
                      reason: "invalid_value",
                      message:
                        "--ghidra-seeds needs --binary to link method addresses.",
                    },
                  ]),
                );
              if (
                seedPath !== undefined &&
                (await lstat(seedPath).catch(() => undefined)) !== undefined
              )
                return err(
                  new AnalysisInputError("inspect_il2cpp_metadata", undefined, [
                    {
                      path: ["ghidra_seeds"],
                      reason: "invalid_value",
                      message: `--ghidra-seeds ${seedPath} already exists; seed files are created, never replaced.`,
                    },
                  ]),
                );
              const result = await service.inspect(
                {
                  path: absoluteCallerPath(args.path),
                  detail: "complete",
                  ...(options.binary === undefined
                    ? {}
                    : { binary_path: absoluteCallerPath(options.binary) }),
                  ...(options.architecture === undefined
                    ? {}
                    : { binary_architecture: options.architecture }),
                },
                { signal },
              );
              if (result.ok && options.ghidraSeeds !== undefined)
                await writeSeeds(
                  result.value.normalized_result,
                  seedPath!,
                  options.seedBase,
                );
              return result;
            },
            service,
            providerId: "il2cpp-metadata",
            operation: "inspect_il2cpp_metadata",
            signal,
            detail: options.detail,
            evidenceOutput: options.evidence_output,
          });
        }),
      ),
  });
};
