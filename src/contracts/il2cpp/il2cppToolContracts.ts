import { z } from "zod";
import { il2cppMetadataSummaryViewResultSchema } from "../../domain/analysisView/analysisView.js";
import {
  il2cppMetadataSchema,
  inspectIl2cppMetadataInputSchema,
} from "../../domain/il2cpp/il2cppMetadata.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static IL2CPP metadata is independent of native-analysis providers and Unity installations. */
export const IL2CPP_TOOL_CONTRACTS = [
  {
    name: "inspect_il2cpp_metadata",
    ...toolContractMetadata("inspect_il2cpp_metadata"),
    kind: "artifact-provider",
    description:
      "Inspect a local Unity IL2CPP global-metadata.dat (versions 24, 27, 29, 31 and 39). Default summary retains complete Evidence and returns artifact identity, version and counts and parent_evidence_id. Query inspect_analysis_view kind il2cpp-metadata, collection sections/images/types/methods/fields/properties/events/parameters/string_literals/method_addresses/return_types/field_types/parameter_types, with exact indices or names, fields and pagination. Types also accept image_indices, namespaces and declaring_types; methods, fields, properties and events accept declaring_types. Filters intersect and empty arrays select none. Each row always keeps index, scoped to its artifact SHA-256 and collection; page offsets count matching rows in metadata order. Explicit detail complete returns all rows. With binary_path naming the matching Mach-O GameAssembly.dylib (binary_architecture selects a universal slice), 64-bit PE GameAssembly.dll or 64-bit ELF libil2cpp.so (AArch64 or x86-64), it reads the binary, locates the CodeRegistration code-generation modules by image name and method count (on x86-64 builds without a static CodeRegistration, through the one instruction that loads the module array, with code_gen_modules_field null), and returns binary (registration addresses) plus method_addresses (one {state, address, rva} row per method index; state code, no-body when the module slot is zero, or unknown when no module claims the method) and return_types/field_types/parameter_types ({type, name} per method, field and parameter index, names rendered C#-like from the binary Il2CppType table); 32-bit images, Mach-O chained fixups, Android packed (APS2) ELF relocations and generic method instances are not linked, and version 27 type names are null. Reads existing files, with 256 MiB input and 64 MiB encoded-report guards and one active inspection per reader. Unsupported versions and malformed metadata return reasons. Type declaring_type is derived from nestedTypes; without binary_path native code addresses remain unknown, and runtime behavior always does.",
    inputSchema: inspectIl2cppMetadataInputSchema,
    outputSchema: evidenceResultOf(
      z.union([il2cppMetadataSchema, il2cppMetadataSummaryViewResultSchema]),
    ),
    examples: [
      {
        title: "Summarize metadata and retain rows for paging",
        input: {
          path: "/artifacts/Data/Managed/Metadata/global-metadata.dat",
          detail: "summary",
        },
      },
      {
        title: "Link method addresses from a universal macOS binary",
        input: {
          path: "/artifacts/Game.app/Contents/Resources/Data/il2cpp_data/Metadata/global-metadata.dat",
          binary_path:
            "/artifacts/Game.app/Contents/Frameworks/GameAssembly.dylib",
          binary_architecture: "arm64",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
