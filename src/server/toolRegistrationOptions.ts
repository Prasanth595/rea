import type { ToolContract } from "../contracts/toolContractTypes.js";
import type { StandardSchemaWithJSON } from "@modelcontextprotocol/server";
import {
  toolInputSchemaWithMetadata,
  toolOutputSchemaWithMetadata,
} from "../contracts/toolSchemaMetadata.js";

/** Preserve advertised contracts while the application owns structured input failures. */
export const applicationValidatedInputSchema = (
  schema: StandardSchemaWithJSON,
): StandardSchemaWithJSON => {
  const standard = schema["~standard"];
  return {
    "~standard": {
      ...standard,
      vendor: "rea-application",
      // The canonical parser only chooses between the caller's bag and its
      // JSON-text recovery, and only client-supplied bags are returned, so
      // application-owned parsing stays in the handler.
      validate: async (value: unknown) => {
        const recoveredArguments = recoveredArgumentBag(value);
        if (recoveredArguments !== undefined) {
          const recoveredResult = await standard.validate(recoveredArguments);
          if (!("issues" in recoveredResult))
            return { value: recoveredArguments };
          if ("issues" in (await standard.validate(value))) return { value };
        }
        return { value };
      },
    },
  };
};

/** Parse structured argument text a client serialized instead of sending as JSON. */
const structuredArgumentText = (supplied: unknown): unknown => {
  if (typeof supplied !== "string") return supplied;
  if (!supplied.startsWith("{") && !supplied.startsWith("[")) return supplied;
  // ponytail: parse cost is bounded by the MCP request size limit
  try {
    const parsed: unknown = JSON.parse(supplied);
    if (parsed !== null && typeof parsed === "object") return parsed;
  } catch {
    // Not JSON text: the supplied value keeps its meaning.
  }
  return supplied;
};

/**
 * Merge JSON-text structured arguments into the supplied bag; undefined when
 * nothing needs recovery so callers keep the caller's exact bag.
 */
const recoveredArgumentBag = (
  value: unknown,
): Record<string, unknown> | undefined => {
  if (typeof value !== "object" || value === null) return undefined;
  const suppliedArguments = value as Record<string, unknown>;
  const recovered = new Map<string, unknown>();
  for (const [argument, supplied] of Object.entries(suppliedArguments)) {
    const parsed = structuredArgumentText(supplied);
    if (parsed !== supplied) recovered.set(argument, parsed);
  }
  return recovered.size === 0
    ? undefined
    : { ...suppliedArguments, ...Object.fromEntries(recovered) };
};

/**
 * Recover structured arguments a client delivered as JSON text before the
 * canonical parser runs. Claude Desktop serializes array and object arguments
 * to strings (morluto/rea#3408), so every structured parameter of every tool
 * is rejected. Recovered values still face the canonical parser: JSON text a
 * string parameter accepts stays the caller's, malformed text keeps its
 * validation failure, and native JSON values are untouched. Recovery applies
 * to the argument bag as a whole, so a call that mixes recovered structured
 * arguments with JSON text a string parameter accepts keeps its rejection.
 * Application-owned validators recover through their own wrapper
 * (applicationValidatedInputSchema), which uses the same helper and keeps
 * failures in the handler.
 */
export const acceptStringifiedStructuredArguments = (
  schema: StandardSchemaWithJSON,
): StandardSchemaWithJSON => {
  const standard = schema["~standard"];
  if (standard === undefined || typeof standard.validate !== "function")
    return schema;
  if (standard.vendor === "rea-application") return schema;
  return {
    "~standard": {
      ...standard,
      validate: async (value: unknown) => {
        const recoveredArguments = recoveredArgumentBag(value);
        if (recoveredArguments === undefined) return standard.validate(value);
        const parsedResult = await standard.validate(recoveredArguments);
        if (!("issues" in parsedResult)) return parsedResult;
        const unchangedResult = await standard.validate(value);
        if (!("issues" in unchangedResult)) return unchangedResult;
        return parsedResult;
      },
    },
  };
};

/** Project the canonical Zod contracts directly into SDK registration. */
export const toolRegistrationOptions = <Contract extends ToolContract>(
  contract: Contract,
): {
  readonly title: Contract["title"];
  readonly description: Contract["description"];
  readonly inputSchema: Contract["inputSchema"];
  readonly outputSchema: Contract["outputSchema"];
  readonly annotations: Contract["annotations"];
} => ({
  title: contract.title,
  description: contract.description,
  inputSchema: toolInputSchemaWithMetadata(contract),
  outputSchema: toolOutputSchemaWithMetadata(contract),
  annotations: contract.annotations,
});
