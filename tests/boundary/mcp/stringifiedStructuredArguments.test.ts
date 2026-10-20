import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";
import { describe, expect, it, onTestFinished } from "vitest";
import { z } from "zod";

import { toolContract } from "../../../src/contracts/toolContracts.js";
import { EvidenceMcpServer } from "../../../src/server/EvidenceMcpServer.js";
import { ToolResultDelivery } from "../../../src/server/toolResult.js";
import {
  applicationValidatedInputSchema,
  toolRegistrationOptions,
} from "../../../src/server/toolRegistrationOptions.js";

type ToolName = Parameters<typeof toolContract>[0];

/** Deliver every top-level structured argument as the JSON text clients send. */
const asJsonTextArguments = (
  input: Readonly<Record<string, unknown>>,
): Record<string, unknown> =>
  Object.fromEntries(
    Object.entries(input).map(([argument, supplied]) =>
      supplied !== null && typeof supplied === "object"
        ? [argument, JSON.stringify(supplied)]
        : [argument, supplied],
    ),
  );

const connect = async (
  register: (
    server: EvidenceMcpServer,
    record: (input: unknown) => void,
  ) => void,
): Promise<{ client: Client; calls: unknown[] }> => {
  const calls: unknown[] = [];
  const server = new EvidenceMcpServer(
    { name: "stringified-arguments", version: "1" },
    { capabilities: {} },
    undefined,
    new ToolResultDelivery(STDIO_DEFAULT_MAX_BUFFER_SIZE),
  );
  register(server, (input) => calls.push(input));
  const client = new Client({ name: "stringified-arguments", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, calls };
};

/** Register a contract with its canonical input but no output contract. */
const registerContractTool = (
  server: EvidenceMcpServer,
  name: ToolName,
  record: (input: unknown) => void,
): void => {
  const { outputSchema: _contractOutput, ...config } = toolRegistrationOptions(
    toolContract(name),
  );
  server.registerTool(name, config, (input: unknown) => {
    record(input);
    return { content: [] };
  });
};

describe("stringified structured tool arguments", () => {
  it("recovers structured arguments a client delivered as JSON text", async () => {
    const example = toolContract("capture_browser_scenario").examples[0].input;
    const supplied = asJsonTextArguments(example);
    expect(supplied).not.toEqual(example);
    const { client, calls } = await connect((server, record) =>
      registerContractTool(server, "capture_browser_scenario", record),
    );

    await client.callTool({
      name: "capture_browser_scenario",
      arguments: supplied,
    });

    expect(calls[0]).toMatchObject({
      browser: example["browser"],
      start_url: example["start_url"],
      actions: example["actions"],
    });
  });

  it("recovers an array argument on inspect_web_page", async () => {
    const example = toolContract("inspect_web_page").examples[0].input;
    const supplied = {
      ...example,
      allowed_origins: JSON.stringify(["https://example.com"]),
    };
    const { client, calls } = await connect((server, record) =>
      registerContractTool(server, "inspect_web_page", record),
    );

    await client.callTool({ name: "inspect_web_page", arguments: supplied });

    expect(calls[0]).toMatchObject({
      allowed_origins: ["https://example.com"],
      target_id: example["target_id"],
    });
  });

  it("keeps JSON text a string parameter accepts as the caller sent it", async () => {
    const jsonText = '{"origin":"https://example.com"}';
    const { client, calls } = await connect((server, record) => {
      server.registerTool(
        "record_note",
        { inputSchema: z.object({ note: z.string() }) },
        (input) => {
          record(input);
          return { content: [] };
        },
      );
    });

    await client.callTool({
      name: "record_note",
      arguments: { note: jsonText },
    });

    expect(calls[0]).toEqual({ note: jsonText });
  });

  it("keeps JSON-looking strings intact on application-validated registrations", async () => {
    const { client, calls } = await connect((server, record) => {
      server.registerTool(
        "inspect_capture_path",
        {
          inputSchema: applicationValidatedInputSchema(
            z.object({ path: z.string() }),
          ),
        },
        (input: unknown) => {
          record(input);
          return { content: [] };
        },
      );
    });

    await client.callTool({
      name: "inspect_capture_path",
      arguments: { path: "[]" },
    });

    expect(calls[0]).toEqual({ path: "[]" });
  });

  it("recovers structured arguments on application-validated registrations", async () => {
    const { client, calls } = await connect((server, record) => {
      server.registerTool(
        "inspect_capture_ordinals",
        {
          inputSchema: applicationValidatedInputSchema(
            z.object({ record_ordinals: z.array(z.number()) }),
          ),
        },
        (input: unknown) => {
          record(input);
          return { content: [] };
        },
      );
    });

    await client.callTool({
      name: "inspect_capture_ordinals",
      arguments: { record_ordinals: "[0]" },
    });

    expect(calls[0]).toEqual({ record_ordinals: [0] });
  });

  it("keeps application-owned failures on the caller's original arguments", async () => {
    const { client, calls } = await connect((server, record) => {
      server.registerTool(
        "inspect_capture_ordinals",
        {
          inputSchema: applicationValidatedInputSchema(
            z.object({ record_ordinals: z.array(z.number()) }),
          ),
        },
        (input: unknown) => {
          record(input);
          return { content: [] };
        },
      );
    });

    await client.callTool({
      name: "inspect_capture_ordinals",
      arguments: { record_ordinals: '{"0":0}' },
    });

    expect(calls[0]).toEqual({ record_ordinals: '{"0":0}' });
  });

  it("still rejects structured text that is not JSON", async () => {
    const example = toolContract("capture_browser_scenario").examples[0].input;
    const { client } = await connect((server, record) =>
      registerContractTool(server, "capture_browser_scenario", record),
    );

    const result = await client.callTool({
      name: "capture_browser_scenario",
      arguments: { ...example, actions: '["unterminated' },
    });

    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain(
      "Invalid arguments for tool capture_browser_scenario",
    );
  });
});
