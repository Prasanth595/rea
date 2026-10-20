/** Database mutations the real bridge admits only on a Unix socket transport. */
export const MUTATING_METHODS = new Set([
  "annotate_native_function",
  "set_address_name",
  "set_addresses_names",
]);

/**
 * Answer a database mutation the way the real bridge does.
 *
 * The read-only Windows transport refuses the mutation, and a Unix socket
 * applies it to the session database and answers with the refreshed
 * observation. A bridge that advertised a capability and stayed silent would
 * leave every caller waiting for a reply that never arrives.
 */
export const handleMutation = (socket, request, transport) => {
  if (transport !== "unix-socket") {
    socket.write(
      `${JSON.stringify({
        id: request.id,
        ok: false,
        error: {
          code: "method_unavailable",
          message: "Windows P0 does not admit database mutation",
        },
      })}\n`,
    );
    return;
  }
  socket.write(
    `${JSON.stringify({
      id: request.id,
      ok: true,
      result: mutationResultFor(request.method, request.params),
    })}\n`,
  );
};

/** The refreshed observation one applied mutation returns. */
const mutationResultFor = (method, params) => {
  if (method === "set_address_name") return true;
  if (method === "set_addresses_names") return addressNameResults(params);
  return {
    annotations: {
      address: "0x1000",
      name: textValue(params, "name") ?? "fixture_main",
      comment: annotationText(params, "comment"),
      inline_comment: annotationText(params, "inline_comment"),
    },
    // This partial bridge models the mutation envelope; a provider-level
    // function dossier is not part of its wire surface.
    dossier: {
      procedure: {
        address: "0x1000",
        name: "fixture_main",
        classification: {
          external: false,
          thunk: false,
          thunk_target: null,
          provenance: "ghidra-function-manager",
        },
      },
    },
    effects: {
      scope: "session-analysis-database",
      source_bytes_modified: false,
      persists_after_close: false,
    },
  };
};

/** Per-address success for one batch of primary-label renames. */
const addressNameResults = (params) => {
  const names = params?.names;
  if (names === null || typeof names !== "object" || Array.isArray(names))
    return {};
  return Object.fromEntries(
    Object.keys(names).map((address) => [address, true]),
  );
};

const textValue = (params, field) =>
  typeof params?.[field] === "string" ? params[field] : undefined;

/** Empty annotation text clears the comment, exactly like the real bridge. */
const annotationText = (params, field) => {
  const value = textValue(params, field);
  return value === undefined || value === "" ? null : value;
};
