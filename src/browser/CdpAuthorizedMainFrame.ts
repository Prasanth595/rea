import type { BrowserObservationOperation } from "../domain/browserObservationErrors.js";
import { BrowserObservationError } from "../domain/browserObservationError.js";
import type { CdpConnection } from "./CdpConnection.js";
import {
  classifyCdpFrameUrl,
  observeMainFrameUrl,
} from "./CdpCaptureDocuments.js";
import { delayWithCancellation, isHttpUrl } from "./CdpCaptureValues.js";

interface AuthorizedMainFrameOptions {
  readonly connection: CdpConnection;
  readonly sessionId: string | undefined;
  readonly signal: AbortSignal | undefined;
  readonly allowedOrigins: ReadonlySet<string>;
  readonly operation: BrowserObservationOperation;
}

/** Wait for the attached target's main frame to enter its approved origin. */
export const authorizedMainFrame = async ({
  connection,
  sessionId,
  signal,
  allowedOrigins,
  operation,
}: AuthorizedMainFrameOptions): Promise<unknown> => {
  for (let attempt = 0; attempt < 80; attempt += 1) {
    const result = await connection.send(
      "Page.getFrameTree",
      {},
      sessionId,
      signal,
    );
    const observed = observeMainFrameUrl(result);
    const facts = classifyCdpFrameUrl(observed, allowedOrigins);
    if (observed.kind === "invalid_fragment") {
      const reason =
        facts.scope === "approved" ? "protocol_error" : "target_not_allowed";
      throw new BrowserObservationError(operation, reason);
    }
    const url = observed.kind === "observed" ? observed.url : undefined;
    if (facts.url !== undefined) return result;
    if (isHttpUrl(url))
      throw new BrowserObservationError(operation, "target_not_allowed");
    await delayWithCancellation(25, operation, signal);
  }
  throw new BrowserObservationError(operation, "target_not_allowed");
};
