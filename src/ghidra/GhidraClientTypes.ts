import type { Logger } from "pino";
import type { Result } from "../domain/result.js";
import type { GhidraLauncher } from "./GhidraLauncher.js";
import type { GhidraSessionError } from "./GhidraSessionError.js";
import type { GhidraSessionInfo } from "./GhidraSessionValues.js";
import type { GhidraTransportKind } from "./GhidraTransport.js";
import type { GhidraProjectCacheIdentity } from "./projectCache/GhidraProjectCacheTypes.js";
import type { GhidraProjectManifestTarget } from "./projectCache/GhidraProjectManifest.js";
import type {
  GhidraProjectReservation,
  GhidraProjectStore,
} from "./projectCache/GhidraProjectStore.js";

/**
 * Persistence wiring for one Ghidra session: a stored project resolved by the
 * provider, published after a clean fresh import or opened read-only on a hit.
 */
export interface GhidraProjectPersistence {
  readonly store: GhidraProjectStore;
  readonly reservation: GhidraProjectReservation;
  readonly identity: GhidraProjectCacheIdentity;
  readonly target: GhidraProjectManifestTarget;
  readonly producer: { readonly reaVersion: string; readonly runId: string };
  /** True only for a populate-capable miss; a hit never publishes. */
  readonly publishable: boolean;
  /** True only on a hit, when the launcher opens the stored program. */
  readonly reuse: boolean;
  /** A stored entry this session did not reuse and rebuilt with a fresh import. */
  readonly rejectedEntry?: {
    readonly reason: string;
    readonly path?: string;
    /** The entry was removed; false while another session still holds it. */
    readonly discarded: boolean;
  };
}

/** Result of opening and authenticating one headless Ghidra session. */
export type GhidraStartResult = Result<GhidraSessionInfo, GhidraSessionError>;

/** Cancellation and deadline controls shared by authenticated requests. */
export interface GhidraRequestOptions {
  readonly signal?: AbortSignal;
  /** Internal startup/shutdown deadline; analysis calls have no fixed deadline. */
  readonly timeoutMs?: number;
}

/** Safe lifecycle telemetry for one isolated Ghidra headless process. */
export type GhidraDiagnostic =
  | {
      readonly type: "launcher-output";
      readonly stream: "stdout" | "stderr";
      readonly bytes: number;
      readonly totalBytes: number;
    }
  | {
      readonly type: "launcher-exit";
      readonly code: number | null;
      readonly signal: NodeJS.Signals | null;
    }
  | { readonly type: "cleanup-incomplete"; readonly reason: string };

/** Dependencies and exact profile commitment for one headless import. */
export interface GhidraClientOptions {
  readonly launcher: GhidraLauncher;
  readonly runId?: string;
  readonly targetPath: string;
  readonly targetSha256: string;
  /** Installation host shared by runtime allocation and snapshot admission. */
  readonly platform?: NodeJS.Platform;
  readonly transport?: GhidraTransportKind;
  readonly providerVersion: string;
  readonly profileDigest: string;
  readonly expectedLanguageId?: string;
  readonly expectedCompilerSpecId?: string;
  readonly startupTimeoutMs?: number;
  readonly onDiagnostic?: (event: GhidraDiagnostic) => void;
  readonly logger?: Logger;
  /** Managed project-cache wiring; absent disables reuse and publish. */
  readonly projectPersistence?: GhidraProjectPersistence;
}
