import { randomUUID } from "node:crypto";
import { DeferredAnalysisClient } from "../providers/DeferredAnalysisClient.js";
import type { ProviderInspectionScope } from "../providers/ProviderInspectionScope.js";
import { analysisClientFailureForOperation } from "../providers/AnalysisClientFailure.js";
import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import {
  SharedStartupAttempt,
  STARTUP_OWNER_CLOSED,
} from "../process/SharedStartupAttempt.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { bindArtifactFileCleanup } from "../artifacts/ArtifactFileOperation.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import type {
  AnalysisClient,
  AnalysisClientContext,
  AnalysisProviderInspectionOptions,
  FileCloseResourceOwner,
  AnalysisProfileResolutionOptions,
  AnalysisProfileResolution,
  AnalysisProviderCandidate,
  AnalysisProviderReadinessSnapshot,
  CapabilityDescriptor,
  ProviderAvailability,
  ProviderIdentity,
  ProviderTargetSupport,
} from "../application/AnalysisProvider.js";
import type { AppConfig } from "../config/types.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import {
  isMachOFormat,
  type BinaryTarget,
} from "../domain/binaryTargetTypes.js";
import {
  jsonObjectSchema,
  jsonValueSchema,
  type JsonValue,
} from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { Logger } from "pino";
import { GhidraClient } from "./GhidraClient.js";
import type { GhidraProjectPersistence } from "./GhidraClientTypes.js";
import { GhidraProjectStore } from "./projectCache/GhidraProjectStore.js";
import type { GhidraProjectCacheIdentity } from "./projectCache/GhidraProjectCacheTypes.js";
import { ghidraProjectCacheCommitmentSchema } from "./projectCache/GhidraProjectCacheCommitment.js";
import type { GhidraProjectReservation } from "./projectCache/GhidraProjectStore.js";
import { PRODUCT_IDENTITY } from "../identity.js";
import {
  ghidraInstallationDiagnostics,
  inspectGhidraInstallation,
  type GhidraInstallationHost,
  type GhidraInstallationInspection,
} from "./GhidraInstallation.js";
import {
  ghidraExistingProjectUnsupportedReason,
  resolveGhidraAnalysisProfile,
} from "./GhidraAnalysisProfile.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { resolveGhidraAnalysisSeeds } from "./GhidraAnalysisSeeds.js";
import {
  admitGhidraLanguageOverride,
  GhidraLanguageCatalogCleanupError,
  readGhidraLanguageCatalog,
} from "./GhidraLanguageCatalog.js";
import {
  ghidraProcessorUnsupportedReason,
  isGhidraPspTarget,
} from "./GhidraPspProfile.js";
import { resolveGhidraExtensions } from "./extensions/GhidraExtensions.js";
import {
  CAPABILITIES,
  windowsP0Capabilities,
  GHIDRA_PROVIDER_IDENTITY,
  WINDOWS_P0_NATIVE_PE_ARCHITECTURES,
} from "./GhidraProviderCapabilities.js";
import {
  createGhidraProviderClient,
  admitGhidraClient,
  type GhidraProviderClientFactory,
} from "./GhidraProviderClient.js";
import {
  inspectWindowsNativeReadiness,
  type WindowsNativeReadiness,
  windowsNativeCapabilities,
} from "../process/WindowsAuthority.js";

const SUPPORTED_ARCHITECTURES = new Set([
  "x86",
  "x86_64",
  "arm",
  "arm64",
  "mips",
  "6502",
  "riscv",
  "powerpc",
  "m68k",
  "hexagon",
]);

/** Managed project-cache coordinates retained between profile and client creation. */
interface ManagedGhidraProject {
  readonly store: GhidraProjectStore;
  readonly identity: GhidraProjectCacheIdentity;
  readonly reservation: GhidraProjectReservation;
  /** A stored entry this session did not reuse and rebuilt with a fresh import. */
  readonly rejectedEntry?: {
    readonly reason: string;
    readonly path?: string;
    /** The entry was removed; false while another session still holds it. */
    readonly discarded: boolean;
  };
}

/** Ghidra candidate backed by an isolated ephemeral headless import. */
export class GhidraProvider implements AnalysisProviderCandidate {
  #installation: GhidraInstallationInspection | undefined;
  #store: GhidraProjectStore | undefined;
  /** Cache wiring keyed by the committed profile digest a client will receive. */
  readonly #managedProjects = new Map<string, ManagedGhidraProject>();
  readonly #inspectionResources = new ArtifactResourceScope();
  readonly #inspectionWork = new Set<Promise<unknown>>();
  #lifetime = new AbortController();
  readonly #observations = new WeakMap<
    ProviderInspectionScope,
    {
      readonly lifetime: AbortSignal;
      readonly installation: GhidraInstallationInspection;
    }
  >();
  #inspectionAttempt:
    | SharedStartupAttempt<Result<GhidraInstallationInspection, AnalysisError>>
    | undefined;
  readonly #inspectionOwner: FileCloseResourceOwner = {
    retain: (owner, resource) =>
      this.#inspectionResources.retain({
        kind: "lease",
        resource,
        lease: AnalysisCleanupLease.forCloseOwner(owner, resource),
      }),
    run: (operation) => this.#inspectionResources.run(operation),
  };
  #closing: Promise<Result<null, AnalysisError>> | undefined;
  private readonly environment: NodeJS.ProcessEnv;

  constructor(
    private readonly config: AppConfig,
    private readonly logger: Logger,
    environment: Readonly<NodeJS.ProcessEnv>,
    private readonly installationHost?: GhidraInstallationHost,
    private readonly clientFactory: GhidraProviderClientFactory = (options) =>
      new GhidraClient(options),
  ) {
    this.environment = snapshotEnvironment(
      environment,
      installationHost?.platform,
    );
  }

  identity(): ProviderIdentity {
    return GHIDRA_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return (this.installationHost?.platform ?? process.platform) === "win32"
      ? windowsP0Capabilities()
      : CAPABILITIES;
  }

  async inspectAvailability(
    options: AnalysisProviderInspectionOptions = {},
  ): Promise<ProviderAvailability> {
    return (await this.inspectReadinessSnapshot(options)).availability;
  }

  inspectReadinessSnapshot(
    options: AnalysisProviderInspectionOptions = {},
  ): Promise<AnalysisProviderReadinessSnapshot> {
    return this.#runInspectionWork(
      (signal) => this.#readinessSnapshot(signal, options.scope),
      options.signal,
    );
  }

  async #readinessSnapshot(
    signal: AbortSignal,
    scope?: ProviderInspectionScope,
  ): Promise<AnalysisProviderReadinessSnapshot> {
    const installation = await this.#inspectInstallation(
      signal,
      "binary_session",
      scope,
    );
    const readiness =
      installation.platform === "win32"
        ? inspectWindowsNativeReadiness(installation.platform)
        : undefined;
    const availability = this.#availability(installation, readiness);
    if (availability.status === "available" && signal.aborted)
      throw new AnalysisCancelledError("binary_session", {
        cause: signal.reason,
        diagnostics: availability.diagnostics,
      });
    return {
      availability,
      capabilities:
        readiness === undefined
          ? CAPABILITIES
          : windowsP0Capabilities(readiness),
    };
  }

  #availability(
    installation: GhidraInstallationInspection,
    readiness: WindowsNativeReadiness | undefined,
  ): ProviderAvailability {
    const diagnostics = ghidraInstallationDiagnostics(installation);
    if (installation.status === "available" && readiness?.available === false)
      return {
        status: "unavailable",
        code: readiness.code,
        reason: readiness.reason,
        diagnostics: {
          ...diagnostics,
          windows_security: jsonObjectSchema.parse(
            windowsNativeCapabilities(installation.platform, readiness),
          ),
          windows_native_failure: {
            stage: readiness.failureStage,
            remediation: readiness.remediation,
          },
        },
      };
    return installation.status === "available"
      ? {
          status: "available",
          code: null,
          reason: null,
          diagnostics,
        }
      : {
          status: "unavailable",
          code: installation.rejection.code,
          reason: installation.rejection.reason,
          diagnostics,
        };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    const hostPlatform = this.installationHost?.platform ?? process.platform;
    const diagnostics = {
      host_platform: hostPlatform,
      target_kind: target.kind,
      target_format: target.format,
      architecture: target.architecture ?? null,
      available_architectures:
        target.kind === "executable"
          ? [...target.availableArchitectures]
          : null,
      executable_role: target.executableRole ?? null,
      managed: target.managed ?? null,
    };
    if (target.kind !== "executable")
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason: `Ghidra v1 imports executable targets, not ${target.kind} targets.`,
        diagnostics,
      };
    if (hostPlatform === "win32")
      return inspectWindowsP0TargetSupport(target, diagnostics);
    const mipsReason =
      isGhidraPspTarget(target) &&
      (hostPlatform !== "linux" ||
        (this.installationHost?.architecture ?? process.arch) !== "x64")
        ? "The initial PSP Allegrex profile is verified on Linux x64 only."
        : ghidraProcessorUnsupportedReason(target);
    if (mipsReason !== null)
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason: mipsReason,
        diagnostics,
      };
    if (
      isMachOFormat(target.format) &&
      target.availableArchitectures.length > 1
    )
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "Ghidra v1 cannot enforce the selected architecture when importing a universal Mach-O; analyze a thinned Mach-O slice instead.",
        diagnostics,
      };
    if (!SUPPORTED_ARCHITECTURES.has(target.architecture))
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "Ghidra v1 requires a supported x86, x86_64, arm, arm64, MIPS, RISC-V, raw 6502, or raw m68k target profile.",
        diagnostics,
      };
    return {
      status: "supported",
      code: null,
      reason: null,
      diagnostics,
    };
  }

  hasPendingOwnedResources(): boolean {
    return (
      this.#inspectionWork.size > 0 ||
      this.#inspectionAttempt !== undefined ||
      this.#inspectionResources.hasPending
    );
  }

  closeOwnedResources() {
    this.#closing ??= Promise.resolve()
      .then(async () => {
        this.#lifetime.abort(STARTUP_OWNER_CLOSED);
        this.#inspectionAttempt?.close();
        await Promise.allSettled([
          ...this.#inspectionWork,
          ...(this.#inspectionAttempt === undefined
            ? []
            : [this.#inspectionAttempt.promise]),
        ]);
        return this.#closeInspectionResources();
      })
      .finally(() => {
        this.#lifetime = new AbortController();
        this.#closing = undefined;
      });
    return this.#closing;
  }

  async #closeInspectionResources() {
    try {
      await this.#inspectionResources.retryCleanup();
      return ok(null);
    } catch (cause: unknown) {
      const error = new ProviderCleanupError(
        "ghidra",
        cause instanceof ArtifactReaderFailure
          ? (cause.cleanup?.resources ?? [])
          : [],
        { reason: providerFailureText(cause) },
        { cause },
      );
      bindArtifactFileCleanup(cause, error);
      return err(error);
    }
  }

  async resolveAnalysisProfile(
    target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ): Promise<Result<AnalysisProfileResolution, AnalysisError>> {
    try {
      return await this.#runInspectionWork(async (signal) => {
        const result = await this.#resolveProfile(target, {
          ...options,
          signal,
        });
        if (!result.ok && result.error instanceof AnalysisCancelledError)
          return err(
            analysisClientFailureForOperation(
              result.error,
              "ghidra",
              "open_binary",
            ),
          );
        if (result.ok && signal.aborted)
          return err(
            new AnalysisCancelledError("open_binary", {
              cause: signal.reason,
              diagnostics: {
                completed_profile_digest: result.value.profile?.digest ?? null,
              },
            }),
          );
        return result;
      }, options?.signal);
    } catch (cause: unknown) {
      return err(
        analysisClientFailureForOperation(
          cause,
          "ghidra",
          cause instanceof AnalysisCancelledError
            ? "open_binary"
            : "resolve_analysis_profile",
        ),
      );
    }
  }

  async #resolveProfile(
    target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ) {
    const installation = await this.#inspectInstallation(
      options?.signal,
      "resolve_analysis_profile",
      options?.scope,
    );
    const resolved = await resolveGhidraAnalysisProfile(
      target,
      GHIDRA_PROVIDER_IDENTITY,
      installation,
      this.#inspectionResources,
      options?.signal,
      this.config.ghidraLanguageOverride,
      this.config.ghidraDisabledAnalyzers,
      this.config.ghidraExistingProject !== undefined,
    );
    if (!resolved.ok || resolved.value.profile === null) return resolved;
    const override = this.config.ghidraLanguageOverride;
    if (override !== undefined && installation.status === "available") {
      let catalog: Awaited<ReturnType<typeof readGhidraLanguageCatalog>>;
      try {
        catalog = await readGhidraLanguageCatalog(installation.installDir);
      } catch (cause: unknown) {
        if (cause instanceof GhidraLanguageCatalogCleanupError)
          return err(
            new ProviderCleanupError(
              "ghidra",
              cause.paths,
              {
                reason: cause.message,
                paths: [...cause.paths],
                close_failures: cause.causes.map(providerFailureText),
                ...(cause.readFailure === undefined
                  ? {}
                  : { read_failure: providerFailureText(cause.readFailure) }),
              },
              { operation: "resolve_analysis_profile", cause },
            ),
          );
        return err(
          new ProviderAdapterError("ghidra", "resolve_analysis_profile", {
            cause,
            diagnostics: {
              reason:
                "Could not read the installed Ghidra language definitions.",
            },
          }),
        );
      }
      const refused = admitGhidraLanguageOverride(
        override,
        catalog,
        installation.providerVersion,
      );
      if (refused !== null) return err(refused);
    }
    const extensions = await resolveGhidraExtensions(
      this.config,
      target,
      installation.platform,
      this.#inspectionResources,
      options?.signal,
    );
    if (!extensions.ok) return extensions;
    if (options?.signal?.aborted === true)
      return err(
        new AnalysisCancelledError("open_binary", {
          cause: options.signal.reason,
        }),
      );
    const seeds = await resolveGhidraAnalysisSeeds(
      this.config.ghidraSeedFile,
      this.#inspectionResources,
      options?.signal,
    );
    if (!seeds.ok) return seeds;
    const existingProject = this.config.ghidraExistingProject;
    const intentProfile = createAnalysisProfile(
      resolved.value.profile.provider,
      {
        ...resolved.value.profile.parameters,
        ...(extensions.value.length === 0
          ? {}
          : { analysis_extensions: jsonValueSchema.parse(extensions.value) }),
        ...(seeds.value === undefined
          ? {}
          : { analysis_seeds: jsonValueSchema.parse(seeds.value) }),
      },
    );
    if (existingProject !== undefined)
      return ok({
        ...resolved.value,
        profile: createAnalysisProfile(resolved.value.profile.provider, {
          ...intentProfile.parameters,
          // A caller-selected project is not manifest-verified, so its state is
          // never treated as a reusable identity: each resolution gets its own
          // session id and snapshots stay session-local.
          existing_project: {
            program_name: existingProject.programName,
            session_id: randomUUID(),
          },
        }),
      });
    const managed = await this.#prepareManagedProject(
      target,
      installation,
      intentProfile,
      options?.signal,
    );
    if (managed !== undefined) {
      this.#managedProjects.set(managed.profile.digest, managed.persistence);
      return ok({ ...resolved.value, profile: managed.profile });
    }
    return ok({ ...resolved.value, profile: intentProfile });
  }

  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
    context?: AnalysisClientContext,
  ): AnalysisClient {
    const managed =
      profile === undefined
        ? undefined
        : this.#managedProjects.get(profile.digest);
    return new DeferredAnalysisClient(async (signal, resourceOwner) => {
      const admitted = admitGhidraClient(
        target,
        profile,
        this.installationHost?.platform ?? process.platform,
      );
      if (!admitted.ok) throw admitted.error;
      const installation = await this.#observeInstallation(
        signal,
        resourceOwner,
      );
      const created = createGhidraProviderClient({
        config: this.config,
        environment: this.environment,
        logger: this.logger,
        clientFactory: this.clientFactory,
        admission: admitted.value,
        ...(context === undefined ? {} : { context }),
        installation,
        signal,
        ...(managed === undefined
          ? {}
          : {
              projectPersistence: this.#persistenceFor(
                target,
                managed,
                context,
              ),
            }),
      });
      if (!created.ok) throw created.error;
      return created.value;
    }, "ghidra");
  }

  async #runInspectionWork<T>(
    operation: (signal: AbortSignal) => Promise<T>,
    callerSignal?: AbortSignal,
  ): Promise<T> {
    if (this.#closing !== undefined) {
      const closed = await this.#closing;
      if (!closed.ok) throw closed.error;
    }
    const signal =
      callerSignal === undefined
        ? this.#lifetime.signal
        : AbortSignal.any([callerSignal, this.#lifetime.signal]);
    if (signal.aborted)
      throw new AnalysisCancelledError("ghidra:inspection", {
        cause: signal.reason,
      });
    const work = Promise.resolve().then(() => operation(signal));
    this.#inspectionWork.add(work);
    try {
      return await work;
    } finally {
      this.#inspectionWork.delete(work);
    }
  }

  async #inspectInstallation(
    callerSignal: AbortSignal | undefined,
    operation: string,
    scope?: ProviderInspectionScope,
  ): Promise<GhidraInstallationInspection> {
    if (callerSignal?.aborted)
      throw new AnalysisCancelledError(operation, {
        cause: callerSignal.reason,
      });
    if (scope?.active) {
      const observed = this.#observations.get(scope);
      if (observed?.lifetime === this.#lifetime.signal)
        return observed.installation;
    }
    let attempt = this.#inspectionAttempt;
    if (attempt === undefined) {
      attempt = new SharedStartupAttempt(
        (signal) =>
          Promise.resolve().then(async () => {
            try {
              return ok(await this.#observeInstallation(signal));
            } catch (cause: unknown) {
              return err(
                analysisClientFailureForOperation(
                  cause,
                  "ghidra",
                  "ghidra:inspection",
                ),
              );
            }
          }),
        this.#lifetime.signal,
      );
      const owned = attempt;
      this.#inspectionAttempt = owned;
      void owned.promise.then(
        () => {
          if (this.#inspectionAttempt === owned)
            this.#inspectionAttempt = undefined;
        },
        () => {
          if (this.#inspectionAttempt === owned)
            this.#inspectionAttempt = undefined;
        },
      );
    }
    const waited = await attempt.wait(callerSignal);
    if (waited.status === "cancelled")
      throw new AnalysisCancelledError(operation, {
        cause: callerSignal?.reason,
      });
    if (!waited.value.ok)
      throw analysisClientFailureForOperation(
        waited.value.error,
        "ghidra",
        operation,
      );
    if (
      waited.value.value.status === "available" &&
      (callerSignal?.aborted || attempt.signal.aborted)
    )
      throw new AnalysisCancelledError(operation, {
        cause: callerSignal?.aborted
          ? callerSignal.reason
          : attempt.signal.reason,
        diagnostics: ghidraInstallationDiagnostics(waited.value.value),
      });
    if (scope?.active && !callerSignal?.aborted && !attempt.signal.aborted)
      this.#observations.set(scope, {
        lifetime: this.#lifetime.signal,
        installation: waited.value.value,
      });
    return waited.value.value;
  }

  #observeInstallation(
    signal: AbortSignal,
    resourceOwner: FileCloseResourceOwner = this.#inspectionOwner,
  ): Promise<GhidraInstallationInspection> {
    const options = {
      resourceOwner,
      signal,
      environment: this.environment,
      ...(this.config.ghidraInstallDir === undefined
        ? {}
        : { installDir: this.config.ghidraInstallDir }),
      ...(this.config.ghidraJavaHome === undefined
        ? {}
        : { javaHome: this.config.ghidraJavaHome }),
      ...(this.installationHost?.platform === undefined
        ? {}
        : { platform: this.installationHost.platform }),
      ...(this.installationHost?.architecture === undefined
        ? {}
        : { architecture: this.installationHost.architecture }),
    };
    return this.installationHost === undefined
      ? inspectGhidraInstallation(options)
      : inspectGhidraInstallation(options, this.installationHost);
  }

  #projectStore(): GhidraProjectStore | undefined {
    if (this.config.ghidraProjectCache.mode === "off") return undefined;
    this.#store ??= new GhidraProjectStore({
      root: this.config.ghidraProjectCache.directory,
      maxBytes: this.config.ghidraProjectCache.maxBytes,
      platform: this.installationHost?.platform ?? process.platform,
      ...(this.config.ghidraProjectCache.maxAgeDays === undefined
        ? {}
        : { maxAgeDays: this.config.ghidraProjectCache.maxAgeDays }),
    });
    return this.#store;
  }

  /**
   * Resolve a managed stored project for this target, or reserve a staging slot
   * on a miss. Returns undefined (keeping the ephemeral profile) when the cache
   * is disabled, unsupported for the target, or unreadable.
   */
  async #prepareManagedProject(
    target: BinaryTarget,
    installation: GhidraInstallationInspection,
    intentProfile: AnalysisProfileCommitment,
    signal?: AbortSignal,
  ): Promise<
    | {
        readonly profile: AnalysisProfileCommitment;
        readonly persistence: ManagedGhidraProject;
      }
    | undefined
  > {
    const store = this.#projectStore();
    if (store === undefined || installation.status !== "available")
      return undefined;
    // A stored project opens with -process, which DOS, raw-binary and PSP
    // targets cannot select, so those lanes are never cached.
    if (ghidraExistingProjectUnsupportedReason(target) !== null)
      return undefined;
    const identity: GhidraProjectCacheIdentity = {
      providerId: GHIDRA_PROVIDER_IDENTITY.id,
      providerVersion: installation.providerVersion,
      jvmVmName: installation.javaVmName ?? "unknown",
      platform: installation.platform,
      targetSha256: target.sha256,
      importProfileDigest: intentProfile.digest,
    };
    let prepared;
    try {
      prepared = await store.prepare({
        identity,
        mode: this.config.ghidraProjectCache.mode,
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (cause: unknown) {
      this.logger.warn(
        { error: providerFailureText(cause) },
        "Ghidra project cache lookup failed; importing fresh",
      );
      return undefined;
    }
    if (!prepared.ok) {
      this.logger.warn(
        { reason: prepared.error.reason, path: prepared.error.path },
        "Ghidra project cache lookup failed; importing fresh",
      );
      return undefined;
    }
    if (prepared.value === null) return undefined;
    const preparation = prepared.value.rootPreparation;
    if (preparation.status === "repaired")
      this.logger.warn(
        {
          preserved_entries: preparation.preservedEntries,
          ...(preparation.leftoverRoot === undefined
            ? {}
            : { leftover_root: preparation.leftoverRoot }),
        },
        "Rebuilt the Ghidra project cache root as an owner-only directory",
      );
    const rejected = prepared.value.rejectedEntry;
    if (rejected !== undefined)
      this.logger.warn(
        {
          reason: rejected.error.reason,
          path: rejected.error.path,
        },
        rejected.discarded
          ? "Discarded a stored Ghidra project that could not be reused; a fresh import will rebuild it"
          : "A stored Ghidra project was not reused; a fresh import will rebuild it",
      );
    const parameters: Record<string, JsonValue> = {
      ...intentProfile.parameters,
    };
    // Identity is open-mode independent: import-mode provenance is dropped so a
    // miss and a hit commit the same profile for one target, which lets a
    // stored analysis snapshot replay in a later session.
    delete parameters.import_mode;
    const profile = createAnalysisProfile(intentProfile.provider, {
      ...parameters,
      project_cache: ghidraProjectCacheCommitmentSchema.parse({
        key: prepared.value.key,
        import_profile_digest: identity.importProfileDigest,
      }),
    });
    return {
      profile,
      persistence: {
        store,
        identity,
        reservation: prepared.value,
        ...(rejected === undefined
          ? {}
          : {
              rejectedEntry: {
                reason: rejected.error.reason,
                ...(rejected.error.path === undefined
                  ? {}
                  : { path: rejected.error.path }),
                discarded: rejected.discarded,
              },
            }),
      },
    };
  }

  #persistenceFor(
    target: BinaryTarget,
    managed: ManagedGhidraProject,
    context: AnalysisClientContext | undefined,
  ): GhidraProjectPersistence {
    const reuse = managed.reservation.hit;
    return {
      store: managed.store,
      reservation: managed.reservation,
      identity: managed.identity,
      target: {
        sha256: target.sha256,
        kind: target.kind,
        format: target.format,
        architecture: target.architecture ?? null,
        executable_role: target.executableRole ?? null,
      },
      producer: {
        reaVersion: PRODUCT_IDENTITY.packageVersion,
        runId: context?.runId ?? randomUUID(),
      },
      publishable: !reuse && managed.reservation.stagingPath !== undefined,
      reuse,
      ...(managed.rejectedEntry === undefined
        ? {}
        : { rejectedEntry: managed.rejectedEntry }),
    };
  }
}

const providerFailureText = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

const inspectWindowsP0TargetSupport = (
  target: BinaryTarget,
  diagnostics: Readonly<Record<string, JsonValue>>,
): ProviderTargetSupport => {
  // The raw 6502 lane uses the same immutable snapshot and native ownership boundary.
  if (target.format === "raw-binary" && target.architecture === "6502")
    return { status: "supported", code: null, reason: null, diagnostics };
  if (target.format !== "pe")
    return {
      status: "unsupported",
      code: "target_format_unsupported",
      reason:
        "Windows Ghidra P0 accepts native PE and explicitly selected raw 6502 targets only.",
      diagnostics,
    };
  if (!WINDOWS_P0_NATIVE_PE_ARCHITECTURES.includes(target.architecture))
    return {
      status: "unsupported",
      code: "architecture_unsupported",
      reason:
        "Windows Ghidra P0 accepts x86, x86-64, ARM and ARM64 PE targets only.",
      diagnostics,
    };
  if (
    target.executableRole !== "application" &&
    target.executableRole !== "shared-library"
  )
    return {
      status: "unsupported",
      code: "target_role_unsupported",
      reason:
        "Windows Ghidra P0 accepts PE applications and DLLs, not non-executable or unclassified images.",
      diagnostics,
    };
  if (target.managed !== false)
    return {
      status: "unsupported",
      code: "managed_target_unsupported",
      reason:
        "Windows Ghidra P0 accepts native PE applications and DLLs; managed or unclassified PE targets are unsupported.",
      diagnostics,
    };
  if (
    (target.architecture === "arm" && target.peMachine !== 0x01c4) ||
    (target.architecture === "arm64" && target.peMachine !== 0xaa64)
  )
    return {
      status: "unsupported",
      code: "architecture_unsupported",
      reason:
        "Windows Ghidra P0 ARM PE targets require observed ARMNT (0x01c4) or ARM64 (0xaa64) COFF machines; legacy ARM/Thumb and unknown machines are unsupported.",
      diagnostics: { ...diagnostics, pe_machine: target.peMachine ?? null },
    };
  return {
    status: "supported",
    code: null,
    reason: null,
    diagnostics,
  };
};
