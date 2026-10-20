import { z } from "zod";

import { digestSchema } from "../../domain/digests.js";

/**
 * Analysis-profile parameter committed by a REA-managed project-cache session.
 *
 * The same value is produced for a cache miss and a cache hit for one target,
 * so `analysisProfilesEqual` matches across sessions and a previously retained
 * analysis snapshot can replay. `import_profile_digest` is the digest of the
 * ephemeral import profile the key was derived from; `key` locates the stored
 * project. Neither field depends on how the program was obtained.
 */
export const ghidraProjectCacheCommitmentSchema = z.strictObject({
  key: digestSchema,
  import_profile_digest: digestSchema,
});
