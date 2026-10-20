import { describe, expect, it } from "vitest";

import { CdpBrowserProvider } from "../../../src/browser/CdpBrowserProvider.js";
import { observeWebSessionInputSchema } from "../../../src/domain/browserSession.js";
import { startFakeCdpBrowser } from "../../fixtures/fakeCdpBrowser.js";
import { trackBrowser } from "./cdpBrowserProvider.support.js";

it.each([
  "malformed-event",
  "missing-same-document",
  "missing-redirect",
  "foreign-event",
  "malformed-final",
  "normal",
])("distinguishes protocol uncertainty in committed URLs: %s", async (kind) => {
  const browser = await startFakeCdpBrowser({
    eventsBeforeReply: ["Page.setLifecycleEventsEnabled"],
    commandResult: ({ method }, origin, reads) =>
      method === "Page.getFrameTree" && kind === "malformed-final" && reads > 1
        ? {
            frameTree: {
              frame: {
                id: "frame-main",
                url: `${origin}/app`,
                urlFragment: 7,
              },
            },
          }
        : undefined,
    commandEvents: ({ method, sessionId }, origin) => {
      if (method !== "Page.setLifecycleEventsEnabled") return undefined;
      const scope = sessionId === undefined ? {} : { sessionId };
      if (kind === "missing-same-document")
        return [
          {
            method: "Page.navigatedWithinDocument",
            ...scope,
            params: { frameId: "frame-main" },
          },
        ];
      if (kind === "missing-redirect")
        return [
          {
            method: "Network.requestWillBeSent",
            ...scope,
            params: {
              frameId: "frame-main",
              requestId: "redirect",
              type: "Document",
              redirectResponse: { status: 302 },
              request: {},
            },
          },
        ];
      return method === "Page.setLifecycleEventsEnabled"
        ? [
            {
              method: "Page.frameNavigated",
              ...(sessionId === undefined ? {} : { sessionId }),
              params: {
                frame: {
                  id: "frame-main",
                  loaderId: "loader-main",
                  url:
                    kind === "foreign-event"
                      ? "https://foreign.test/"
                      : `${origin}/app`,
                  ...(kind === "malformed-event" ? { urlFragment: 7 } : {}),
                },
              },
            },
          ]
        : undefined;
    },
  });
  trackBrowser(browser);
  const result = await new CdpBrowserProvider().observeSession(
    observeWebSessionInputSchema.parse({
      cdp_endpoint: browser.endpoint,
      allowed_origins: [browser.allowedOrigin],
      target_id: "allowed-page",
      observation_ms: 1,
    }),
  );
  if (!result.ok) throw result.error;
  if (
    kind === "malformed-event" ||
    kind.startsWith("missing-") ||
    kind === "malformed-final"
  ) {
    expect(result.value.completeness.excluded).toContainEqual({
      section: "timeline",
      reason: "invalid_protocol_value",
      count: 1,
    });
    expect(result.value.completeness.policy_filtered_sections).toEqual([]);
  }
  if (kind === "malformed-final")
    expect(result.value.target.final_url).toBeNull();
  if (
    kind === "malformed-event" ||
    kind === "malformed-final" ||
    kind.startsWith("missing-")
  )
    expect(result.value.window.end_reason).toBe("window_elapsed");
  if (kind === "foreign-event")
    expect(result.value.completeness.excluded).toContainEqual({
      section: "timeline",
      reason: "out_of_target_scope",
      count: 1,
    });
  if (kind === "normal")
    expect(result.value.window.end_reason).toBe("window_elapsed");
});
it.each(
  [false, true].flatMap((foreign) =>
    [7, "bad-fragment"].map((urlFragment) => ({ foreign, urlFragment })),
  ),
)(
  "retains malformed committed identity and known scope: $foreign/$urlFragment",
  async ({ foreign, urlFragment }) => {
    const browser = await startFakeCdpBrowser({
      eventsBeforeReply: ["Page.setLifecycleEventsEnabled"],
      commandEvents: ({ method, sessionId }, origin) =>
        method === "Page.setLifecycleEventsEnabled"
          ? [
              {
                method: "Page.frameNavigated",
                ...(sessionId === undefined ? {} : { sessionId }),
                params: {
                  frame: {
                    id: "frame-main",
                    url: foreign ? "https://foreign.test/" : `${origin}/app`,
                    urlFragment,
                  },
                },
              },
            ]
          : undefined,
    });
    trackBrowser(browser);
    const result = await new CdpBrowserProvider().observeSession(
      observeWebSessionInputSchema.parse({
        cdp_endpoint: browser.endpoint,
        allowed_origins: [browser.allowedOrigin],
        target_id: "allowed-page",
        observation_ms: 1,
      }),
    );
    if (!result.ok) throw result.error;
    expect(result.value.completeness.excluded).toContainEqual({
      section: "timeline",
      reason: "invalid_protocol_value",
      count: 1,
    });
    expect(
      result.value.timeline.find(({ type }) => type === "navigation_committed"),
    ).toMatchObject({
      url: null,
      destination_scope: foreign ? "outside_policy" : "approved",
    });
    expect(result.value.window.end_reason).toBe(
      foreign ? "target_left_scope" : "window_elapsed",
    );
    if (foreign) {
      expect(result.value.target.final_url).toBeNull();
      expect(result.value.completeness.excluded).toContainEqual({
        section: "timeline",
        reason: "out_of_target_scope",
        count: 1,
      });
    } else
      expect(result.value.completeness.policy_filtered_sections).toEqual([]);
  },
);

it.each(
  [7, "bad-fragment"].flatMap((fragment) =>
    ["allowed", "foreign", "missing"].map((scope) => ({ fragment, scope })),
  ),
)(
  "retains final-probe identity and scope without an event: $scope/$fragment",
  async ({ fragment, scope }) => {
    const browser = await startFakeCdpBrowser({
      commandResult: ({ method }, origin, reads) =>
        method === "Page.getFrameTree" && reads > 1
          ? {
              frameTree: {
                frame: {
                  id: "frame-main",
                  ...(scope === "missing"
                    ? {}
                    : {
                        url:
                          scope === "foreign"
                            ? "https://foreign.test/"
                            : `${origin}/app`,
                      }),
                  urlFragment: fragment,
                },
              },
            }
          : undefined,
    });
    trackBrowser(browser);
    const result = await new CdpBrowserProvider().observeSession(
      observeWebSessionInputSchema.parse({
        cdp_endpoint: browser.endpoint,
        allowed_origins: [browser.allowedOrigin],
        target_id: "allowed-page",
        observation_ms: 1,
      }),
    );
    if (!result.ok) throw result.error;
    expect(result.value.target.final_url).toBeNull();
    expect(result.value.window.end_reason).toBe(
      scope === "foreign" ? "target_left_scope" : "window_elapsed",
    );
    expect(result.value.completeness.excluded).toContainEqual({
      section: "timeline",
      reason: "invalid_protocol_value",
      count: 1,
    });
    expect(
      result.value.completeness.policy_filtered_sections.includes("timeline"),
    ).toBe(scope === "foreign");
    if (scope === "foreign")
      expect(result.value.completeness.excluded).toContainEqual({
        section: "timeline",
        reason: "out_of_target_scope",
        count: 1,
      });
  },
);

describe("CdpBrowserProvider navigation timeline", () => {
  it.each(["outside_policy", "target_detached"] as const)(
    "settles and releases a long wait after %s",
    async (sessionTimeline) => {
      const browser = await startFakeCdpBrowser({ sessionTimeline });
      trackBrowser(browser);
      const result = await new CdpBrowserProvider().observeSession(
        observeWebSessionInputSchema.parse({
          cdp_endpoint: browser.endpoint,
          allowed_origins: [browser.allowedOrigin],
          target_id: "allowed-page",
          observation_ms: 3_000_000_000,
        }),
      );
      if (!result.ok) throw result.error;
      expect(result.value.window.end_reason).toBe(
        sessionTimeline === "outside_policy"
          ? "target_left_scope"
          : "target_terminated",
      );
    },
  );
  it.each([2_147_483_648, 3_000_000_000])(
    "keeps a long observation pending until cancellation: %s",
    async (observation_ms) => {
      const browser = await startFakeCdpBrowser();
      trackBrowser(browser);
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      let armed = false;
      try {
        const result = await new CdpBrowserProvider().observeSession(
          observeWebSessionInputSchema.parse({
            cdp_endpoint: browser.endpoint,
            allowed_origins: [browser.allowedOrigin],
            target_id: "allowed-page",
            observation_ms,
          }),
          {
            signal: controller.signal,
            progress: {
              report: async (update) => {
                if (
                  update.phase === "browser_observation" &&
                  update.completed === 1
                ) {
                  armed = true;
                  timer = setTimeout(() => controller.abort(), 150);
                }
              },
            },
          },
        );
        expect(result).toMatchObject({
          ok: false,
          error: { _tag: "AnalysisCancelledError" },
        });
        expect(armed).toBe(true);
      } finally {
        clearTimeout(timer);
      }
    },
  );
  it("returns every event beyond the former default collection cap", async () => {
    const additionalEvents = 2_001;
    const browser = await startFakeCdpBrowser({
      pageScopedVersionWebSocket: true,
      omitTargetWebSocket: true,
      sessionTimeline: "same_origin",
      sessionTimelineEventCount: additionalEvents,
    });
    trackBrowser(browser);

    const result = await new CdpBrowserProvider().observeSession(
      observeWebSessionInputSchema.parse({
        cdp_endpoint: browser.endpoint,
        allowed_origins: [browser.allowedOrigin],
        target_id: "allowed-page",
        observation_ms: 1,
      }),
    );

    if (!result.ok) throw result.error;
    expect(result.value.timeline).toHaveLength(additionalEvents + 6);
    expect(result.value.completeness.truncated_sections).not.toContain(
      "timeline",
    );
  });
});
