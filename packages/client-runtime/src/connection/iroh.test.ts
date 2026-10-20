import { describe, expect, it } from "vite-plus/test";
import * as Option from "effect/Option";
import { EnvironmentId } from "@t3tools/contracts";
import {
  BearerConnectionProfile,
  IrohConnectionRegistration,
  connectionRegistrationCatalogEntry,
} from "./catalog.ts";
import { BearerConnectionTarget } from "./model.ts";
import {
  connectionRouteKind,
  connectionRouteLabel,
  mergeLearnedRoutes,
  routeHttpBaseUrl,
} from "./routes.ts";

describe("Iroh route identity", () => {
  it("keeps the environment and pinned peer separate from ephemeral gateway origins and direct routes", () => {
    const environmentId = EnvironmentId.make("iroh-environment");
    const profile = new BearerConnectionProfile({
      connectionId: "iroh:device-1",
      environmentId,
      label: "remote",
      httpBaseUrl: "http://pinned.iroh.invalid",
      wsBaseUrl: "ws://pinned.iroh.invalid",
      iroh: { profileId: "device-1", hostId: "a".repeat(64) },
    });
    const registration = new IrohConnectionRegistration({
      target: new BearerConnectionTarget({
        environmentId,
        label: "remote",
        connectionId: profile.connectionId,
      }),
      profile,
    });
    const entry = connectionRegistrationCatalogEntry(registration);
    expect(connectionRouteKind(entry)).toBe("iroh");
    expect(connectionRouteLabel(entry)).toBe("Iroh");
    expect(routeHttpBaseUrl(entry)).toBeNull();
    expect(
      mergeLearnedRoutes({ entry, activeRoute: entry, reported: [], allowInsecure: true }),
    ).toBeNull();
    expect(Option.getOrThrow(entry.profile).environmentId).toBe(environmentId);
  });
});
