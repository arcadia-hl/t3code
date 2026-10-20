import { GatewayOwners } from "./gatewayOwners.ts";
import {
  openClientGateway,
  fileProfileStore,
  enrollDevice,
  type DeviceProfileStore,
} from "@t3tools/iroh/client";
import {
  AuthStandardClientScopes,
  type IrohEnrollmentInput,
  type IrohEnrollmentResult,
  IrohSavedDevice,
  type IrohGatewayOpen,
  type IrohGatewayLease,
} from "@t3tools/contracts";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import { encryptedProfileStore } from "./encryptedProfiles.ts";
import * as ElectronSafeStorage from "../electron/ElectronSafeStorage.ts";
import * as DesktopEnvironment from "../app/DesktopEnvironment.ts";

export class DesktopIrohError extends Schema.TaggedError<DesktopIrohError>()("DesktopIrohError", {
  operation: Schema.Literals(["list", "open", "close", "enroll", "forget"]),
  cause: Schema.Defect(),
}) {
  override get message(): string {
    return "Iroh native gateway failed. Check the native binding, protected storage, device approval and connectivity.";
  }
}

export class DesktopIroh extends Context.Service<
  DesktopIroh,
  {
    readonly enroll: (
      input: IrohEnrollmentInput,
    ) => Effect.Effect<IrohEnrollmentResult, DesktopIrohError>;
    readonly forget: (profileId: string) => Effect.Effect<void, DesktopIrohError>;
    readonly devices: Effect.Effect<readonly IrohSavedDevice[], DesktopIrohError>;
    readonly open: (
      input: IrohGatewayOpen,
      ownerId: number,
      allowedOrigin: string,
    ) => Effect.Effect<IrohGatewayLease, DesktopIrohError>;
    readonly close: (leaseId: string, ownerId: number) => Effect.Effect<void, DesktopIrohError>;
    readonly observeOwner: (
      ownerId: number,
      subscribe: (destroy: () => void) => () => void,
    ) => Effect.Effect<void, DesktopIrohError>;
    readonly closeOwner: (ownerId: number) => Effect.Effect<void>;
  }
>()("@t3tools/desktop/iroh/DesktopIroh") {}

const make = Effect.gen(function* () {
  const environment = yield* DesktopEnvironment.DesktopEnvironment;
  const directory = environment.path.join(environment.stateDir, "iroh-client");
  const supported = environment.platform === "linux" || environment.platform === "win32";
  let store: DeviceProfileStore = fileProfileStore(directory);
  if (environment.platform === "win32") {
    const safe = yield* ElectronSafeStorage.ElectronSafeStorage;
    const run = Effect.runPromiseWith(yield* Effect.context<never>());
    store = encryptedProfileStore({
      directory,
      privateRoot: environment.homeDirectory,
      crypto: {
        available: () => run(safe.isEncryptionAvailable),
        encrypt: (text) => run(safe.encryptString(text)),
        decrypt: (bytes) => run(safe.decryptString(bytes)),
      },
    });
  }
  const owners = new GatewayOwners();
  yield* Effect.addFinalizer(() => Effect.promise(() => owners.shutdown()));
  const observeOwner: DesktopIroh["Service"]["observeOwner"] = (ownerId, subscribe) =>
    Effect.try({
      try: () => owners.observe(ownerId, subscribe),
      catch: (cause) => new DesktopIrohError({ operation: "open", cause }),
    });
  const devices = !supported
    ? Effect.succeed([])
    : Effect.tryPromise({
        try: () => store.list(),
        catch: (cause) => new DesktopIrohError({ operation: "list", cause }),
      }).pipe(
        Effect.flatMap(Schema.decodeUnknownEffect(Schema.Array(IrohSavedDevice))),
        Effect.mapError((cause) => new DesktopIrohError({ operation: "list", cause })),
      );
  const open: DesktopIroh["Service"]["open"] = Effect.fn("DesktopIroh.open")(
    function* (input, ownerId, allowedOrigin) {
      if (!supported)
        return yield* new DesktopIrohError({ operation: "open", cause: "unsupported-platform" });
      return yield* Effect.tryPromise({
        try: async (signal) => {
          const { id, gateway } = await owners.open(
            ownerId,
            () =>
              openClientGateway({
                directory,
                store,
                profileId: input.profileId,
                expectedHostId: input.hostId,
                expectedEnvironmentId: input.environmentId,
                allowedOrigin,
                signal,
              }),
            input.profileId,
          );
          return {
            leaseId: id,
            httpBaseUrl: gateway.httpBaseUrl,
            socketUrl: gateway.socketUrl,
            gatewayToken: gateway.gatewayToken,
          };
        },
        catch: (cause) => new DesktopIrohError({ operation: "open", cause }),
      });
    },
  );
  const close: DesktopIroh["Service"]["close"] = (leaseId, ownerId) =>
    Effect.tryPromise({
      try: () => owners.close(leaseId, ownerId),
      catch: (cause) => new DesktopIrohError({ operation: "close", cause }),
    });
  const closeOwner: DesktopIroh["Service"]["closeOwner"] = (ownerId) =>
    Effect.promise(() => owners.closeOwner(ownerId));
  let enrolling = 0;
  const enroll: DesktopIroh["Service"]["enroll"] = (input) =>
    Effect.tryPromise({
      try: async (signal) => {
        if (!supported || enrolling >= 4)
          throw new Error("Iroh enrollment unavailable or capacity reached.");
        enrolling++;
        try {
          await store.list();
          return await enrollDevice({
            link: input.link,
            directory,
            store,
            signal,
            scopes: input.control
              ? [...AuthStandardClientScopes]
              : ["orchestration:read", "filesystem:read", "terminal:read"],
            relayPolicy: { mode: "automatic" },
          });
        } finally {
          enrolling--;
        }
      },
      catch: (cause) => new DesktopIrohError({ operation: "enroll", cause }),
    });
  const forget: DesktopIroh["Service"]["forget"] = (profileId) =>
    Effect.tryPromise({
      try: async () => {
        await owners.closeKey(profileId);
        await store.forget(profileId);
      },
      catch: (cause) => new DesktopIrohError({ operation: "forget", cause }),
    });
  return DesktopIroh.of({ devices, open, close, closeOwner, observeOwner, enroll, forget });
});
export const layer = Layer.effect(DesktopIroh, make);
