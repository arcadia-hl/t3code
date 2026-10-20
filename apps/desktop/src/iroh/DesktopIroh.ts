import { GatewayOwners } from "./gatewayOwners.ts";
import { openClientGateway, savedDevices } from "@t3tools/iroh/client";
import { IrohSavedDevice, type IrohGatewayOpen, type IrohGatewayLease } from "@t3tools/contracts";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import * as DesktopEnvironment from "../app/DesktopEnvironment.ts";

export class DesktopIrohError extends Schema.TaggedError<DesktopIrohError>()("DesktopIrohError", {
  operation: Schema.Literals(["list", "open", "close"]),
  cause: Schema.Defect(),
}) {
  override get message(): string {
    return "Iroh native gateway failed. Check the Linux binding, saved device approval and connectivity.";
  }
}

export class DesktopIroh extends Context.Service<
  DesktopIroh,
  {
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
  const owners = new GatewayOwners();
  yield* Effect.addFinalizer(() => Effect.promise(() => owners.shutdown()));
  const observeOwner: DesktopIroh["Service"]["observeOwner"] = (ownerId, subscribe) =>
    Effect.try({
      try: () => owners.observe(ownerId, subscribe),
      catch: (cause) => new DesktopIrohError({ operation: "open", cause }),
    });
  const devices =
    environment.platform !== "linux"
      ? Effect.succeed([])
      : Effect.try({
          try: () => savedDevices(directory),
          catch: (cause) => new DesktopIrohError({ operation: "list", cause }),
        }).pipe(
          Effect.flatMap(Schema.decodeUnknownEffect(Schema.Array(IrohSavedDevice))),
          Effect.mapError((cause) => new DesktopIrohError({ operation: "list", cause })),
        );
  const open: DesktopIroh["Service"]["open"] = Effect.fn("DesktopIroh.open")(
    function* (input, ownerId, allowedOrigin) {
      if (environment.platform !== "linux")
        return yield* new DesktopIrohError({ operation: "open", cause: "unsupported-platform" });
      return yield* Effect.tryPromise({
        try: async (signal) => {
          const { id, gateway } = await owners.open(ownerId, () =>
            openClientGateway({
              directory,
              profileId: input.profileId,
              expectedHostId: input.hostId,
              expectedEnvironmentId: input.environmentId,
              allowedOrigin,
              signal,
            }),
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
  return DesktopIroh.of({ devices, open, close, closeOwner, observeOwner });
});
export const layer = Layer.effect(DesktopIroh, make);
