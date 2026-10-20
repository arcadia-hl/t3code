import {
  IrohEnrollmentInput,
  IrohEnrollmentResult,
  IrohGatewayOpen,
  IrohGatewayLease,
  IrohSavedDevice,
} from "@t3tools/contracts";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Schema from "effect/Schema";
import * as DesktopIpc from "../DesktopIpc.ts";
import * as Channels from "../channels.ts";
import * as DesktopIroh from "../../iroh/DesktopIroh.ts";
import * as ElectronWindow from "../../electron/ElectronWindow.ts";
import * as DesktopEnvironment from "../../app/DesktopEnvironment.ts";

class IrohSenderError extends Schema.TaggedError<IrohSenderError>()("IrohSenderError", {}) {
  override get message(): string {
    return "Iroh gateway request rejected.";
  }
}
const sender = Effect.fn("desktop.ipc.iroh.sender")(function* (
  event: DesktopIpc.DesktopIpcInvokeEvent | undefined,
) {
  const main = yield* (yield* ElectronWindow.ElectronWindow).main;
  const environment = yield* DesktopEnvironment.DesktopEnvironment;
  if (
    !event ||
    Option.isNone(main) ||
    main.value.isDestroyed() ||
    main.value.webContents.id !== event.sender.id ||
    !event.senderFrame ||
    event.senderFrame.parent !== null ||
    event.senderFrame.url !== main.value.webContents.getURL()
  )
    return yield* new IrohSenderError();
  const url = new URL(main.value.webContents.getURL());
  const origin = url.origin === "null" ? `${url.protocol}//${url.host}` : url.origin;
  const devOrigin = Option.getOrUndefined(environment.devServerUrl)?.origin;
  if (origin !== "t3code://app" && origin !== "t3code-dev://app" && origin !== devOrigin)
    return yield* new IrohSenderError();
  return { window: main.value, origin, ownerId: event.sender.id };
});
export const devices = DesktopIpc.makeIpcMethod({
  channel: Channels.IROH_DEVICES_CHANNEL,
  payload: Schema.Undefined,
  result: Schema.Array(IrohSavedDevice),
  handler: Effect.fn("desktop.ipc.iroh.devices")(function* (_input, event) {
    yield* sender(event);
    return yield* (yield* DesktopIroh.DesktopIroh).devices;
  }),
});
export const open = DesktopIpc.makeIpcMethod({
  channel: Channels.IROH_OPEN_CHANNEL,
  payload: IrohGatewayOpen,
  result: IrohGatewayLease,
  handler: Effect.fn("desktop.ipc.iroh.open")(function* (input, event) {
    const owner = yield* sender(event);
    const native = yield* DesktopIroh.DesktopIroh;
    yield* native.observeOwner(owner.ownerId, (destroy) => {
      const contents = owner.window.webContents;
      contents.once("destroyed", destroy);
      if (contents.isDestroyed()) destroy();
      return () => {
        contents.removeListener("destroyed", destroy);
      };
    });
    return yield* native.open(input, owner.ownerId, owner.origin);
  }),
});
export const close = DesktopIpc.makeIpcMethod({
  channel: Channels.IROH_CLOSE_CHANNEL,
  payload: Schema.String,
  result: Schema.Void,
  handler: Effect.fn("desktop.ipc.iroh.close")(function* (leaseId, event) {
    const owner = yield* sender(event);
    yield* (yield* DesktopIroh.DesktopIroh).close(leaseId, owner.ownerId);
  }),
});

export const enroll = DesktopIpc.makeIpcMethod({
  channel: Channels.IROH_ENROLL_CHANNEL,
  payload: IrohEnrollmentInput,
  result: IrohEnrollmentResult,
  handler: Effect.fn("desktop.ipc.iroh.enroll")(function* (input, event) {
    yield* sender(event);
    return yield* (yield* DesktopIroh.DesktopIroh).enroll(input);
  }),
});
export const forget = DesktopIpc.makeIpcMethod({
  channel: Channels.IROH_FORGET_CHANNEL,
  payload: IrohSavedDevice.fields.profileId,
  result: Schema.Void,
  handler: Effect.fn("desktop.ipc.iroh.forget")(function* (id, event) {
    yield* sender(event);
    yield* (yield* DesktopIroh.DesktopIroh).forget(id);
  }),
});
