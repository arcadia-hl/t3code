import {
  AuthSessionId,
  AuthEnvironmentScopes,
  type IrohControlRequest,
  type IrohLocalAdminRequest,
} from "@t3tools/contracts";
import { invitationLink, SESSION_TTL_SECONDS } from "@t3tools/iroh/protocol";
import * as Context from "effect/Context";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import * as SessionStore from "../auth/SessionStore.ts";
import { openDeviceDatabase } from "./deviceDatabase.ts";

export class IrohPairingError extends Schema.TaggedError<IrohPairingError>()("IrohPairingError", {
  operation: Schema.Literals(["open", "challenge", "enroll", "renew", "admin"]),
  cause: Schema.Defect(),
}) {
  override get message(): string {
    return "Iroh pairing request failed. Check approval and invitation expiry on the host.";
  }
}

export class Pairing extends Context.Service<
  Pairing,
  {
    readonly control: (
      peerId: string,
      request: Exclude<IrohControlRequest, { operation: "http" }>,
    ) => Effect.Effect<unknown, IrohPairingError>;
    readonly admin: (request: IrohLocalAdminRequest) => Effect.Effect<unknown, IrohPairingError>;
  }
>()("t3/iroh/Pairing") {}

const decodeScopes = Schema.decodeUnknownEffect(AuthEnvironmentScopes);

export const layer = (options: {
  readonly path: string;
  readonly hostId: string;
  readonly environmentId: string;
  readonly relayHints: () => readonly string[];
  readonly disconnectDevice: (deviceId: string) => void;
}) =>
  Layer.effect(
    Pairing,
    Effect.gen(function* () {
      const sessions = yield* SessionStore.SessionStore;
      const database = yield* Effect.acquireRelease(
        Effect.try({
          try: () => openDeviceDatabase(options),
          catch: (cause) => new IrohPairingError({ operation: "open", cause }),
        }),
        (database) => Effect.sync(() => database.close()),
      );
      const attempt = <A>(operation: "challenge" | "enroll" | "renew" | "admin", action: () => A) =>
        Effect.try({ try: action, catch: (cause) => new IrohPairingError({ operation, cause }) });
      const control: Pairing["Service"]["control"] = Effect.fn("IrohPairing.control")(
        function* (peerId, request) {
          if (request.operation === "challenge") {
            const challenge = yield* attempt("challenge", () =>
              database.challenge(peerId, request.purpose),
            );
            return {
              version: 1,
              hostId: options.hostId,
              environmentId: options.environmentId,
              challenge,
            };
          }
          if (request.operation === "enroll")
            return yield* attempt("enroll", () => database.redeem({ ...request, peerId }));
          const grant = yield* attempt("renew", () => database.renew({ ...request, peerId }));
          const scopes = yield* decodeScopes(grant.scopes).pipe(
            Effect.mapError((cause) => new IrohPairingError({ operation: "renew", cause })),
          );
          return yield* Effect.acquireUseRelease(
            sessions
              .issue({
                subject: `iroh:${grant.deviceId}`,
                method: "dpop-access-token",
                scopes,
                proofKeyThumbprint: grant.thumbprint,
                ttl: Duration.seconds(SESSION_TTL_SECONDS),
              })
              .pipe(
                Effect.mapError((cause) => new IrohPairingError({ operation: "renew", cause })),
              ),
            (issued) =>
              Effect.gen(function* () {
                const attached = yield* attempt("renew", () =>
                  database.attachSession(
                    grant.deviceId,
                    issued.sessionId,
                    issued.expiresAt.epochMilliseconds,
                  ),
                );
                if (!attached)
                  return yield* new IrohPairingError({
                    operation: "renew",
                    cause: "device-removed",
                  });
                const ticket = yield* sessions
                  .issueWebSocketToken(issued.sessionId)
                  .pipe(
                    Effect.mapError((cause) => new IrohPairingError({ operation: "renew", cause })),
                  );
                return {
                  deviceId: grant.deviceId,
                  token: issued.token,
                  expiresAt: issued.expiresAt.epochMilliseconds,
                  wsTicket: ticket.token,
                  ticketExpiresAt: ticket.expiresAt.epochMilliseconds,
                  scopes,
                };
              }),
            (issued, exit) =>
              Exit.isFailure(exit)
                ? sessions.revoke(issued.sessionId).pipe(Effect.orDie)
                : Effect.void,
          );
        },
      );
      const admin: Pairing["Service"]["admin"] = Effect.fn("IrohPairing.admin")(
        function* (request) {
          if (request.operation === "devices")
            return yield* attempt("admin", () => database.devices());
          if (request.operation === "invite") {
            const invite = yield* attempt("admin", () => database.invite(request.scopes));
            return {
              link: invitationLink({
                ...invite,
                version: 1,
                hostId: options.hostId,
                environmentId: options.environmentId,
                relays: options.relayHints(),
              }),
            };
          }
          if (request.operation === "approve") {
            yield* attempt("admin", () => database.approve(request.deviceId, request.scopes));
            return { approved: true };
          }
          if (request.operation === "revoke-invitation")
            return yield* attempt("admin", () => database.revokeInvitation(request.invitationId));
          const revoked = yield* attempt("admin", () => database.revokeDevice(request.deviceId));
          // Persist removal first. Even if session invalidation fails, renewal stays denied.
          yield* Effect.sync(() => options.disconnectDevice(request.deviceId));
          for (const id of revoked)
            yield* sessions
              .revoke(AuthSessionId.make(id))
              .pipe(
                Effect.mapError((cause) => new IrohPairingError({ operation: "admin", cause })),
              );
          return { revokedSessions: revoked.length };
        },
      );
      return Pairing.of({ control, admin });
    }),
  );
