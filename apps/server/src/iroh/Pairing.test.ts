import * as NodeServices from "@effect/platform-node/NodeServices";
import { expect, it } from "@effect/vitest";
import { EnvironmentId } from "@t3tools/contracts";
import * as NodeCrypto from "node:crypto";
import * as NodePath from "node:path";
import * as NodeFS from "node:fs";
import { createDeviceProof, parseInvitation, publicDeviceKey } from "@t3tools/iroh/protocol";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import * as Fiber from "effect/Fiber";
import * as ServerConfig from "../config.ts";
import * as ServerSecretStore from "../auth/ServerSecretStore.ts";
import * as SessionStore from "../auth/SessionStore.ts";
import * as ServerEnvironment from "../environment/ServerEnvironment.ts";
import * as Sqlite from "../persistence/Sqlite.ts";
import * as Pairing from "./Pairing.ts";

const hostId = "a".repeat(64);
const environmentId = EnvironmentId.make("iroh-service-test");
const peerId = "b".repeat(64);
const scopes = ["orchestration:read"] as const;
const layer = Layer.unwrap(
  Effect.gen(function* () {
    const config = yield* ServerConfig.ServerConfig;
    // The fixture owns this directory; production refuses writable ancestors.
    NodeFS.chmodSync(config.stateDir, 0o700);
    return Pairing.layer({
      path: NodePath.join(config.stateDir, "iroh/devices.sqlite"),
      hostId,
      environmentId,
      relayHints: () => [],
      disconnectDevice: () => {},
    }).pipe(
      Layer.provideMerge(
        SessionStore.layer.pipe(
          Layer.provide(Sqlite.layerMemory),
          Layer.provide(ServerSecretStore.layer),
          Layer.provide(
            Layer.succeed(ServerEnvironment.ServerEnvironmentIdentity, {
              getEnvironmentId: Effect.succeed(environmentId),
            }),
          ),
        ),
      ),
    );
  }),
).pipe(Layer.provide(ServerConfig.layerTest(process.cwd(), { prefix: "t3-iroh-pairing-" })));
const challengeSchema = Schema.Struct({ challenge: Schema.String });
const pendingSchema = Schema.Struct({ deviceId: Schema.String, status: Schema.Literal("pending") });
const decodeInvite = Schema.decodeUnknownEffect(Schema.Struct({ link: Schema.String }));
const sessionSchema = Schema.Struct({
  token: Schema.String,
  expiresAt: Schema.Number,
  wsTicket: Schema.String,
  ticketExpiresAt: Schema.Number,
});

it.layer(NodeServices.layer)("accountless Iroh sessions", (it) => {
  it.effect(
    "requires approval, preserves scopes and proof binding, and revokes real session invalidation waiters",
    () =>
      Effect.gen(function* () {
        const pairing = yield* Pairing.Pairing;
        const sessions = yield* SessionStore.SessionStore;
        const keys = NodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
        const publicKey = publicDeviceKey(keys.publicKey.export({ format: "jwk" }));
        const raw = yield* pairing.admin({ operation: "invite", scopes });
        const invitation = parseInvitation((yield* decodeInvite(raw)).link);
        const nonce = (yield* pairing
          .control(peerId, { version: 1, operation: "challenge", purpose: "enroll" })
          .pipe(Effect.flatMap(Schema.decodeUnknownEffect(challengeSchema)))).challenge;
        const { createHash } = yield* Effect.promise(() => import("node:crypto"));
        const body = {
          invitationId: invitation.invitationId,
          verifier: createHash("sha256").update(invitation.secret).digest("hex"),
          publicKey,
          scopes,
        };
        const pending = yield* pairing
          .control(peerId, {
            version: 1,
            operation: "enroll",
            challenge: nonce,
            invitationId: invitation.invitationId,
            secret: invitation.secret,
            publicKey: publicKey as { kty: "EC"; crv: "P-256"; x: string; y: string },
            scopes,
            proof: createDeviceProof(keys.privateKey, {
              hostId,
              environmentId,
              operation: "enroll",
              challenge: nonce,
              body,
            }),
          })
          .pipe(Effect.flatMap(Schema.decodeUnknownEffect(pendingSchema)));
        const renew = Effect.gen(function* () {
          const challenge = (yield* pairing
            .control(peerId, { version: 1, operation: "challenge", purpose: "renew" })
            .pipe(Effect.flatMap(Schema.decodeUnknownEffect(challengeSchema)))).challenge;
          const body = { deviceId: pending.deviceId, scopes };
          return yield* pairing.control(peerId, {
            version: 1,
            operation: "renew",
            challenge,
            ...body,
            proof: createDeviceProof(keys.privateKey, {
              hostId,
              environmentId,
              operation: "renew",
              challenge,
              body,
            }),
          });
        });
        const denied = yield* renew.pipe(Effect.result);
        expect(denied._tag).toBe("Failure");
        yield* pairing.admin({ operation: "approve", deviceId: pending.deviceId, scopes });
        const issued = yield* renew.pipe(Effect.flatMap(Schema.decodeUnknownEffect(sessionSchema)));
        const session = yield* sessions.verify(issued.token);
        expect(session.scopes).toEqual(scopes);
        expect(session.proofKeyThumbprint !== undefined).toBe(true);
        const invalidated = yield* sessions
          .awaitInvalidation(session.sessionId)
          .pipe(Effect.forkChild);
        yield* pairing.admin({ operation: "revoke-device", deviceId: pending.deviceId });
        yield* Fiber.join(invalidated);
        expect((yield* sessions.verify(issued.token).pipe(Effect.result))._tag).toBe("Failure");
        expect((yield* renew.pipe(Effect.result))._tag).toBe("Failure");
      }).pipe(Effect.provide(layer)),
  );
});
