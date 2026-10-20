// @effect-diagnostics nodeBuiltinImport:off -- Native QUIC streams attach to the Node HTTP parser and private Unix admin socket.
// Application boundary: native/Node callbacks run domain Effects in the server-owned context.
import * as NodeHttp from "node:http";
import * as NodeNet from "node:net";
import * as NodePath from "node:path";
import * as NodeFS from "node:fs";
import { IrohControlRequest, IrohLocalAdminRequest } from "@t3tools/contracts";
import { bindEndpoint } from "@t3tools/iroh/native";
import { fixedHttpProxy, httpSocket } from "@t3tools/iroh/gateway";
import { readPrivateFile } from "@t3tools/iroh/keys";
import { IROH_ALPN, MAX_STREAMS, logicalOrigin, validateRelayPolicy } from "@t3tools/iroh/protocol";
import { deadline, irohDuplex, readControl, writeControl } from "@t3tools/iroh/transport";
import type { Connection } from "../../../../packages/iroh/src/upstream.js";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Schema from "effect/Schema";
import * as HttpServer from "effect/http/HttpServer";
import * as ServerConfig from "../config.ts";
import * as ServerEnvironment from "../environment/ServerEnvironment.ts";
import * as Pairing from "./Pairing.ts";
import { TransportAdmission } from "./admission.ts";
import * as HostKeyStore from "./HostKeyStore.ts";

export class IrohStartupError extends Schema.TaggedError<IrohStartupError>()("IrohStartupError", {
  stage: Schema.Literals(["config", "bind", "listen"]),
  cause: Schema.Defect(),
}) {
  override get message(): string {
    return "Iroh startup failed; transport remains unavailable. Check the native build, relay policy and identity permissions.";
  }
}

const HostConfig = Schema.Struct({
  enabled: Schema.Literal(true),
  relay: Schema.Struct({
    relayOnly: Schema.optionalKey(Schema.Boolean),
    mode: Schema.Literals(["automatic", "custom", "private-only"]),
    relays: Schema.optionalKey(
      Schema.Array(
        Schema.Struct({ url: Schema.String, authToken: Schema.optionalKey(Schema.String) }),
      ),
    ),
  }),
  systemdCredentialPath: Schema.optionalKey(Schema.String),
});

const decodeHostConfig = Schema.decodeUnknownEffect(Schema.fromJsonString(HostConfig));
const decodeAdmin = Schema.decodeUnknownEffect(Schema.fromJsonString(IrohLocalAdminRequest));
const decodeControl = Schema.decodeUnknownEffect(IrohControlRequest);

export const layer = Layer.unwrap(
  Effect.gen(function* () {
    const config = yield* ServerConfig.ServerConfig;
    const directory = NodePath.join(config.stateDir, "iroh");
    const path = NodePath.join(directory, "host.json");
    const configured = yield* Effect.try({
      try: () => {
        try {
          NodeFS.lstatSync(path);
        } catch (error) {
          if (error instanceof Error && "code" in error && error.code === "ENOENT")
            return undefined;
          throw error;
        }
        return readPrivateFile(path, 16 * 1024).toString("utf8");
      },
      catch: (cause) => new IrohStartupError({ stage: "config", cause }),
    });
    if (configured === undefined) return Layer.empty;
    const settings = yield* decodeHostConfig(configured).pipe(
      Effect.mapError((cause) => new IrohStartupError({ stage: "config", cause })),
    );
    yield* Effect.try({
      try: () => validateRelayPolicy(settings.relay),
      catch: (cause) => new IrohStartupError({ stage: "config", cause }),
    });
    const identity = yield* ServerEnvironment.ServerEnvironmentIdentity;
    const environmentId = yield* identity.getEnvironmentId;
    const backend =
      settings.systemdCredentialPath === undefined
        ? {
            kind: "file" as const,
            directory: NodePath.join(directory, "identity"),
            allowCreate: !NodeFS.existsSync(NodePath.join(directory, "devices.sqlite")),
          }
        : { kind: "systemd-credential" as const, path: settings.systemdCredentialPath };
    const keyStore = yield* HostKeyStore.HostKeyStore.pipe(
      Effect.provide(HostKeyStore.layer(backend)),
    );
    const seed = yield* keyStore.load;
    const endpoint = yield* Effect.acquireRelease(
      Effect.tryPromise({
        try: () => bindEndpoint({ seed, policy: settings.relay }),
        catch: (cause) => new IrohStartupError({ stage: "bind", cause }),
      }).pipe(Effect.ensuring(Effect.sync(() => seed.fill(0)))),
      (endpoint) => Effect.promise(() => endpoint.close()),
    );
    // Invitations need a usable rendezvous hint; publishing before relay bootstrap
    // makes first enrollment depend on public DNS publication winning a race.
    yield* Effect.tryPromise({
      try: () =>
        deadline(endpoint.online(), 20_000, () => {
          void endpoint.close();
        }),
      catch: (cause) => new IrohStartupError({ stage: "bind", cause }),
    });
    const http = yield* HttpServer.HttpServer;
    const address = http.address;
    if (typeof address === "string" || !("port" in address))
      return yield* new IrohStartupError({ stage: "bind", cause: "no-fixed-http-port" });
    const hostId = endpoint.id().toString();
    const admission = new TransportAdmission<Connection>();
    const connections = admission.connections;
    const proxy = fixedHttpProxy({
      logicalHost: new URL(logicalOrigin(hostId)).host,
      open: async () => NodeNet.connect({ host: "127.0.0.1", port: address.port }),
      access: (request) => request.headers.host === new URL(logicalOrigin(hostId)).host,
    });
    yield* Effect.addFinalizer(() =>
      Effect.sync(() => {
        for (const connection of connections.keys()) connection.close(0n, []);
        proxy.close();
      }),
    );
    const serve = Effect.gen(function* () {
      const pairing = yield* Pairing.Pairing;
      const context = yield* Effect.context<Pairing.Pairing>();
      const run = Effect.runPromiseWith(context);
      const admin = NodeHttp.createServer(
        { maxHeaderSize: 4096, headersTimeout: 5000, requestTimeout: 5000 },
        (request, response) => {
          if (request.method !== "POST" || request.url !== "/") {
            response.writeHead(404);
            response.end();
            return;
          }
          const chunks: Buffer[] = [];
          let length = 0;
          request.on("data", (chunk: Buffer) => {
            length += chunk.length;
            if (length > 16 * 1024) request.destroy();
            else chunks.push(chunk);
          });
          request.once("end", () => {
            const effect = decodeAdmin(Buffer.concat(chunks).toString("utf8")).pipe(
              Effect.flatMap(pairing.admin),
              Effect.match({
                onFailure: () => ({ ok: false }),
                onSuccess: (value) => ({ ok: true, value }),
              }),
            );
            void run(effect).then(
              (result) => {
                response.setHeader("content-type", "application/json");
                response.end(JSON.stringify(result));
              },
              () => {
                response.writeHead(500);
                response.end();
              },
            );
          });
        },
      );
      const socket = NodePath.join(directory, "admin.sock");
      yield* Effect.acquireRelease(
        Effect.tryPromise({
          try: () =>
            new Promise<void>((resolve, reject) => {
              admin.once("error", reject);
              admin.listen(socket, () => {
                admin.removeListener("error", reject);
                NodeFS.chmodSync(socket, 0o600);
                resolve();
              });
            }),
          catch: (cause) => new IrohStartupError({ stage: "listen", cause }),
        }),
        () =>
          Effect.promise(
            () =>
              new Promise<void>((resolve) => {
                admin.closeAllConnections();
                admin.close(() => resolve());
              }),
          ),
      );
      const accept = async () => {
        while (!endpoint.isClosed()) {
          const incoming = await endpoint.acceptNext();
          if (incoming === null) return;
          const release = admission.handshake();
          if (!release) {
            await incoming.refuse();
            continue;
          }
          let expired = false;
          const pending = incoming.accept().then((connecting) => connecting.connect());
          // A timeout cannot cancel Connecting in this binding. Hold the slot until
          // it settles and close a late result instead of publishing it.
          void deadline(pending, 10_000, () => {
            expired = true;
          }).catch(() => {});
          void pending
            .then(
              (connection) => {
                if (
                  expired ||
                  endpoint.isClosed() ||
                  !Buffer.from(connection.alpn()).equals(Buffer.from(IROH_ALPN))
                ) {
                  connection.close(1n, []);
                  return;
                }
                if (!admission.accept(connection)) return;
                connection.setMaxConcurrentBiStreams(BigInt(MAX_STREAMS));
                connection.setMaxConcurrentUniStreams(0n);
                connection.setReceiveWindow(1024n * 1024n);
                void connection.closed().then(
                  () => admission.remove(connection),
                  () => admission.remove(connection),
                );
                void serveConnection(connection).catch(() => connection.close(1n, []));
              },
              () => {},
            )
            .finally(release);
        }
      };
      const serveConnection = async (connection: Connection) => {
        while (true) {
          const stream = await connection.acceptBi();
          const release = admission.control();
          if (!release) {
            connection.close(1n, []);
            return;
          }
          void deadline(readControl(stream), 10_000, () => connection.close(1n, []))
            .then(async (frame) => {
              const request = await run(decodeControl(frame.value));
              if (request.operation === "http") {
                if (!admission.device(connection)) throw new Error("Device not approved.");
                proxy.emit("connection", httpSocket(irohDuplex(stream, frame.remainder)));
                return;
              }
              if (frame.remainder.length) throw new Error("Unexpected control bytes.");
              const value = await run(pairing.control(connection.remoteId().toString(), request));
              if (
                request.operation === "renew" &&
                typeof value === "object" &&
                value !== null &&
                "deviceId" in value &&
                typeof value.deviceId === "string"
              )
                admission.authorize(connection, value.deviceId);
              await writeControl(stream, { ok: true, value });
              await stream.send.finish();
            })
            .catch(async () => {
              try {
                await writeControl(stream, { ok: false });
                await stream.send.finish();
              } catch {}
              await stream.recv.stop(1n).catch(() => {});
            })
            .finally(release);
        }
      };
      yield* Effect.acquireRelease(
        Effect.sync(() => {
          void accept().catch(() => {});
        }),
        () => Effect.promise(() => endpoint.close()),
      );
      yield* Effect.logInfo("Iroh Linux transport enabled", {
        backend: keyStore.status.backend,
        hardwareSigning: false,
      });
    });
    return Layer.effectDiscard(serve).pipe(
      Layer.provide(
        Pairing.layer({
          path: NodePath.join(directory, "devices.sqlite"),
          hostId,
          environmentId,
          relayHints: () =>
            settings.relay.relays?.map((relay) => relay.url) ??
            (endpoint.addr().relayUrl() ? [endpoint.addr().relayUrl()!] : []),
          disconnectDevice: (deviceId) => admission.revoke(deviceId),
        }),
      ),
    );
  }),
);
