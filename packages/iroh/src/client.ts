import * as NodeCrypto from "node:crypto";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import { ensurePrivateDirectory, publishPrivateFile, readPrivateFile } from "./keys.ts";
import { bindEndpoint, peerAddress } from "./native.ts";
import {
  IROH_ALPN,
  createDeviceProof,
  logicalOrigin,
  parseInvitation,
  publicDeviceKey,
  validateRelayPolicy,
  type RelayPolicy,
} from "./protocol.ts";
import { assertPinnedHost, deadline, irohDuplex, readControl, writeControl } from "./transport.ts";
import { fixedHttpProxy, gatewayAccess, createDpopProof, listenGateway } from "./gateway.ts";
import type { Connection } from "./upstream.js";

interface DeviceProfile {
  readonly version: 1;
  readonly profileId: string;
  readonly hostId: string;
  readonly environmentId: string;
  readonly deviceId: string;
  readonly label: string;
  readonly scopes: readonly string[];
  readonly privateKey: NodeCrypto.JsonWebKey;
  readonly relayPolicy: RelayPolicy;
  readonly relays: readonly string[];
}
interface Session {
  readonly deviceId: string;
  readonly token: string;
  readonly expiresAt: number;
  readonly wsTicket: string;
  readonly ticketExpiresAt: number;
}
const record = (value: unknown): Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error("Invalid Iroh response.");
  return value as Record<string, unknown>;
};

export function readDeviceProfile(directory: string, profileId: string): DeviceProfile {
  if (!/^[a-f0-9-]{36}$/.test(profileId)) throw new Error("Invalid Iroh device profile.");
  const bytes = readPrivateFile(NodePath.join(directory, `${profileId}.json`), 16 * 1024);
  try {
    const data = record(JSON.parse(bytes.toString("utf8")));
    if (
      data.version !== 1 ||
      data.profileId !== profileId ||
      typeof data.hostId !== "string" ||
      !/^[a-f0-9]{64}$/.test(data.hostId) ||
      typeof data.environmentId !== "string" ||
      typeof data.deviceId !== "string" ||
      typeof data.label !== "string" ||
      data.label.length > 128 ||
      !Array.isArray(data.scopes) ||
      data.scopes.some((scope) => typeof scope !== "string") ||
      !Array.isArray(data.relays) ||
      data.relays.some((hint) => typeof hint !== "string")
    )
      throw new Error();
    const privateKey = record(data.privateKey) as NodeCrypto.JsonWebKey;
    NodeCrypto.createPrivateKey({ key: privateKey, format: "jwk" });
    const relayPolicy = record(data.relayPolicy) as unknown as RelayPolicy;
    validateRelayPolicy(relayPolicy, data.relays);
    return {
      version: 1,
      profileId,
      hostId: data.hostId,
      environmentId: data.environmentId,
      deviceId: data.deviceId,
      label: data.label,
      privateKey,
      relayPolicy,
      relays: data.relays,
      scopes: data.scopes,
    };
  } catch {
    throw new Error("Invalid Iroh device profile. Profile was not replaced.");
  } finally {
    bytes.fill(0);
  }
}

export function savedDevices(directory: string) {
  ensurePrivateDirectory(directory);
  return NodeFS.readdirSync(directory)
    .filter((name) => /^[a-f0-9-]{36}\.json$/.test(name))
    .map((name) => {
      const profile = readDeviceProfile(directory, name.slice(0, -5));
      return {
        profileId: profile.profileId,
        hostId: profile.hostId,
        environmentId: profile.environmentId,
        label: profile.label,
      };
    });
}

async function dial(
  hostId: string,
  relays: readonly string[],
  policy: RelayPolicy,
  signal?: AbortSignal,
) {
  validateRelayPolicy(policy, relays);
  const endpoint = await bindEndpoint({ policy });
  const abort = () => {
    void endpoint.close();
  };
  signal?.addEventListener("abort", abort, { once: true });
  try {
    if (signal?.aborted) throw new Error("Iroh connection cancelled.");
    const connection = await deadline(
      endpoint.connect(peerAddress(hostId, relays, policy), IROH_ALPN),
      15_000,
      abort,
    );
    assertPinnedHost(connection, hostId);
    const close = async () => {
      signal?.removeEventListener("abort", abort);
      connection.close(0n, []);
      await endpoint.close();
    };
    return { endpoint, connection, close };
  } catch (cause) {
    signal?.removeEventListener("abort", abort);
    await endpoint.close();
    throw new Error(
      "Iroh host unavailable or identity mismatch. Check relay policy and pinned identity.",
      { cause },
    );
  }
}

async function control(connection: Connection, request: unknown): Promise<Record<string, unknown>> {
  const stream = await connection.openBi();
  try {
    await writeControl(stream, request);
    await stream.send.finish();
    const frame = await deadline(readControl(stream), 10_000, () => connection.close(1n, []));
    const result = record(frame.value);
    if (result.ok !== true || frame.remainder.length)
      throw new Error("Iroh request rejected. Check device approval on the host.");
    return record(result.value);
  } finally {
    void stream.recv.stop(0n).catch(() => {});
  }
}

async function challenge(
  connection: Connection,
  hostId: string,
  environmentId: string,
  purpose: "enroll" | "renew",
) {
  const value = await control(connection, { version: 1, operation: "challenge", purpose });
  if (
    value.hostId !== hostId ||
    value.environmentId !== environmentId ||
    typeof value.challenge !== "string" ||
    !/^[\w-]{43}$/.test(value.challenge)
  )
    throw new Error("Iroh environment identity mismatch.");
  return value.challenge;
}

export async function enrollDevice(input: {
  readonly link: string;
  readonly directory: string;
  readonly scopes: readonly string[];
  readonly relayPolicy: RelayPolicy;
  readonly signal?: AbortSignal;
}) {
  const invitation = parseInvitation(input.link);
  validateRelayPolicy(input.relayPolicy, invitation.relays);
  const keys = NodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = publicDeviceKey(keys.publicKey.export({ format: "jwk" }));
  const client = await dial(invitation.hostId, invitation.relays, input.relayPolicy, input.signal);
  try {
    // Both the QUIC pin and the environment challenge are checked before sending the secret.
    const nonce = await challenge(
      client.connection,
      invitation.hostId,
      invitation.environmentId,
      "enroll",
    );
    const body = {
      invitationId: invitation.invitationId,
      verifier: NodeCrypto.createHash("sha256").update(invitation.secret).digest("hex"),
      publicKey,
      scopes: input.scopes,
    };
    const proof = createDeviceProof(keys.privateKey, {
      hostId: invitation.hostId,
      environmentId: invitation.environmentId,
      operation: "enroll",
      challenge: nonce,
      body,
    });
    const result = await control(client.connection, {
      version: 1,
      operation: "enroll",
      challenge: nonce,
      invitationId: invitation.invitationId,
      secret: invitation.secret,
      publicKey,
      scopes: input.scopes,
      proof,
    });
    if (
      result.status !== "pending" ||
      typeof result.deviceId !== "string" ||
      !/^[a-f0-9-]{36}$/.test(result.deviceId)
    )
      throw new Error("Invalid enrollment response.");
    ensurePrivateDirectory(input.directory);
    const profileId = NodeCrypto.randomUUID();
    const profile: DeviceProfile = {
      version: 1,
      profileId,
      hostId: invitation.hostId,
      environmentId: invitation.environmentId,
      deviceId: result.deviceId,
      label: "Iroh environment",
      scopes: input.scopes,
      privateKey: keys.privateKey.export({ format: "jwk" }),
      relayPolicy: input.relayPolicy,
      relays: invitation.relays,
    };
    const bytes = Buffer.from(JSON.stringify(profile));
    try {
      publishPrivateFile(NodePath.join(input.directory, `${profileId}.json`), bytes);
    } finally {
      bytes.fill(0);
    }
    return { profileId, deviceId: result.deviceId, status: "pending" as const };
  } finally {
    await client.close();
  }
}

export async function openClientGateway(input: {
  readonly directory: string;
  readonly profileId: string;
  readonly expectedHostId: string;
  readonly expectedEnvironmentId: string;
  readonly allowedOrigin: string;
  readonly signal?: AbortSignal;
}) {
  const profile = readDeviceProfile(input.directory, input.profileId);
  if (
    profile.hostId !== input.expectedHostId ||
    profile.environmentId !== input.expectedEnvironmentId
  )
    throw new Error("Iroh profile identity mismatch.");
  const key = NodeCrypto.createPrivateKey({ key: profile.privateKey, format: "jwk" });
  const publicKey = publicDeviceKey(NodeCrypto.createPublicKey(key).export({ format: "jwk" }));
  const client = await dial(profile.hostId, profile.relays, profile.relayPolicy, input.signal);
  const origin = logicalOrigin(profile.hostId);
  let session: Session | undefined;
  let renewing: Promise<Session> | undefined;
  const getSession = async (): Promise<Session> => {
    if (session && Math.min(session.expiresAt, session.ticketExpiresAt) > Date.now() + 60_000)
      return session;
    if (renewing) return renewing;
    renewing = (async () => {
      const nonce = await challenge(
        client.connection,
        profile.hostId,
        profile.environmentId,
        "renew",
      );
      const body = { deviceId: profile.deviceId, scopes: profile.scopes };
      const proof = createDeviceProof(key, {
        hostId: profile.hostId,
        environmentId: profile.environmentId,
        operation: "renew",
        challenge: nonce,
        body,
      });
      const value = await control(client.connection, {
        version: 1,
        operation: "renew",
        challenge: nonce,
        ...body,
        proof,
      });
      if (
        value.deviceId !== profile.deviceId ||
        typeof value.token !== "string" ||
        value.token.length > 8192 ||
        typeof value.expiresAt !== "number" ||
        typeof value.ticketExpiresAt !== "number" ||
        typeof value.wsTicket !== "string" ||
        value.wsTicket.length > 8192
      )
        throw new Error("Invalid Iroh session response.");
      return (session = {
        deviceId: profile.deviceId,
        token: value.token,
        expiresAt: value.expiresAt,
        wsTicket: value.wsTicket,
        ticketExpiresAt: value.ticketExpiresAt,
      });
    })();
    try {
      return await renewing;
    } finally {
      renewing = undefined;
    }
  };
  const token = NodeCrypto.randomBytes(32).toString("base64url");
  let host = "unbound";
  const gateway = fixedHttpProxy({
    logicalHost: new URL(origin).host,
    allowedOrigin: input.allowedOrigin,
    access: (request) =>
      gatewayAccess(request.headers, request.url ?? "/", {
        host,
        token,
        allowedOrigin: input.allowedOrigin,
      }),
    open: async () => {
      const stream = await client.connection.openBi();
      await writeControl(stream, { version: 1, operation: "http" });
      return irohDuplex(stream);
    },
    authorize: async (method, path, headers, upgrade) => {
      const current = await getSession();
      const url = new URL(path, origin);
      url.searchParams.delete("gatewayToken");
      if (upgrade || url.searchParams.has("wsTicket"))
        url.searchParams.set("wsTicket", current.wsTicket);
      headers.authorization = `DPoP ${current.token}`;
      headers.dpop = createDpopProof(key, publicKey, method, url.href, current.token);
      return { path: `${url.pathname}${url.search}`, headers };
    },
  });
  let closing: Promise<void> | undefined;
  const close = (): Promise<void> =>
    (closing ??= (async () => {
      client.connection.close(0n, []);
      gateway.closeAllConnections();
      await Promise.all([
        new Promise<void>((resolve) => gateway.close(() => resolve())),
        client.close(),
      ]);
    })());
  try {
    await getSession();
    const bound = await listenGateway(gateway, token);
    if (input.signal?.aborted) throw new Error("Gateway acquisition cancelled.");
    host = new URL(bound.httpBaseUrl).host;
    const socket = new URL("/ws", bound.httpBaseUrl);
    socket.protocol = "ws:";
    socket.searchParams.set("gatewayToken", token);
    return {
      ...bound,
      socketUrl: socket.href,
      close,
      transportStatus: () => ({
        relayOnly: profile.relayPolicy.relayOnly === true,
        selectedPaths: client.connection
          .paths()
          .filter((path) => path.isSelected)
          .map((path) => ({ isRelay: path.isRelay, isIp: path.isIp })),
      }),
    };
  } catch {
    await close();
    throw new Error("Iroh gateway unavailable. Check host approval and connectivity.");
  }
}
