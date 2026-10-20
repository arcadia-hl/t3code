import * as NodeCrypto from "node:crypto";

export const IROH_ALPN = Array.from(Buffer.from("t3/iroh/http/1"));
export const MAX_CONTROL_BYTES = 16 * 1024;
export const MAX_STREAMS = 32;
export const SESSION_TTL_SECONDS = 15 * 60;
export const INVITATION_TTL_MS = 5 * 60_000;

export interface Invitation {
  readonly version: 1;
  readonly environmentId: string;
  readonly hostId: string;
  readonly invitationId: string;
  readonly secret: string;
  readonly expiresAt: number;
  readonly relays: readonly string[];
}

export interface RelayPolicy {
  readonly relayOnly?: boolean;
  readonly mode: "automatic" | "custom" | "private-only";
  readonly relays?: readonly { readonly url: string; readonly authToken?: string }[];
}

function relayUrl(value: string): string {
  if (value.length > 2048) throw new Error("Invalid relay policy.");
  const url = new URL(value);
  if (
    url.protocol !== "https:" ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/"
  )
    throw new Error("Invalid relay policy.");
  return url.href;
}

export function validateRelayPolicy(
  policy: RelayPolicy,
  hints: readonly string[] = [],
): RelayPolicy {
  try {
    if (!["automatic", "custom", "private-only"].includes(policy.mode)) throw new Error();
    if (policy.relayOnly !== undefined && typeof policy.relayOnly !== "boolean") throw new Error();
    const relays = policy.relays ?? [];
    if (
      relays.length > 8 ||
      hints.length > 8 ||
      (policy.mode !== "automatic" && relays.length === 0)
    )
      throw new Error();
    const allowed = new Set(relays.map((relay) => relayUrl(relay.url)));
    if (
      relays.some(
        (relay) =>
          relay.authToken !== undefined &&
          (typeof relay.authToken !== "string" || relay.authToken.length > 4096),
      )
    )
      throw new Error();
    for (const hint of hints) {
      const normalized = relayUrl(hint);
      if (policy.mode === "private-only" && !allowed.has(normalized)) throw new Error();
    }
    return policy;
  } catch {
    throw new Error("Invalid relay policy.");
  }
}

export function parseInvitation(link: string, now = Date.now()): Invitation {
  try {
    if (link.length > 8192) throw new Error();
    const url = new URL(link);
    if (url.protocol !== "t3-iroh:" || url.host !== "pair" || url.search || url.pathname)
      throw new Error();
    const value: unknown = JSON.parse(Buffer.from(url.hash.slice(1), "base64url").toString("utf8"));
    if (typeof value !== "object" || value === null) throw new Error();
    const v = value as Record<string, unknown>;
    if (
      v.version !== 1 ||
      typeof v.environmentId !== "string" ||
      !v.environmentId ||
      v.environmentId.length > 128 ||
      typeof v.hostId !== "string" ||
      !/^[a-f0-9]{64}$/.test(v.hostId) ||
      typeof v.invitationId !== "string" ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(v.invitationId) ||
      typeof v.secret !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(v.secret) ||
      typeof v.expiresAt !== "number" ||
      !Number.isSafeInteger(v.expiresAt) ||
      v.expiresAt <= now ||
      v.expiresAt > now + INVITATION_TTL_MS ||
      !Array.isArray(v.relays) ||
      v.relays.some((hint) => typeof hint !== "string")
    )
      throw new Error();
    validateRelayPolicy({ mode: "automatic" }, v.relays);
    return {
      version: 1,
      environmentId: v.environmentId,
      hostId: v.hostId,
      invitationId: v.invitationId,
      secret: v.secret,
      expiresAt: v.expiresAt,
      relays: v.relays,
    };
  } catch {
    throw new Error("Invalid invitation.");
  }
}

export function invitationLink(invitation: Invitation): string {
  return `t3-iroh://pair#${Buffer.from(JSON.stringify(invitation)).toString("base64url")}`;
}

export function logicalOrigin(hostId: string): string {
  if (!/^[a-f0-9]{64}$/.test(hostId)) throw new Error("Invalid host identity.");
  return `http://${hostId.slice(0, 32)}.${hostId.slice(32)}.iroh.invalid`;
}

export interface DeviceTranscript {
  readonly hostId: string;
  readonly environmentId: string;
  readonly operation: "enroll" | "renew";
  readonly challenge: string;
  readonly body: Readonly<Record<string, unknown>>;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.entries(value)
      .sort(([a], [b]) => a.localeCompare(b, "en"))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
      .join(",")}}`;
  const result = JSON.stringify(value);
  if (result === undefined) throw new Error("Invalid proof body.");
  return result;
}

export function publicDeviceKey(key: NodeCrypto.JsonWebKey): NodeCrypto.JsonWebKey {
  if (
    key.kty !== "EC" ||
    key.crv !== "P-256" ||
    key.d !== undefined ||
    typeof key.x !== "string" ||
    typeof key.y !== "string" ||
    !/^[\w-]{43}$/.test(key.x) ||
    !/^[\w-]{43}$/.test(key.y)
  )
    throw new Error("Invalid device key.");
  const publicKey = { kty: "EC", crv: "P-256", x: key.x, y: key.y };
  NodeCrypto.createPublicKey({ key: publicKey, format: "jwk" });
  return publicKey;
}

export function deviceThumbprint(key: NodeCrypto.JsonWebKey): string {
  const jwk = publicDeviceKey(key);
  return NodeCrypto.createHash("sha256")
    .update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
    .digest("base64url");
}

function transcriptBytes(transcript: DeviceTranscript): Buffer {
  return Buffer.from(`t3/iroh/pairing/1\n${canonical(transcript)}`);
}

export function createDeviceProof(key: NodeCrypto.KeyObject, transcript: DeviceTranscript): string {
  return NodeCrypto.sign("sha256", transcriptBytes(transcript), {
    key,
    dsaEncoding: "ieee-p1363",
  }).toString("base64url");
}

export function verifyDeviceProof(
  key: NodeCrypto.JsonWebKey,
  transcript: DeviceTranscript,
  signature: string,
): boolean {
  try {
    if (!/^[\w-]{86}$/.test(signature)) return false;
    return NodeCrypto.verify(
      "sha256",
      transcriptBytes(transcript),
      {
        key: NodeCrypto.createPublicKey({ key: publicDeviceKey(key), format: "jwk" }),
        dsaEncoding: "ieee-p1363",
      },
      Buffer.from(signature, "base64url"),
    );
  } catch {
    return false;
  }
}
