import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as NodeCrypto from "node:crypto";
import {
  invitationLink,
  parseInvitation,
  validateRelayPolicy,
  logicalOrigin,
  createDeviceProof,
  verifyDeviceProof,
} from "./protocol.ts";

const hostId = "a".repeat(64);
const invitation = {
  version: 1 as const,
  environmentId: "environment-a",
  hostId,
  invitationId: "id",
  secret: "A".repeat(43),
  expiresAt: 100_000,
  relays: ["https://relay.example/"],
};

NodeTest.test("versioned invitation roundtrips with secret only in fragment", () => {
  const link = invitationLink(invitation);
  NodeAssert.equal(new URL(link).search, "");
  NodeAssert.deepEqual(parseInvitation(link, 1), invitation);
});

NodeTest.test(
  "rejects malformed, expired, unbounded and unknown-version invitation metadata",
  () => {
    for (const value of [
      "oops",
      "https://example/",
      "t3-iroh://pair#garbage",
      `t3-iroh://pair#${"A".repeat(9000)}`,
    ]) {
      NodeAssert.throws(() => parseInvitation(value, 1), /Invalid invitation/);
    }
    for (const patch of [
      { version: 2 },
      { expiresAt: 1 },
      { secret: "short" },
      { relays: Array(9).fill("https://relay.example") },
      { hostId: "http://evil" },
    ]) {
      const link = `t3-iroh://pair#${Buffer.from(JSON.stringify({ ...invitation, ...patch })).toString("base64url")}`;
      NodeAssert.throws(() => parseInvitation(link, 2), /Invalid invitation/);
    }
  },
);

NodeTest.test(
  "private-only policy rejects public fallback and unauthorized invitation relay hints",
  () => {
    const policy = validateRelayPolicy(
      { mode: "private-only", relays: [{ url: "https://private.example/" }] },
      ["https://private.example/"],
    );
    NodeAssert.equal(policy.mode, "private-only");
    for (const relays of [
      [],
      [{ url: "http://insecure.example/" }],
      [{ url: "https://user:secret@relay.example/" }],
      [{ url: "https://relay.example/?token=bad" }],
    ]) {
      NodeAssert.throws(
        () => validateRelayPolicy({ mode: "private-only", relays }),
        /Invalid relay policy/,
      );
    }
    NodeAssert.throws(
      () => validateRelayPolicy(policy, ["https://public.example/"]),
      /Invalid relay policy/,
    );
  },
);

NodeTest.test("device proof binds host, environment, operation, challenge, and body", () => {
  const { publicKey, privateKey } = NodeCrypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const jwk = publicKey.export({ format: "jwk" });
  const transcript = {
    hostId,
    environmentId: "environment-a",
    operation: "renew" as const,
    challenge: "nonce",
    body: { deviceId: "device-a", scopes: ["orchestration:read"] },
  };
  const signature = createDeviceProof(privateKey, transcript);
  NodeAssert.equal(verifyDeviceProof(jwk, transcript, signature), true);
  for (const patch of [
    { hostId: "b".repeat(64) },
    { environmentId: "environment-b" },
    { operation: "enroll" as const },
    { challenge: "other" },
    { body: { deviceId: "device-b" } },
  ]) {
    NodeAssert.equal(verifyDeviceProof(jwk, { ...transcript, ...patch }, signature), false);
  }
  NodeAssert.equal(
    logicalOrigin(hostId),
    `http://${hostId.slice(0, 32)}.${hostId.slice(32)}.iroh.invalid`,
  );
});
