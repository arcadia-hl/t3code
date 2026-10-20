import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import * as NodeWorkerThreads from "node:worker_threads";
import * as NodeEvents from "node:events";
import * as NodeCrypto from "node:crypto";
import { openDeviceDatabase } from "./deviceDatabase.ts";
import { createDeviceProof } from "@t3tools/iroh/protocol";

const hostId = "a".repeat(64);
const environmentId = "env-one";
const peerId = "b".repeat(64);
const read = ["orchestration:read"];
function setup(t: { after(fn: () => void): void }) {
  const directory = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-iroh-devices-"));
  const path = NodePath.join(directory, "devices.sqlite");
  let now = 1000;
  const db = openDeviceDatabase({ path, hostId, environmentId, now: () => now });
  t.after(() => {
    db.close();
    NodeFS.rmSync(directory, { recursive: true, force: true });
  });
  const keys = NodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicKey = keys.publicKey.export({ format: "jwk" });
  const enroll = (invite = db.invite(read)) => {
    const challenge = db.challenge(peerId, "enroll");
    const body = db.enrollmentBody(invite.invitationId, invite.secret, publicKey, read);
    return db.redeem({
      peerId,
      challenge,
      ...body,
      secret: invite.secret,
      proof: createDeviceProof(keys.privateKey, {
        hostId,
        environmentId,
        operation: "enroll",
        challenge,
        body,
      }),
    });
  };
  const renew = (deviceId: string, scopes = read, changes: Record<string, unknown> = {}) => {
    const challenge = db.challenge(peerId, "renew");
    const body = { deviceId, scopes };
    return db.renew({
      peerId,
      challenge,
      ...body,
      proof: createDeviceProof(keys.privateKey, {
        hostId,
        environmentId,
        operation: "renew",
        challenge,
        body,
        ...changes,
      }),
    });
  };
  return {
    db,
    enroll,
    renew,
    path,
    setNow: (value: number) => {
      now = value;
    },
  };
}

NodeTest.test(
  "one-time invitation stores only verifier, requires host approval, renews after restart",
  (t) => {
    const { db, enroll, renew, path } = setup(t);
    const invite = db.invite(read);
    NodeAssert.equal(NodeFS.readFileSync(path).includes(invite.secret), false);
    const device = enroll(invite);
    NodeAssert.equal(device.status, "pending");
    NodeAssert.throws(() => renew(device.deviceId), /Device not approved/);
    db.approve(device.deviceId, read);
    NodeAssert.deepEqual(renew(device.deviceId).scopes, read);
    NodeAssert.throws(() => enroll(invite), /Invalid invitation/);
    db.close();
    const restarted = openDeviceDatabase({ path, hostId, environmentId, now: () => 1000 });
    NodeAssert.equal(restarted.devices()[0]?.status, "approved");
    restarted.close();
  },
);

NodeTest.test("malformed, expired, revoked invitations and scope escalation fail closed", (t) => {
  const { db, enroll, renew, setNow } = setup(t);
  NodeAssert.throws(() => enroll({ ...db.invite(read), secret: "short" }), /Invalid invitation/);
  const expired = db.invite(read);
  setNow(expired.expiresAt);
  NodeAssert.throws(() => enroll(expired), /Invalid invitation/);
  const revoked = db.invite(read);
  db.revokeInvitation(revoked.invitationId);
  NodeAssert.throws(() => enroll(revoked), /Invalid invitation/);
  const device = enroll();
  NodeAssert.throws(() => db.approve(device.deviceId, ["access:write"]), /Scope escalation/);
  db.approve(device.deviceId, read);
  NodeAssert.throws(() => renew(device.deviceId, ["access:write"]), /Scope escalation/);
  NodeAssert.throws(
    () => renew(device.deviceId, read, { hostId: "c".repeat(64) }),
    /Invalid device proof/,
  );
});

NodeTest.test(
  "simultaneous valid redemptions in independent workers consume exactly once",
  async (t) => {
    const { db, path } = setup(t);
    const invitation = db.invite(read);
    const keys = NodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const barrier = new SharedArrayBuffer(4);
    const workers = [0, 1].map(
      (i) =>
        new NodeWorkerThreads.Worker(new URL("./testUtils/redemption.worker.ts", import.meta.url), {
          workerData: {
            path,
            hostId,
            environmentId,
            peerId: peerId + i,
            invitation,
            publicKey: keys.publicKey.export({ format: "jwk" }),
            privateKey: keys.privateKey.export({ format: "jwk" }),
            barrier,
          },
        }),
    );
    const exited = workers.map((worker) => NodeEvents.EventEmitter.once(worker, "exit"));
    await Promise.all(
      workers.map((worker) =>
        NodeEvents.EventEmitter.once(worker, "message").then(([message]) =>
          NodeAssert.equal(message, "ready"),
        ),
      ),
    );
    const results = workers.map((worker) =>
      NodeEvents.EventEmitter.once(worker, "message").then(([message]) => message),
    );
    Atomics.store(new Int32Array(barrier), 0, 1);
    Atomics.notify(new Int32Array(barrier), 0);
    NodeAssert.deepEqual((await Promise.all(results)).sort(), [false, true]);
    await Promise.all(exited);
    NodeAssert.equal(db.devices().length, 1);
  },
);

NodeTest.test(
  "device removal persists, returns all sessions for invalidation, blocks renewal and in-flight session attachment",
  (t) => {
    const { db, enroll, renew } = setup(t);
    const device = enroll();
    db.approve(device.deviceId, read);
    db.attachSession(device.deviceId, "session-1", 99999);
    db.attachSession(device.deviceId, "session-2", 99999);
    NodeAssert.deepEqual(db.revokeDevice(device.deviceId), ["session-1", "session-2"]);
    NodeAssert.throws(() => renew(device.deviceId), /Device not approved/);
    NodeAssert.equal(db.attachSession(device.deviceId, "late-session", 99999), false);
    NodeAssert.throws(() => db.approve(device.deviceId, read), /Device not approved/);
  },
);

NodeTest.test(
  "challenge is one-use and bound to caller, with bounded unauthenticated state",
  (t) => {
    const { db, enroll, renew } = setup(t);
    const device = enroll();
    db.approve(device.deviceId, read);
    NodeAssert.deepEqual(renew(device.deviceId).scopes, read);
    for (let i = 0; i < 256; i++) db.challenge(peerId, "renew");
    NodeAssert.throws(() => db.challenge(peerId, "renew"), /Pairing capacity/);
  },
);

NodeTest.test("renewal challenge rejects another caller, replay and expiry", (t) => {
  const { db, enroll, setNow } = setup(t);
  const device = enroll();
  db.approve(device.deviceId, read);
  const keys = NodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const nonce = db.challenge(peerId, "renew");
  const body = { deviceId: device.deviceId, scopes: read };
  const request = {
    peerId: "other-peer",
    challenge: nonce,
    ...body,
    proof: createDeviceProof(keys.privateKey, {
      hostId,
      environmentId,
      operation: "renew",
      challenge: nonce,
      body,
    }),
  };
  NodeAssert.throws(() => db.renew(request), /Invalid device proof/);
  setNow(1000 + 30_000);
  NodeAssert.throws(() => db.renew({ ...request, peerId }), /Invalid device proof/);
});
