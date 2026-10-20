// oxlint-disable unicorn/require-post-message-target-origin -- Node worker_threads messages have no browser targetOrigin argument.
import * as NodeWorkerThreads from "node:worker_threads";
import * as NodeCrypto from "node:crypto";
import { openDeviceDatabase } from "../deviceDatabase.ts";
import { createDeviceProof } from "@t3tools/iroh/protocol";

const { path, hostId, environmentId, peerId, invitation, publicKey, privateKey, barrier } =
  NodeWorkerThreads.workerData;
const db = openDeviceDatabase({ path, hostId, environmentId, now: () => 1000 });
try {
  const challenge = db.challenge(peerId, "enroll");
  const body = db.enrollmentBody(invitation.invitationId, invitation.secret, publicKey, [
    "orchestration:read",
  ]);
  const proof = createDeviceProof(NodeCrypto.createPrivateKey({ key: privateKey, format: "jwk" }), {
    hostId,
    environmentId,
    operation: "enroll",
    challenge,
    body,
  });
  NodeWorkerThreads.parentPort!.postMessage("ready");
  Atomics.wait(new Int32Array(barrier), 0, 0);
  try {
    db.redeem({ peerId, challenge, ...body, secret: invitation.secret, proof });
    NodeWorkerThreads.parentPort!.postMessage(true);
  } catch {
    NodeWorkerThreads.parentPort!.postMessage(false);
  }
} finally {
  db.close();
}
