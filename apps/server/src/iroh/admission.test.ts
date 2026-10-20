import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import { TransportAdmission } from "./admission.ts";

NodeTest.test("removal between renewal and callback cannot reauthorize the transport", () => {
  let closed = 0;
  const connection = {
    close: () => {
      closed++;
    },
  };
  const admission = new TransportAdmission<typeof connection>(2, 2);
  const release = admission.handshake();
  NodeAssert.ok(release);
  NodeAssert.ok(admission.accept(connection));
  release();
  admission.revoke("device");
  NodeAssert.equal(admission.authorize(connection, "device"), false);
  NodeAssert.equal(admission.device(connection), undefined);
  NodeAssert.equal(closed, 1);
});

NodeTest.test("pending handshakes and control frames share bounded global admission", () => {
  const admission = new TransportAdmission<{ close(): void }>(2, 2);
  const first = admission.handshake(),
    second = admission.handshake();
  NodeAssert.ok(first);
  NodeAssert.ok(second);
  NodeAssert.equal(admission.handshake(), undefined);
  first();
  first();
  const connection = { close: () => {} };
  NodeAssert.ok(admission.accept(connection));
  second();
  const third = admission.handshake();
  NodeAssert.ok(third);
  NodeAssert.equal(admission.handshake(), undefined);
  const a = admission.control(),
    b = admission.control();
  NodeAssert.ok(a);
  NodeAssert.ok(b);
  NodeAssert.equal(admission.control(), undefined);
  a();
  a();
  NodeAssert.ok(admission.control());
  admission.remove(connection);
  third();
  NodeAssert.ok(admission.handshake());
});
