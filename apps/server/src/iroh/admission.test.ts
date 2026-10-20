import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import { TransportAdmission } from "./admission.ts";

NodeTest.test("an idle unapproved connection expires and releases its admission slot", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let closed = 0;
  const connection = {
    close: () => {
      closed++;
    },
  };
  const admission = new TransportAdmission<typeof connection>(1, 1);
  NodeAssert.ok(admission.accept(connection));
  NodeAssert.equal(admission.handshake(), undefined);
  t.mock.timers.tick(15_000);
  NodeAssert.equal(closed, 1);
  NodeAssert.equal(admission.connections.size, 0);
  const release = admission.handshake();
  NodeAssert.ok(release);
  release();
});

NodeTest.test("authorization and removal cancel the unauthenticated deadline", (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let closed = 0;
  const approved = {
    close: () => {
      closed++;
    },
  };
  const removed = {
    close: () => {
      closed++;
    },
  };
  const admission = new TransportAdmission<typeof approved>(2, 2);
  NodeAssert.ok(admission.accept(approved));
  NodeAssert.ok(admission.authorize(approved, "approved-device"));
  NodeAssert.ok(admission.accept(removed));
  admission.remove(removed);
  t.mock.timers.tick(60_000);
  NodeAssert.equal(closed, 0);
  NodeAssert.equal(admission.device(approved), "approved-device");
  admission.revoke("approved-device");
  NodeAssert.equal(closed, 1);
  t.mock.timers.tick(60_000);
  NodeAssert.equal(closed, 1);
});

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
