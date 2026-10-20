import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import { GatewayOwners } from "./gatewayOwners.ts";

NodeTest.test("one owner listener survives reconnects and is removed at shutdown", async () => {
  const owners = new GatewayOwners();
  let added = 0,
    removed = 0,
    closed = 0;
  const subscribe = (_destroy: () => void) => {
    added++;
    return () => {
      removed++;
    };
  };
  for (let i = 0; i < 30; i++) {
    owners.observe(7, subscribe);
    const lease = await owners.open(7, async () => ({
      close: async () => {
        closed++;
      },
    }));
    await NodeAssert.rejects(owners.close(lease.id, 8));
    await owners.close(lease.id, 7);
  }
  NodeAssert.equal(added, 1);
  NodeAssert.equal(closed, 30);
  await owners.shutdown();
  NodeAssert.equal(removed, 1);
});

for (const ending of ["destroy", "shutdown"] as const)
  NodeTest.test(`late pending gateway closes after owner ${ending}`, async () => {
    const owners = new GatewayOwners();
    let destroy = () => {};
    owners.observe(1, (callback) => {
      destroy = callback;
      return () => {};
    });
    let finish!: (value: { close(): Promise<void> }) => void;
    let closed = 0;
    const pending = owners.open(
      1,
      () =>
        new Promise<{ close(): Promise<void> }>((resolve) => {
          finish = resolve;
        }),
    );
    const denied = NodeAssert.rejects(pending);
    if (ending === "destroy") destroy();
    else await owners.shutdown();
    finish({
      close: async () => {
        closed++;
      },
    });
    await denied;
    NodeAssert.equal(closed, 1);
    await NodeAssert.rejects(
      owners.open(1, async () => {
        throw new Error("must not start");
      }),
    );
  });

NodeTest.test("forget closes active and late gateways for a profile", async () => {
  const owners = new GatewayOwners();
  owners.observe(1, () => () => {});
  let closed = 0;
  await owners.open(
    1,
    async () => ({
      close: async () => {
        closed++;
      },
    }),
    "profile",
  );
  let finish!: (gateway: { close(): Promise<void> }) => void;
  const pending = owners.open(
    1,
    () =>
      new Promise<{ close(): Promise<void> }>((r) => {
        finish = r;
      }),
    "profile",
  );
  const denied = NodeAssert.rejects(pending);
  await owners.closeKey("profile");
  finish({
    close: async () => {
      closed++;
    },
  });
  await denied;
  NodeAssert.equal(closed, 2);
  await NodeAssert.rejects(owners.open(1, async () => ({ close: async () => {} }), "profile"));
});
