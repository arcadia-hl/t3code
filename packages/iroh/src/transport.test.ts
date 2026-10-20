import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as NodeEvents from "node:events";
import { irohDuplex, readControl, writeControl, assertPinnedHost } from "./transport.ts";

function stream() {
  const writes: number[][] = [];
  let stopped = false;
  let reset = false;
  let finished = false;
  const data = [Array.from(Buffer.from("abc")), null];
  return {
    native: {
      send: {
        writeAll: async (bytes: number[]) => {
          writes.push(bytes);
        },
        finish: () => {
          finished = true;
        },
        reset: () => {
          reset = true;
        },
      },
      recv: {
        read: async () => data.shift() ?? null,
        stop: () => {
          stopped = true;
        },
      },
    },
    writes,
    status: () => ({ stopped, reset, finished }),
  };
}

NodeTest.test(
  "native duplex streams bytes with bounded chunks and closes native halves",
  async () => {
    const fixture = stream();
    const duplex = irohDuplex(fixture.native);
    const chunks: Buffer[] = [];
    duplex.on("data", (chunk) => chunks.push(chunk));
    duplex.end(Buffer.alloc(150_000, 1));
    await NodeEvents.EventEmitter.once(duplex, "finish");
    await NodeEvents.EventEmitter.once(duplex, "close");
    NodeAssert.equal(Buffer.concat(chunks).toString(), "abc");
    NodeAssert.equal(
      fixture.writes.reduce((n, bytes) => n + bytes.length, 0),
      150_000,
    );
    NodeAssert.ok(fixture.writes.every((bytes) => bytes.length <= 64 * 1024));
    NodeAssert.equal(fixture.status().finished, true);
  },
);

NodeTest.test(
  "control messages have bounded framing and preserve subsequent HTTP bytes",
  async () => {
    const fixture = stream();
    await writeControl(fixture.native, { version: 1, operation: "http" });
    const combined = Buffer.concat([
      Buffer.from(fixture.writes.flat()),
      Buffer.from("GET /api/auth/session HTTP/1.1\r\n"),
    ]);
    const recv = { read: async () => Array.from(combined), stop: () => {} };
    const { value, remainder } = await readControl({ recv });
    NodeAssert.deepEqual(value, { version: 1, operation: "http" });
    NodeAssert.ok(remainder.toString().startsWith("GET "));
    const invalid = { recv: { read: async () => [0xff, 0xff, 0xff, 0xff], stop: () => {} } };
    await NodeAssert.rejects(readControl(invalid), /Invalid Iroh control frame/);
  },
);

NodeTest.test("wrong pinned host closes the connection before any enrollment disclosure", () => {
  let closed = false;
  const connection = {
    remoteId: () => ({ toString: () => "wrong" }),
    close: () => {
      closed = true;
    },
  };
  NodeAssert.throws(() => assertPinnedHost(connection, "expected"), /Iroh host identity mismatch/);
  NodeAssert.equal(closed, true);
});
