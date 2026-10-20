import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import { loadNative } from "./native.ts";

for (const operation of ["read", "readExact", "readToEnd", "receivedReset"] as const) {
  NodeTest.test(
    `native stop interrupts pending ${operation} and the connection remains usable`,
    { timeout: 8000 },
    async () => {
      const native = loadNative();
      const alpn = Array.from(Buffer.from("t3/cancellation-test/1"));
      const builder = native.Endpoint.builder();
      builder.applyMinimal();
      builder.alpns([alpn]);
      const host = await builder.bind();
      const cb = native.Endpoint.builder();
      cb.applyMinimal();
      const client = await cb.bind();
      try {
        const accepted = (async () => (await (await host.acceptNext())!.accept()).connect())();
        const connection = await client.connect(host.addr(), alpn);
        const remote = await accepted;
        const stream = await connection.openBi();
        const incoming = remote.acceptBi();
        await stream.send.writeAll([1]);
        const other = await incoming;
        NodeAssert.deepEqual(await other.recv.read(1), [1]);
        const reading =
          operation === "receivedReset" ? other.recv.receivedReset() : other.recv[operation](8);
        const rejected = NodeAssert.rejects(reading);
        // Queue another operation on the receive mutex before stop. Both must end.
        const queued = NodeAssert.rejects(other.recv.read(1));
        const stop = other.recv.stop(1n);
        await Promise.race([
          Promise.all([stop, rejected, queued]),
          new Promise((_, reject) => {
            const timer = setTimeout(
              () => reject(new Error("stop blocked behind pending native read")),
              1500,
            );
            timer.unref();
          }),
        ]);
        const next = await connection.openBi();
        const nextRemote = remote.acceptBi();
        await next.send.writeAll([9]);
        await next.send.finish();
        NodeAssert.deepEqual(await (await nextRemote).recv.readToEnd(8), [9]);
      } finally {
        await client.close();
        await host.close();
      }
    },
  );
}

NodeTest.test(
  "native reset interrupts a backpressured writeAll and queued write without closing the connection",
  { timeout: 8000 },
  async () => {
    const native = loadNative();
    const alpn = Array.from(Buffer.from("t3/send-cancellation-test/1"));
    const builder = native.Endpoint.builder();
    builder.applyMinimal();
    builder.alpns([alpn]);
    const host = await builder.bind();
    const cb = native.Endpoint.builder();
    cb.applyMinimal();
    const client = await cb.bind();
    try {
      const accepted = (async () => (await (await host.acceptNext())!.accept()).connect())();
      const connection = await client.connect(host.addr(), alpn);
      const remote = await accepted;
      const stream = await connection.openBi();
      const incoming = remote.acceptBi();
      const writing = stream.send.writeAll(Array(4 * 1024 * 1024).fill(7));
      const rejected = NodeAssert.rejects(writing);
      const other = await incoming;
      NodeAssert.deepEqual(await other.recv.read(1), [7]);
      const queued = NodeAssert.rejects(stream.send.writeAll([8]));
      const reset = stream.send.reset(1n);
      await Promise.race([
        Promise.all([reset, rejected, queued]),
        new Promise((_, reject) => {
          const timer = setTimeout(
            () => reject(new Error("reset blocked behind backpressured write")),
            1500,
          );
          timer.unref();
        }),
      ]);
      const next = await connection.openBi();
      const nextRemote = remote.acceptBi();
      await next.send.writeAll([9]);
      await next.send.finish();
      NodeAssert.deepEqual(await (await nextRemote).recv.readToEnd(8), [9]);
    } finally {
      await client.close();
      await host.close();
    }
  },
);
