import * as NodeStream from "node:stream";
import { MAX_CONTROL_BYTES } from "./protocol.ts";

export interface NativeStream {
  readonly send: {
    writeAll(bytes: number[]): Promise<void>;
    finish(): Promise<void> | void;
    reset(code: bigint): Promise<void> | void;
  };
  readonly recv: {
    read(limit: number): Promise<number[] | null>;
    stop(code: bigint): Promise<void> | void;
  };
}

export function assertPinnedHost(
  connection: { remoteId(): { toString(): string }; close(code: bigint, reason: number[]): void },
  expected: string,
): void {
  if (connection.remoteId().toString() !== expected) {
    connection.close(1n, []);
    throw new Error("Iroh host identity mismatch.");
  }
}

export function irohDuplex(
  stream: NativeStream,
  initial: Buffer = Buffer.alloc(0),
): NodeStream.Duplex {
  let reading = false;
  const duplex = new NodeStream.Duplex({
    allowHalfOpen: true,
    highWaterMark: 64 * 1024,
    read() {
      if (reading) return;
      reading = true;
      void (async () => {
        if (initial.length) {
          const bytes = initial;
          initial = Buffer.alloc(0);
          if (!duplex.push(bytes)) return;
        }
        while (!duplex.destroyed) {
          const bytes = await stream.recv.read(64 * 1024);
          if (!bytes?.length) {
            duplex.push(null);
            return;
          }
          if (bytes.length > 64 * 1024) throw new Error("Oversized native read.");
          if (!duplex.push(Buffer.from(bytes))) return;
        }
      })()
        .catch(() => duplex.destroy(new Error("Iroh receive failed.")))
        .finally(() => {
          reading = false;
        });
    },
    write(chunk: Buffer, _encoding, callback) {
      void (async () => {
        for (let offset = 0; offset < chunk.length; offset += 64 * 1024)
          await stream.send.writeAll(Array.from(chunk.subarray(offset, offset + 64 * 1024)));
      })().then(
        () => callback(),
        () => callback(new Error("Iroh send failed.")),
      );
    },
    final(callback) {
      Promise.resolve(stream.send.finish()).then(
        () => callback(),
        () => callback(new Error("Iroh finish failed.")),
      );
    },
    destroy(error, callback) {
      // The pinned local patch interrupts a pending native read before acquiring
      // its mutex, so aborting one HTTP stream leaves the connection usable.
      void Promise.resolve(stream.recv.stop(0n)).catch(() => {});
      void Promise.resolve(stream.send.reset(0n)).catch(() => {});
      callback(error);
    },
  });
  return duplex;
}

export async function writeControl(
  stream: Pick<NativeStream, "send">,
  value: unknown,
): Promise<void> {
  const bytes = Buffer.from(JSON.stringify(value));
  if (bytes.length > MAX_CONTROL_BYTES) throw new Error("Invalid Iroh control frame.");
  const header = Buffer.alloc(4);
  header.writeUInt32BE(bytes.length);
  await stream.send.writeAll(Array.from(Buffer.concat([header, bytes])));
}

export async function readControl(
  stream: Pick<NativeStream, "recv">,
): Promise<{ value: unknown; remainder: Buffer }> {
  let bytes = Buffer.alloc(0);
  let length: number | undefined;
  while (true) {
    if (length === undefined && bytes.length >= 4) {
      length = bytes.readUInt32BE();
      if (length === 0 || length > MAX_CONTROL_BYTES)
        throw new Error("Invalid Iroh control frame.");
    }
    if (length !== undefined && bytes.length >= length + 4) {
      try {
        return {
          value: JSON.parse(bytes.subarray(4, length + 4).toString("utf8")),
          remainder: bytes.subarray(length + 4),
        };
      } catch {
        throw new Error("Invalid Iroh control frame.");
      }
    }
    const chunk = await stream.recv.read(MAX_CONTROL_BYTES + 4);
    if (!chunk?.length || chunk.length > MAX_CONTROL_BYTES + 4)
      throw new Error("Invalid Iroh control frame.");
    bytes = Buffer.concat([bytes, Buffer.from(chunk)]);
  }
}

export async function deadline<A>(
  promise: Promise<A>,
  milliseconds: number,
  cancel: () => void,
): Promise<A> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          cancel();
          reject(new Error("Iroh operation timed out."));
        }, milliseconds);
        timer.unref();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
