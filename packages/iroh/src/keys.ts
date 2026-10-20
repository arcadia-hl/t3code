import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";

export type HostKeyBackend =
  | { readonly kind: "file"; readonly directory: string; readonly allowCreate?: boolean }
  | { readonly kind: "systemd-credential"; readonly path: string };

function unsafe(): never {
  // Never include seed bytes or the underlying filesystem error in a public message.
  throw new Error("Unsafe identity storage; refusing to read or replace the host key.");
}

function checkAncestors(path: string): void {
  const absolute = NodePath.resolve(path);
  let current = NodePath.parse(absolute).root;
  for (const part of absolute.slice(current.length).split("/")) {
    if (!part) continue;
    current = NodePath.join(current, part);
    const stat = NodeFS.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) unsafe();
    // Sticky shared parents allow a private child; writable non-sticky parents
    // permit another group member to replace a checked path component.
    if ((stat.mode & 0o022) !== 0 && (stat.mode & 0o1000) === 0) unsafe();
  }
}

export function ensurePrivateDirectory(directory: string): void {
  if (!NodePath.isAbsolute(directory)) unsafe();
  const parent = NodePath.dirname(directory);
  checkAncestors(parent);
  try {
    NodeFS.mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST") throw error;
  }
  const stat = NodeFS.lstatSync(directory);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid?.() ||
    (stat.mode & 0o777) !== 0o700
  )
    unsafe();
}

export function readPrivateFile(path: string, maxBytes: number): Buffer {
  checkAncestors(NodePath.dirname(path));
  if (NodeFS.lstatSync(path).isSymbolicLink()) unsafe();
  const fd = NodeFS.openSync(
    path,
    NodeFS.constants.O_RDONLY | NodeFS.constants.O_NOFOLLOW | NodeFS.constants.O_NONBLOCK,
  );
  try {
    const stat = NodeFS.fstatSync(fd);
    if (
      !stat.isFile() ||
      stat.uid !== process.getuid?.() ||
      (stat.mode & 0o177) !== 0 ||
      stat.nlink !== 1 ||
      stat.size > maxBytes
    )
      unsafe();
    const bytes = Buffer.alloc(stat.size);
    let position = 0;
    while (position < bytes.length) {
      const count = NodeFS.readSync(fd, bytes, position, bytes.length - position, position);
      if (count === 0) unsafe();
      position += count;
    }
    return bytes;
  } finally {
    NodeFS.closeSync(fd);
  }
}

export function loadHostSeed(backend: HostKeyBackend): Buffer {
  // oxlint-disable-next-line t3code/no-global-process-runtime -- POSIX seed protection must reject the actual Windows host, regardless of injected services.
  if (process.platform !== "linux")
    throw new Error("Iroh native transport currently supports Linux only.");
  if (backend.kind === "systemd-credential") {
    const seed = readPrivateFile(backend.path, 32);
    if (seed.length !== 32) unsafe();
    return seed;
  }
  ensurePrivateDirectory(backend.directory);
  const path = NodePath.join(backend.directory, "host.seed");
  try {
    NodeFS.lstatSync(path);
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
    if (backend.allowCreate === false) unsafe();
    const temporary = NodePath.join(backend.directory, `.host-${NodeCrypto.randomUUID()}`);
    const seed = NodeCrypto.randomBytes(32);
    const fd = NodeFS.openSync(
      temporary,
      NodeFS.constants.O_WRONLY |
        NodeFS.constants.O_CREAT |
        NodeFS.constants.O_EXCL |
        NodeFS.constants.O_NOFOLLOW,
      0o600,
    );
    try {
      NodeFS.writeSync(fd, seed);
      NodeFS.fsyncSync(fd);
    } finally {
      NodeFS.closeSync(fd);
      seed.fill(0);
    }
    try {
      // link is a no-replace atomic publication; a concurrent initializer cannot rotate identity.
      NodeFS.linkSync(temporary, path);
    } catch (error) {
      if (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST") throw error;
    } finally {
      NodeFS.unlinkSync(temporary);
    }
    const directoryFd = NodeFS.openSync(
      backend.directory,
      NodeFS.constants.O_RDONLY | NodeFS.constants.O_DIRECTORY | NodeFS.constants.O_NOFOLLOW,
    );
    try {
      NodeFS.fsyncSync(directoryFd);
    } finally {
      NodeFS.closeSync(directoryFd);
    }
  }
  const seed = readPrivateFile(path, 32);
  if (seed.length !== 32) unsafe();
  return seed;
}

export function publishPrivateFile(path: string, bytes: Uint8Array): void {
  ensurePrivateDirectory(NodePath.dirname(path));
  const temporary = NodePath.join(NodePath.dirname(path), `.new-${NodeCrypto.randomUUID()}`);
  const fd = NodeFS.openSync(
    temporary,
    NodeFS.constants.O_WRONLY |
      NodeFS.constants.O_CREAT |
      NodeFS.constants.O_EXCL |
      NodeFS.constants.O_NOFOLLOW,
    0o600,
  );
  try {
    let offset = 0;
    while (offset < bytes.length)
      offset += NodeFS.writeSync(fd, bytes, offset, bytes.length - offset);
    NodeFS.fsyncSync(fd);
  } finally {
    NodeFS.closeSync(fd);
  }
  try {
    NodeFS.linkSync(temporary, path);
  } finally {
    NodeFS.unlinkSync(temporary);
  }
  const parent = NodeFS.openSync(
    NodePath.dirname(path),
    NodeFS.constants.O_RDONLY | NodeFS.constants.O_DIRECTORY | NodeFS.constants.O_NOFOLLOW,
  );
  try {
    NodeFS.fsyncSync(parent);
  } finally {
    NodeFS.closeSync(parent);
  }
}
