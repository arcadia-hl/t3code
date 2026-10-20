import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import { loadHostSeed } from "./keys.ts";

function fixture(t: { after(fn: () => void): void }) {
  const root = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-iroh-key-"));
  t.after(() => NodeFS.rmSync(root, { recursive: true, force: true }));
  return { root, directory: NodePath.join(root, "identity") };
}

NodeTest.test("creates owner-only identity atomically and preserves it on restart", (t) => {
  const { directory } = fixture(t);
  const a = loadHostSeed({ kind: "file", directory });
  const b = loadHostSeed({ kind: "file", directory });
  NodeAssert.equal(a.length, 32);
  NodeAssert.ok(a.equals(b));
  NodeAssert.equal(NodeFS.statSync(directory).mode & 0o777, 0o700);
  NodeAssert.equal(NodeFS.statSync(NodePath.join(directory, "host.seed")).mode & 0o777, 0o600);
});

for (const mode of [0o644, 0o660, 0o666]) {
  NodeTest.test(
    `rejects insecure existing seed permissions ${mode.toString(8)} without repairing or rotating`,
    (t) => {
      const { directory } = fixture(t);
      loadHostSeed({ kind: "file", directory });
      const path = NodePath.join(directory, "host.seed");
      const original = NodeFS.readFileSync(path);
      NodeFS.chmodSync(path, mode);
      NodeAssert.throws(() => loadHostSeed({ kind: "file", directory }), /Unsafe identity/);
      NodeAssert.ok(NodeFS.readFileSync(path).equals(original));
      NodeAssert.equal(NodeFS.statSync(path).mode & 0o777, mode);
    },
  );
}

NodeTest.test("rejects symlink directories, seed symlinks, hard links and corrupt seeds", (t) => {
  const { root, directory } = fixture(t);
  NodeFS.mkdirSync(directory, { mode: 0o700 });
  const other = NodePath.join(root, "other");
  NodeFS.writeFileSync(other, Buffer.alloc(32), { mode: 0o600 });
  NodeFS.symlinkSync(other, NodePath.join(directory, "host.seed"));
  NodeAssert.throws(() => loadHostSeed({ kind: "file", directory }), /Unsafe identity/);
  NodeFS.rmSync(NodePath.join(directory, "host.seed"));
  NodeFS.linkSync(other, NodePath.join(directory, "host.seed"));
  NodeAssert.throws(() => loadHostSeed({ kind: "file", directory }), /Unsafe identity/);
  NodeFS.rmSync(NodePath.join(directory, "host.seed"));
  NodeFS.writeFileSync(NodePath.join(directory, "host.seed"), Buffer.alloc(31), { mode: 0o600 });
  NodeAssert.throws(() => loadHostSeed({ kind: "file", directory }), /Unsafe identity/);
  NodeFS.symlinkSync(directory, NodePath.join(root, "alias"));
  NodeAssert.throws(
    () => loadHostSeed({ kind: "file", directory: NodePath.join(root, "alias") }),
    /Unsafe identity/,
  );
});

NodeTest.test(
  "rejects an existing accessible directory instead of changing its permissions",
  (t) => {
    const { directory } = fixture(t);
    NodeFS.mkdirSync(directory, { mode: 0o755 });
    NodeAssert.throws(() => loadHostSeed({ kind: "file", directory }), /Unsafe identity/);
    NodeAssert.equal(NodeFS.statSync(directory).mode & 0o777, 0o755);
  },
);

NodeTest.test(
  "systemd credential backend reads a raw seed and never falls back on missing or malformed credentials",
  (t) => {
    const { root } = fixture(t);
    const path = NodePath.join(root, "credential");
    NodeFS.writeFileSync(path, Buffer.alloc(32, 7), { mode: 0o400 });
    const seed = loadHostSeed({ kind: "systemd-credential", path });
    NodeAssert.equal(seed.length, 32);
    NodeAssert.ok(seed.every((byte) => byte === 7));
    NodeAssert.throws(() =>
      loadHostSeed({ kind: "systemd-credential", path: NodePath.join(root, "absent") }),
    );
    NodeFS.chmodSync(path, 0o600);
    NodeFS.writeFileSync(path, Buffer.alloc(12));
    NodeAssert.throws(() => loadHostSeed({ kind: "systemd-credential", path }), /Unsafe identity/);
  },
);

NodeTest.test("rejects a same-owner group-writable ancestor without creating identity", (t) => {
  const { root } = fixture(t);
  const shared = NodePath.join(root, "shared");
  NodeFS.mkdirSync(shared, { mode: 0o770 });
  NodeFS.chmodSync(shared, 0o770);
  NodeAssert.throws(
    () => loadHostSeed({ kind: "file", directory: NodePath.join(shared, "identity") }),
    /Unsafe identity/,
  );
});

NodeTest.test("existing host state cannot silently regenerate a missing seed", (t) => {
  const { directory } = fixture(t);
  NodeAssert.throws(
    () => loadHostSeed({ kind: "file", directory, allowCreate: false }),
    /Unsafe identity/,
  );
  NodeAssert.equal(NodeFS.existsSync(NodePath.join(directory, "host.seed")), false);
});
