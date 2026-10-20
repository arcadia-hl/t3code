// @effect-diagnostics nodeBuiltinImport:off -- Isolated filesystem and cryptography fixtures exercise the protected-storage boundary.
import * as NodeAssert from "node:assert/strict";
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import * as NodeTest from "node:test";
import { encryptedProfileStore } from "./encryptedProfiles.ts";
const profile = () => ({
  version: 1 as const,
  profileId: NodeCrypto.randomUUID(),
  hostId: "a".repeat(64),
  environmentId: "env-test",
  deviceId: NodeCrypto.randomUUID(),
  label: "test",
  scopes: ["environment:read"],
  privateKey: NodeCrypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" }).privateKey.export({
    format: "jwk",
  }),
  relayPolicy: {
    mode: "automatic" as const,
    relays: [{ url: "https://relay.example/", authToken: "test-fixture-relay-value" }],
  },
  relays: [],
});
NodeTest.test(
  "protected store persists ciphertext, rejects overwrite, corruption and unavailable crypto without replacing identity",
  async () => {
    const root = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "iroh-encrypted-"));
    const key = NodeCrypto.randomBytes(32);
    let available = true;
    const crypto = {
      available: async () => available,
      encrypt: async (text: string) => {
        const iv = NodeCrypto.randomBytes(12);
        const c = NodeCrypto.createCipheriv("aes-256-gcm", key, iv);
        const bytes = Buffer.concat([c.update(text), c.final()]);
        return Buffer.concat([iv, c.getAuthTag(), bytes]);
      },
      decrypt: async (bytes: Uint8Array) => {
        const b = Buffer.from(bytes);
        const d = NodeCrypto.createDecipheriv("aes-256-gcm", key, b.subarray(0, 12));
        d.setAuthTag(b.subarray(12, 28));
        return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString();
      },
    };
    try {
      const store = encryptedProfileStore({
        directory: NodePath.join(root, "profiles"),
        privateRoot: root,
        crypto,
      });
      const p = profile();
      await store.create(p);
      const path = NodePath.join(root, "profiles", `${p.profileId}.dpapi`);
      const bytes = NodeFS.readFileSync(path);
      NodeAssert.equal(bytes.includes(Buffer.from(p.privateKey.d!)), false);
      NodeAssert.equal(bytes.includes(Buffer.from("test-fixture-relay-value")), false);
      NodeAssert.deepEqual(await store.read(p.profileId), p);
      NodeAssert.equal((await store.list()).length, 1);
      await NodeAssert.rejects(store.create(p));
      NodeAssert.deepEqual(NodeFS.readFileSync(path), bytes);
      available = false;
      await NodeAssert.rejects(store.read(p.profileId));
      await NodeAssert.rejects(store.list());
      NodeAssert.deepEqual(NodeFS.readFileSync(path), bytes);
      available = true;
      NodeFS.writeFileSync(path, Buffer.from("corrupt"));
      await NodeAssert.rejects(store.read(p.profileId));
      NodeAssert.equal(NodeFS.readFileSync(path).toString(), "corrupt");
      await store.forget(p.profileId);
      NodeAssert.equal((await store.list()).length, 0);
      await NodeAssert.rejects(store.read("../escape"));
      const outside = encryptedProfileStore({
        directory: NodePath.dirname(root),
        privateRoot: root,
        crypto,
      });
      await NodeAssert.rejects(outside.list());
      const linked = NodePath.join(root, "linked");
      NodeFS.symlinkSync(NodePath.join(root, "profiles"), linked, "junction");
      await NodeAssert.rejects(
        encryptedProfileStore({ directory: linked, privateRoot: root, crypto }).list(),
      );
    } finally {
      key.fill(0);
      NodeFS.rmSync(root, { recursive: true, force: true });
    }
  },
);
