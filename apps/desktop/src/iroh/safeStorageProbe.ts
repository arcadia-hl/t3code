// @effect-diagnostics nodeBuiltinImport:off -- Windowless packaging probe uses supervisor-owned private fixtures, removed after Electron exits.
import * as Electron from "electron";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import * as NodeAssert from "node:assert/strict";
import { encryptedProfileStore } from "./encryptedProfiles.ts";
const rootArgument = process.argv.indexOf("--iroh-probe-root");
const suppliedRoot = process.argv[rootArgument + 1];
if (rootArgument < 0 || suppliedRoot === undefined || !NodePath.isAbsolute(suppliedRoot)) {
  throw new Error("Storage probe requires its supervisor-owned fixture directory.");
}
const root = suppliedRoot;
NodeFS.mkdirSync(NodePath.join(root, "electron"));
Electron.app.setPath("userData", NodePath.join(root, "electron"));
async function probe() {
  await Electron.app.whenReady();
  NodeAssert.equal(Electron.safeStorage.isEncryptionAvailable(), true);
  const crypto = {
    available: async () => Electron.safeStorage.isEncryptionAvailable(),
    encrypt: async (text: string) => Electron.safeStorage.encryptString(text),
    decrypt: async (bytes: Uint8Array) => Electron.safeStorage.decryptString(Buffer.from(bytes)),
  };
  const input = { directory: NodePath.join(root, "profiles"), privateRoot: root, crypto };
  const profile = {
    version: 1 as const,
    profileId: NodeCrypto.randomUUID(),
    hostId: "a".repeat(64),
    environmentId: "probe-environment",
    deviceId: NodeCrypto.randomUUID(),
    label: "probe",
    scopes: ["orchestration:read"],
    privateKey: NodeCrypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    }).privateKey.export({ format: "jwk" }),
    relayPolicy: { mode: "automatic" as const },
    relays: [],
  };
  const store = encryptedProfileStore(input);
  await store.create(profile);
  const ciphertext = NodeFS.readFileSync(
    NodePath.join(input.directory, `${profile.profileId}.dpapi`),
  );
  NodeAssert.equal(ciphertext.includes(Buffer.from(profile.privateKey.d!)), false);
  NodeAssert.deepEqual(await encryptedProfileStore(input).read(profile.profileId), profile);
  await NodeAssert.rejects(store.create(profile));
  await NodeAssert.rejects(
    encryptedProfileStore({ ...input, crypto: { ...crypto, available: async () => false } }).read(
      profile.profileId,
    ),
  );
  await store.forget(profile.profileId);
  NodeAssert.equal((await store.list()).length, 0);
  process.stdout.write("Windows safeStorage profile probe passed.\n");
}
void probe().then(
  () => Electron.app.exit(0),
  () => {
    process.stderr.write("Windows safeStorage profile probe failed.\n");
    Electron.app.exit(1);
  },
);
