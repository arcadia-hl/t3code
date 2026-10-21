import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import * as NodeChildProcess from "node:child_process";
import * as NodeModule from "node:module";
import * as NodeAssert from "node:assert/strict";

export const PAYLOAD_SOURCE = "57ef1d5b16d48ae56b62eb36915beb037b101037";
export const INSTALLER_SHA256 = "3b3610e3e3e8627f529d746d64cd33acf71bc95666bd45dca0fdadc776b3a729";
export const INSTALLER_BYTES = 157259189;
export const BINDING_PIN = "3103bf5295be6d50c5272ff7a426e9b539f3f587";
export const PATCH_SHA256 = "048145420bab2d23a32cbdd6983ddd0e12426f84f25f0eb47ffef1a3deab3f89";

export function hashFile(file, fs = NodeFS) {
  const descriptor = fs.openSync(file, "r");
  const hash = NodeCrypto.createHash("sha256");
  const buffer = Buffer.alloc(1024 * 1024);
  try {
    let length;
    while ((length = fs.readSync(descriptor, buffer, 0, buffer.length, null)) !== 0)
      hash.update(buffer.subarray(0, length));
    return hash.digest("hex");
  } finally {
    fs.closeSync(descriptor);
  }
}

export function inventory(root, fs = NodeFS) {
  const files = [];
  const visit = (directory) => {
    for (const name of fs.readdirSync(directory).sort()) {
      const path = NodePath.join(directory, name);
      const stat = fs.lstatSync(path);
      NodeAssert.equal(stat.isSymbolicLink(), false, "Payload cannot contain symbolic links.");
      if (
        /^(?:host\.(?:seed|json)|(?:devices|statev?2?)\.sqlite(?:-wal|-shm)?|admin\.sock|\.env(?:\..*)?|.+\.(?:dpapi|log|db|pem|key)|Local State|Cookies|lease(?:[-.].*)?\.json|[a-f0-9-]{36}\.json|\.t3(?:-iroh)?)$/.test(
          name,
        )
      )
        throw new Error("Payload contains runtime state.");
      if (stat.isDirectory()) visit(path);
      else {
        NodeAssert.ok(stat.isFile());
        files.push({
          path: NodePath.relative(root, path).split(NodePath.sep).join("/"),
          bytes: stat.size,
          sha256: hashFile(path, fs),
        });
      }
    }
  };
  visit(root);
  return files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

export function assertSameInventory(expected, actual) {
  NodeAssert.deepEqual(actual, expected, "Portable payload differs from the verified installer.");
}

export function findPayloadRoot(root) {
  const matches = [];
  const visit = (directory) => {
    if (
      NodeFS.existsSync(NodePath.join(directory, "T3 Code Iroh (Experimental).exe")) &&
      NodeFS.existsSync(NodePath.join(directory, "resources", "app.asar"))
    ) {
      matches.push(directory);
      return;
    }
    for (const name of NodeFS.readdirSync(directory)) {
      const path = NodePath.join(directory, name),
        stat = NodeFS.lstatSync(path);
      NodeAssert.equal(stat.isSymbolicLink(), false);
      if (stat.isDirectory()) visit(path);
    }
  };
  visit(root);
  if (matches.length > 1) throw new Error("Ambiguous extracted application roots.");
  return matches[0];
}

export function inventoryHash(files) {
  return NodeCrypto.createHash("sha256").update(JSON.stringify(files)).digest("hex");
}

export async function superviseProbe({
  executable,
  args,
  marker,
  env = process.env,
  expectFailure = false,
}) {
  const child = NodeChildProcess.spawn(executable, args, {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill();
  }, 60_000);
  child.stdout.on("data", (bytes) => process.stdout.write(bytes));
  child.stderr.on("data", (bytes) => process.stderr.write(bytes));
  const result = await new Promise((accept, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => accept({ code, signal, launcherPid: child.pid }));
  }).finally(() => clearTimeout(timer));
  if (timedOut) throw new Error("Portable probe timed out.");
  if (expectFailure) {
    if (result.code === null || result.code === 0 || result.signal !== null)
      throw new Error("Corrupted portable invocation unexpectedly succeeded or was interrupted.");
    NodeAssert.equal(NodeFS.existsSync(marker), false, "Failed invocation left a success marker.");
    return result;
  }
  if (result.code !== 0 || result.signal !== null)
    throw new Error(`Portable probe exit ${result.code}, signal ${result.signal}.`);
  if (!NodeFS.existsSync(marker)) throw new Error("Portable probe omitted its success marker.");
  const value = JSON.parse(NodeFS.readFileSync(marker, "utf8"));
  NodeAssert.equal(value.nativeProbe, "passed");
  return { ...result, marker: value };
}

export function portableProbeChild() {
  const [, , marker, baselinePath, mode] = process.argv;
  const baseline = JSON.parse(NodeFS.readFileSync(baselinePath, "utf8"));
  NodeAssert.equal(baseline.sourceCommit, PAYLOAD_SOURCE);
  const root = NodePath.dirname(process.execPath);
  const resources = NodePath.join(root, "resources");
  const probe = NodePath.join(
    resources,
    "app.asar",
    "apps/desktop/dist-electron",
    mode === "corrupt" ? "absent-portable-probe.cjs" : "nativeProbe.cjs",
  );
  const originalWrite = process.stdout.write.bind(process.stdout);
  const rawFS = NodeModule.createRequire(import.meta.url)("original-fs");
  let buffered = "";
  process.stdout.write = (chunk, encoding, callback) => {
    buffered += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    NodeAssert.ok(buffered.length <= 8192);
    let newline;
    while ((newline = buffered.indexOf("\n")) >= 0) {
      const line = buffered.slice(0, newline);
      buffered = buffered.slice(newline + 1);
      let value;
      try {
        value = JSON.parse(line);
      } catch {
        continue;
      }
      if (value.nativeProbe !== "passed") continue;
      NodeAssert.equal(value.pin, BINDING_PIN);
      NodeAssert.equal(value.patchSha256, PATCH_SHA256);
      // The bundled probe emits this only after native bind/close has completed.
      assertSameInventory(baseline.files, inventory(root, rawFS));
      const pkg = JSON.parse(
        NodeFS.readFileSync(NodePath.join(resources, "app.asar/package.json"), "utf8"),
      );
      NodeAssert.equal(pkg.t3codeCommitHash, PAYLOAD_SOURCE.slice(0, 12));
      NodeFS.writeFileSync(
        marker,
        JSON.stringify({
          ...value,
          sourceCommit: PAYLOAD_SOURCE,
          inventorySha256: inventoryHash(baseline.files),
          executable: process.execPath,
          portableExecutable: process.env.PORTABLE_EXECUTABLE_FILE,
        }),
        { flag: "wx", mode: 0o600 },
      );
    }
    return originalWrite(chunk, encoding, callback);
  };
  NodeModule.createRequire(probe)(probe);
}
