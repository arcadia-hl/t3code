import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeModule from "node:module";
import * as NodeChildProcess from "node:child_process";
import * as NodeURL from "node:url";
import * as NodeAssert from "node:assert/strict";
import {
  PAYLOAD_SOURCE,
  INSTALLER_SHA256,
  INSTALLER_BYTES,
  BINDING_PIN,
  PATCH_SHA256,
  hashFile,
  inventory,
  inventoryHash,
  assertSameInventory,
  findPayloadRoot,
  superviseProbe,
} from "./iroh-portable.mjs";

const [workspaceArgument, installerArgument, toolsArgument] = process.argv.slice(2);
const workspace = NodePath.resolve(workspaceArgument),
  installer = NodePath.resolve(installerArgument),
  tools = NodePath.resolve(toolsArgument);
NodeFS.mkdirSync(workspace, { recursive: true });
NodeAssert.equal(NodeFS.statSync(installer).size, INSTALLER_BYTES);
NodeAssert.equal(hashFile(installer), INSTALLER_SHA256, "Wrong source installer.");
const require = NodeModule.createRequire(NodePath.join(tools, "package.json"));
NodeAssert.equal(require("electron-builder/package.json").version, "26.15.6");
const sevenzip = await require("app-builder-lib/out/toolsets/7zip").getPath7za();
// Builder's minimal 7za reads embedded 7z streams, but not direct-file NSIS containers.
const extractor = NodePath.join(process.env.ProgramFiles, "7-Zip", "7z.exe");
NodeAssert.ok(NodeFS.existsSync(extractor), "Native Windows verifier requires full 7-Zip.");
const commands = NodePath.join(workspace, "commands.jsonl");
function run(executable, args, cwd = workspace) {
  console.log(JSON.stringify({ command: executable, args }));
  const result = NodeChildProcess.spawnSync(executable, args, { cwd, stdio: "inherit" });
  NodeFS.appendFileSync(
    commands,
    JSON.stringify({
      executable,
      args,
      pid: result.pid,
      code: result.status,
      signal: result.signal,
    }) + "\n",
  );
  NodeAssert.equal(result.status, 0);
  NodeAssert.equal(result.signal, null);
}
function embeddedArchive(root) {
  const matches = [];
  const visit = (directory) => {
    for (const name of NodeFS.readdirSync(directory)) {
      const path = NodePath.join(directory, name);
      if (NodeFS.statSync(path).isDirectory()) visit(path);
      else if (name === "app-64.7z") matches.push(path);
    }
  };
  visit(root);
  NodeAssert.equal(matches.length, 1);
  return matches[0];
}
function extract(exe, label) {
  const wrapper = NodePath.join(workspace, label + "-wrapper"),
    payload = NodePath.join(workspace, label + "-payload");
  run(extractor, ["x", "-y", "-o" + wrapper, exe]);
  const direct = findPayloadRoot(wrapper);
  if (direct !== undefined) return direct;
  run(extractor, ["x", "-y", "-o" + payload, embeddedArchive(wrapper)]);
  const extracted = findPayloadRoot(payload);
  NodeAssert.ok(extracted, "Embedded archive did not contain the application.");
  return extracted;
}
function unsignedPE(file, expectedMachine) {
  const bytes = Buffer.alloc(4096),
    fd = NodeFS.openSync(file, "r");
  try {
    NodeFS.readSync(fd, bytes, 0, bytes.length, 0);
  } finally {
    NodeFS.closeSync(fd);
  }
  NodeAssert.equal(bytes.toString("ascii", 0, 2), "MZ");
  const pe = bytes.readUInt32LE(0x3c),
    machine = bytes.readUInt16LE(pe + 4),
    optional = pe + 24,
    magic = bytes.readUInt16LE(optional);
  NodeAssert.equal(bytes.readUInt32LE(pe), 0x4550);
  if (expectedMachine !== undefined) NodeAssert.equal(machine, expectedMachine);
  NodeAssert.ok(magic === 0x10b || magic === 0x20b);
  const certificate = optional + (magic === 0x10b ? 96 : 112) + 4 * 8;
  NodeAssert.equal(bytes.readUInt32LE(certificate), 0);
  NodeAssert.equal(bytes.readUInt32LE(certificate + 4), 0);
  return {
    machine: "0x" + machine.toString(16),
    magic: "0x" + magic.toString(16),
    authenticodeCertificate: "absent",
  };
}
const payload = extract(installer, "installer"),
  files = inventory(payload);
NodeAssert.equal(files.length, 55);
const baseline = { sourceCommit: PAYLOAD_SOURCE, files },
  baselinePath = NodePath.join(workspace, "baseline.json");
NodeFS.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2));
const project = NodePath.join(workspace, "project"),
  output = NodePath.join(workspace, "artifacts");
NodeFS.mkdirSync(project, { recursive: true });
NodeFS.mkdirSync(output, { recursive: true });
NodeFS.writeFileSync(
  NodePath.join(project, "package.json"),
  JSON.stringify({
    name: "t3-code-iroh-portable",
    version: "0.1.0-preview.20261020.2",
    description: "Experimental T3 Code Iroh portable wrapper",
    author: "Hermes",
    private: true,
  }),
);
const artifactName = "T3-Code-Iroh-0.1.0-preview.20261020.2-x64-portable.exe";
const config = {
  appId: "soy.hermes.t3code.iroh",
  productName: "T3 Code Iroh (Experimental)",
  electronVersion: "44.4.5",
  artifactName,
  publish: null,
  npmRebuild: false,
  nodeGypRebuild: false,
  directories: { output },
  win: { target: ["portable"], signAndEditExecutable: false },
  portable: {
    // In builder26.15.6 true omits UNPACK_DIR_NAME, selecting per-launch $PLUGINSDIR.
    unpackDirName: true,
    requestExecutionLevel: "user",
    // Direct-file mode bypasses the archive helper that copies elevate.exe.
    useZip: true,
  },
};
const configPath = NodePath.join(workspace, "portable-config.json");
NodeFS.writeFileSync(configPath, JSON.stringify(config, null, 2));
run(process.execPath, [
  require.resolve("electron-builder/cli.js"),
  "--projectDir",
  project,
  "--config",
  configPath,
  "--win",
  "portable",
  "--x64",
  "--prepackaged",
  payload,
  "--publish",
  "never",
]);
assertSameInventory(files, inventory(payload));
const executable = NodePath.join(output, artifactName);
const portablePayload = extract(executable, "portable");
assertSameInventory(files, inventory(portablePayload));
const wrapperPE = unsignedPE(executable),
  appPE = unsignedPE(NodePath.join(portablePayload, "T3 Code Iroh (Experimental).exe"), 0x8664);
const helper = NodeURL.fileURLToPath(new URL("./iroh-portable.mjs", import.meta.url));
const code =
  "import(require('node:url').pathToFileURL(process.argv[1]).href).then(m=>m.portableProbeChild())";
const probes = [];
for (const mode of ["normal", "normal", "corrupt"]) {
  const fixture = NodeFS.mkdtempSync(NodePath.join(workspace, "probe-")),
    marker = NodePath.join(fixture, "success marker.json");
  try {
    const result = await superviseProbe({
      executable,
      args: ["-e", code, helper, marker, baselinePath, mode],
      marker,
      env: { ...process.env, ELECTRON_RUN_AS_NODE: "1", TEMP: fixture, TMP: fixture },
      expectFailure: mode === "corrupt",
    });
    if (mode !== "corrupt") {
      NodeAssert.equal(result.marker.sourceCommit, PAYLOAD_SOURCE);
      NodeAssert.equal(result.marker.inventorySha256, inventoryHash(files));
      NodeAssert.equal(result.marker.portableExecutable.toLowerCase(), executable.toLowerCase());
      const extracted = NodePath.dirname(result.marker.executable);
      NodeAssert.ok(!NodePath.relative(fixture, extracted).startsWith(".."));
      NodeAssert.equal(
        NodeFS.existsSync(extracted),
        false,
        "Portable runtime survived launcher close.",
      );
    }
    probes.push({ mode, ...result });
  } finally {
    NodeFS.rmSync(fixture, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}
NodeAssert.notEqual(
  NodePath.dirname(probes[0].marker.executable),
  NodePath.dirname(probes[1].marker.executable),
  "Portable extraction directory must be unique per launch.",
);
NodeAssert.equal(hashFile(installer), INSTALLER_SHA256);
const packagingCommit = NodeChildProcess.execFileSync("git", ["rev-parse", "HEAD"], {
  encoding: "utf8",
}).trim();
const manifest = {
  payloadSourceCommit: PAYLOAD_SOURCE,
  packagingCommit,
  runId: process.env.GITHUB_RUN_ID,
  installer: {
    sha256: INSTALLER_SHA256,
    bytes: INSTALLER_BYTES,
    unchanged: true,
    sourceRun: 39518025945,
  },
  binding: {
    pin: BINDING_PIN,
    patchSha256: PATCH_SHA256,
    evidence: "reused exact verified installer payload; no native rebuild",
  },
  artifact: {
    name: artifactName,
    bytes: NodeFS.statSync(executable).size,
    sha256: hashFile(executable),
  },
  tooling: {
    electronBuilder: "26.15.6",
    sevenzip: "checksum-pinned builder toolset7zip@1.0.0",
    minimalSevenzipSha256: hashFile(sevenzip),
    verifier: {
      path: extractor,
      sha256: hashFile(extractor),
      dllSha256: hashFile(NodePath.join(NodePath.dirname(extractor), "7z.dll")),
      version: NodeChildProcess.execFileSync(extractor, ["i"], { encoding: "utf8" })
        .split("\n")
        .slice(0, 4)
        .join("\n"),
    },
  },
  verification: {
    physicalFiles: files.length,
    payloadInventorySha256: inventoryHash(files),
    payloadByteEquality:
      "all55 files match installer before/after packaging, extracted archive and live launcher runtime",
    wrapperPE,
    appPE,
    probes,
    unchangedPayloadTests: "reused source run39518025945 Node39/Electron25/DPAPI/ASAR; not rerun",
    GUI: "not run",
    WindowsToLinux: "not run",
    twoHost: "deferred",
  },
};
NodeFS.writeFileSync(
  NodePath.join(output, "portable-manifest.json"),
  JSON.stringify(manifest, null, 2),
);
NodeFS.writeFileSync(
  NodePath.join(output, "portable-payload-inventory.json"),
  JSON.stringify(baseline, null, 2),
);
NodeFS.writeFileSync(
  NodePath.join(output, "PORTABLE-SHA256SUMS"),
  manifest.artifact.sha256 + "  " + artifactName + "\n",
);
NodeFS.writeFileSync(
  NodePath.join(output, "PORTABLE-README.txt"),
  [
    "T3 Code Iroh unsigned experimental Windows x64 portable",
    "Payload source: " + PAYLOAD_SOURCE,
    "Packaging source: " + packagingCommit,
    "",
    "Launch " +
      artifactName +
      " without an installer. It self-extracts into a unique temporary directory, waits for the app, then removes that runtime. The wrapper requests user privileges and adds no installer shortcuts or protocol associations. The unchanged app retains its existing startup behavior.",
    "",
    "Portable means installerless, not a USB-migratable profile. Existing per-user storage remains external to this EXE, including Windows %APPDATA% Chromium/DPAPI state and the .t3-iroh data home. Device profiles remain DPAPI/user/profile/machine bound; do not copy decrypted profiles or Linux records. safeStorage protections and disabled updater remain unchanged. Windows Iroh client only; hosting unsupported. Keep the existing NSIS installer as fallback.",
    "",
    "Verified on native Windows without GUI: actual launcher argument forwarding, packaged async native bind/close, every extracted payload file hash, real process exit, unique temp paths, cleanup after exit, and corrupted invocation denial. Prior application/native/DPAPI tests are reused byte-identical payload evidence, not new runs. Installed GUI, Windows-to-Linux and two-host/cross-NAT acceptance remain unperformed. Media/preview/private-relay gaps remain as documented for source57ef. No signing or auto-update feed.",
    "",
  ].join("\n"),
);
console.log(
  JSON.stringify({
    portable: "passed",
    payloadSourceCommit: PAYLOAD_SOURCE,
    packagingCommit,
    artifact: manifest.artifact,
  }),
);
