import * as NodeChildProcess from "node:child_process";
import * as NodeFS from "node:fs";
import * as NodeCrypto from "node:crypto";
import * as NodePath from "node:path";
import * as NodeURL from "node:url";

import { bindingTarget } from "./src/target.ts";
import { IROH_BINDING_PATCH_SHA256 } from "./src/native.ts";

// oxlint-disable-next-line t3code/no-global-process-runtime -- Build only for the actual host; cross-target mapping requires a native Windows runner.
const nativePlatform = process.platform;
// oxlint-disable-next-line t3code/no-global-process-runtime -- The emitted addon metadata describes the actual build architecture.
const nativeArch = process.arch;
const pin = "3103bf5295be6d50c5272ff7a426e9b539f3f587";
const root = NodeURL.fileURLToPath(new URL("../../", import.meta.url));
const source = process.argv[2]
  ? NodePath.resolve(process.argv[2])
  : NodePath.join(root, ".generated/iroh-ffi");
function run(command, args, cwd = root) {
  const result = NodeChildProcess.spawnSync(command, args, { cwd, stdio: "inherit" });
  if (result.error || result.status !== 0)
    throw new Error(
      `Build command failed: ${command} (exit ${result.status ?? result.error?.code})`,
    );
}
const target = bindingTarget(nativePlatform, nativeArch);
if (!process.argv[2]) {
  NodeFS.mkdirSync(NodePath.join(root, ".generated"), { recursive: true });
  run("git", ["-c", "core.autocrlf=false", "clone", "https://github.com/n0-computer/iroh-ffi.git", source]);
  run("git", ["checkout", "--detach", pin], source);
}
const rev = NodeChildProcess.spawnSync("git", ["rev-parse", "HEAD"], {
  cwd: source,
  encoding: "utf8",
});
if (rev.status !== 0 || rev.stdout.trim() !== pin) throw new Error("Iroh source pin mismatch.");
const patch = NodeFS.readFileSync(new URL("./patches/relay-only.patch", import.meta.url));
const patchSha256 = NodeCrypto.createHash("sha256").update(patch).digest("hex");
if (patchSha256 !== IROH_BINDING_PATCH_SHA256)
  throw new Error("Reviewed local patch hash mismatch.");
const changes = NodeChildProcess.spawnSync("git", ["diff", "--binary", pin], {
  cwd: source,
  encoding: "utf8",
});
if (changes.status !== 0) throw new Error("Cannot inspect Iroh source changes.");
if (changes.stdout.length === 0)
  run(
    "git",
    ["apply", NodeURL.fileURLToPath(new URL("./patches/relay-only.patch", import.meta.url))],
    source,
  );
else if (changes.stdout !== patch.toString("utf8"))
  throw new Error("Iroh source has changes beyond the pinned relay-only patch.");
// Cargo.lock is the reviewed upstream lock. No published 1.1.0 binary is accepted.
run(
  "cargo",
  [
    "build",
    "--locked",
    "--release",
    "--package",
    "number0_iroh",
    ...(target.cargoTarget ? ["--target", target.cargoTarget] : []),
  ],
  source,
);
const binding = NodeURL.fileURLToPath(new URL("./binding/", import.meta.url));
NodeFS.mkdirSync(binding, { recursive: true });
NodeFS.writeFileSync(
  NodePath.join(binding, "package.json"),
  JSON.stringify({
    name: "@t3tools/iroh-binding",
    version: "0.0.0",
    private: true,
    main: "./index.cjs",
    exports: { ".": "./index.cjs", "./build.json": "./build.json" },
  }),
);
NodeFS.copyFileSync(
  new URL("./patches/relay-only.patch", import.meta.url),
  NodePath.join(binding, "upstream.patch"),
);
const binary = target.binary;
NodeFS.copyFileSync(
  NodePath.join(
    process.env.CARGO_TARGET_DIR
      ? NodePath.resolve(source, process.env.CARGO_TARGET_DIR)
      : NodePath.join(source, "target"),
    ...(target.cargoTarget ? [target.cargoTarget] : []),
    "release",
    target.library,
  ),
  NodePath.join(binding, binary),
);
NodeFS.writeFileSync(
  NodePath.join(binding, "index.cjs"),
  [
    "// Pinned local N-API binding. No environment override or registry fallback.",
    `module.exports = require(${JSON.stringify(`./${binary}`)});`,
    "",
  ].join("\n"),
);
for (const name of ["LICENSE-MIT", "LICENSE-APACHE"])
  NodeFS.copyFileSync(NodePath.join(source, name), NodePath.join(binding, name));
const sha256 = NodeCrypto.createHash("sha256")
  .update(NodeFS.readFileSync(NodePath.join(binding, binary)))
  .digest("hex");
NodeFS.writeFileSync(
  NodePath.join(binding, "build.json"),
  JSON.stringify(
    {
      source: "https://github.com/n0-computer/iroh-ffi",
      commit: pin,
      binary,
      sha256,
      platform: nativePlatform,
      arch: nativeArch,
      patchSha256,
    },
    null,
    2,
  ),
);
console.log(
  `Built patched Iroh ${pin} for ${nativePlatform} ${nativeArch}. Run the upstream stream/watcher regressions before use.`,
);
