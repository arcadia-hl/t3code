import * as NodeChildProcess from "node:child_process";
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import * as NodeURL from "node:url";

export async function runStorageProbe({ executable, script, temporaryParent = NodeOS.tmpdir() }) {
  const root = NodeFS.mkdtempSync(NodePath.join(temporaryParent, "t3-iroh-dpapi-"));
  try {
    const child = NodeChildProcess.spawn(executable, [script, "--iroh-probe-root", root], {
      env: { ...process.env, ELECTRON_RUN_AS_NODE: undefined },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, 30_000);
    const collect = (bytes) => {
      const text = bytes.toString();
      output = (output + text).slice(-8192);
      process.stdout.write(text);
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    const result = await new Promise((accept, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => accept({ code, signal }));
    }).finally(() => clearTimeout(timeout));
    if (timedOut) throw new Error("Windows safeStorage probe timed out.");
    if (result.code !== 0)
      throw new Error(`Windows safeStorage probe exit ${result.code}, signal ${result.signal}.`);
    if (
      !output.includes("Windows safeStorage profile probe passed.") ||
      output.includes("Windows safeStorage profile probe failed.")
    )
      throw new Error("Windows safeStorage probe did not supply a successful assertion marker.");
  } finally {
    // Chromium retains Local State handles until Electron exits, even without a window.
    NodeFS.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}

if (
  process.argv[1] &&
  NodeURL.pathToFileURL(NodePath.resolve(process.argv[1])).href === import.meta.url
) {
  try {
    await runStorageProbe({
      executable: NodePath.resolve("apps/desktop/node_modules/electron/dist/electron.exe"),
      script: NodePath.resolve("apps/desktop/dist-electron/safeStorageProbe.cjs"),
    });
    process.stdout.write("Windows safeStorage process exit and fixture cleanup passed.\n");
  } catch (error) {
    process.stderr.write(
      `${error instanceof Error ? error.message : "Windows storage probe failed."}\n`,
    );
    process.exitCode = 1;
  }
}
