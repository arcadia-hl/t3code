// @effect-diagnostics nodeBuiltinImport:off -- CLI boundary fixture owns its private temporary state and simulates the actual platform guard.
import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import { runIrohCli } from "./cli.ts";

NodeTest.test("Windows Iroh hosting fails explicitly before writing host state", async (t) => {
  const root = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-iroh-cli-platform-"));
  t.after(() => NodeFS.rmSync(root, { recursive: true, force: true }));
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  let result: Promise<void>;
  try {
    Object.defineProperty(process, "platform", { ...platform, value: "win32" });
    result = runIrohCli(["enable", "--state-dir", root]);
  } finally {
    Object.defineProperty(process, "platform", platform);
  }
  await NodeAssert.rejects(result, /Iroh hosting and headless pairing require Linux/);
  NodeAssert.equal(NodeFS.existsSync(NodePath.join(root, "iroh")), false);
});
