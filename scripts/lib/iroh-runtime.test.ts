import * as NodeURL from "node:url";
import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeOS from "node:os";
import { stageIrohRuntime } from "./iroh-runtime.ts";

NodeTest.test("Linux staging fails closed on missing or mismatched native build", async (t) => {
  const root = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-iroh-stage-"));
  t.after(() => NodeFS.rmSync(root, { recursive: true, force: true }));
  const source = NodePath.join(root, "source"),
    stage = NodePath.join(root, "stage");
  NodeFS.mkdirSync(source);
  NodeFS.mkdirSync(stage);
  await NodeAssert.rejects(stageIrohRuntime({ source, stage, platform: "linux", arch: "x64" }));
  NodeFS.writeFileSync(
    NodePath.join(source, "build.json"),
    JSON.stringify({ commit: "wrong", platform: "linux", arch: "x64" }),
  );
  await NodeAssert.rejects(stageIrohRuntime({ source, stage, platform: "linux", arch: "x64" }));
  NodeAssert.deepEqual(
    await stageIrohRuntime({ source, stage, platform: "mac", arch: "arm64" }),
    {},
  );
});

NodeTest.test(
  "stages the verified native loader, patch, binary and notices as a local dependency",
  async (t) => {
    const stage = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-iroh-stage-real-"));
    t.after(() => NodeFS.rmSync(stage, { recursive: true, force: true }));
    const source = NodeURL.fileURLToPath(new URL("../../packages/iroh/binding/", import.meta.url));
    const dependencies = await stageIrohRuntime({
      source,
      stage,
      // oxlint-disable-next-line t3code/no-global-process-runtime -- Stage the binding built on this runner.
      platform: process.platform === "win32" ? "win" : "linux",
      // oxlint-disable-next-line t3code/no-global-process-runtime -- This integration test stages the addon built for the current runner.
      arch: process.arch,
    });
    NodeAssert.deepEqual(dependencies, { "@t3tools/iroh-binding": "file:./iroh-binding" });
    const metadata = JSON.parse(
      NodeFS.readFileSync(NodePath.join(stage, "iroh-binding/build.json"), "utf8"),
    );
    NodeAssert.ok(
      NodeFS.readFileSync(NodePath.join(stage, "iroh-binding", metadata.binary)).length > 0,
    );
    NodeAssert.ok(
      NodeFS.readFileSync(NodePath.join(stage, "iroh-binding/LICENSE-APACHE")).length > 0,
    );
    NodeAssert.equal(
      JSON.parse(NodeFS.readFileSync(NodePath.join(stage, "iroh-binding/package.json"), "utf8"))
        .name,
      "@t3tools/iroh-binding",
    );
  },
);

NodeTest.test(
  "Windows packaging refuses an absent or Linux binding rather than omitting transport",
  async (t) => {
    const stage = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-iroh-win-stage-"));
    t.after(() => NodeFS.rmSync(stage, { recursive: true, force: true }));
    const absent = NodePath.join(stage, "absent");
    await NodeAssert.rejects(
      stageIrohRuntime({ source: absent, stage, platform: "win", arch: "x64" }),
    );
    const source = NodeURL.fileURLToPath(new URL("../../packages/iroh/binding/", import.meta.url));
    // oxlint-disable-next-line t3code/no-global-process-runtime -- Compare the runner's actual addon with the opposite artifact target.
    const opposite = process.platform === "win32" ? "linux" : "win";
    await NodeAssert.rejects(stageIrohRuntime({ source, stage, platform: opposite, arch: "x64" }));
  },
);
