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
  "stages the verified Linux loader, patch, binary and notices as a local dependency",
  async (t) => {
    const stage = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-iroh-stage-real-"));
    t.after(() => NodeFS.rmSync(stage, { recursive: true, force: true }));
    const source = new URL("../../packages/iroh/binding/", import.meta.url).pathname;
    const dependencies = await stageIrohRuntime({
      source,
      stage,
      platform: "linux",
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
