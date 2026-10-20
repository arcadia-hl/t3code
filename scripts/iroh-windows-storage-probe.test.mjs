import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";
import { runStorageProbe } from "./iroh-windows-storage-probe.mjs";

async function fixture(source, run) {
  const parent = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-iroh-probe-test-"));
  const script = NodePath.join(parent, "child.cjs");
  NodeFS.writeFileSync(script, source);
  try {
    await run({ executable: process.execPath, script, temporaryParent: parent });
    NodeAssert.deepEqual(NodeFS.readdirSync(parent), ["child.cjs"]);
  } finally {
    NodeFS.rmSync(parent, { recursive: true, force: true });
  }
}

NodeTest.test(
  "storage probe waits for the child and removes its fixtures after successful exit",
  async () => {
    await fixture(
      `const fs = require('node:fs');
const root = process.argv.at(-1);
fs.writeFileSync(root + '/owned-fixture', 'private');
process.on('exit', () => {
  if (!fs.existsSync(root + '/owned-fixture')) process.exitCode = 2;
});
console.log('Windows safeStorage profile probe passed.');`,
      runStorageProbe,
    );
  },
);

NodeTest.test(
  "a passed assertion marker followed by nonzero process exit fails acceptance",
  async () => {
    await fixture(
      `console.log('Windows safeStorage profile probe passed.');process.exitCode=1;`,
      async (input) => {
        await NodeAssert.rejects(runStorageProbe(input), /exit 1/);
      },
    );
  },
);

NodeTest.test("zero process exit without the assertion marker fails acceptance", async () => {
  await fixture(`process.exitCode=0;`, async (input) => {
    await NodeAssert.rejects(runStorageProbe(input), /assertion marker/);
  });
});

NodeTest.test("spawn failure removes owned fixtures and fails acceptance", async () => {
  await fixture("", async (input) => {
    await NodeAssert.rejects(
      runStorageProbe({
        ...input,
        executable: NodePath.join(input.temporaryParent, "absent-executable"),
      }),
    );
  });
});
