import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeOS from "node:os";
import {
  inventory,
  assertSameInventory,
  superviseProbe,
  findPayloadRoot,
} from "./iroh-portable.mjs";

async function fixture(run) {
  const root = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "iroh-portable-test-"));
  try {
    await run(root);
  } finally {
    NodeFS.rmSync(root, { recursive: true, force: true });
  }
}

NodeTest.test("finds the app in direct or nested 7zip output", async () => {
  await fixture(async (root) => {
    NodeAssert.equal(findPayloadRoot(root), undefined);
    const app = NodePath.join(root, "nested", "app");
    NodeFS.mkdirSync(NodePath.join(app, "resources"), { recursive: true });
    NodeFS.writeFileSync(NodePath.join(app, "resources", "app.asar"), "archive");
    NodeFS.writeFileSync(NodePath.join(app, "T3 Code Iroh (Experimental).exe"), "app");
    NodeAssert.equal(findPayloadRoot(root), app);
    NodeAssert.equal(findPayloadRoot(app), app);
  });
});

NodeTest.test("ambiguous extracted application roots are rejected", async () => {
  await fixture(async (root) => {
    for (const name of ["first", "second"]) {
      const app = NodePath.join(root, name);
      NodeFS.mkdirSync(NodePath.join(app, "resources"), { recursive: true });
      NodeFS.writeFileSync(NodePath.join(app, "resources", "app.asar"), "archive");
      NodeFS.writeFileSync(NodePath.join(app, "T3 Code Iroh (Experimental).exe"), "app");
    }
    NodeAssert.throws(() => findPayloadRoot(root), /Ambiguous/);
  });
});

NodeTest.test("payload comparison rejects changed, missing and additional files", async () => {
  await fixture(async (root) => {
    const original = NodePath.join(root, "original"),
      copy = NodePath.join(root, "copy");
    NodeFS.mkdirSync(original);
    NodeFS.writeFileSync(NodePath.join(original, "app.asar"), "tested app");
    const expected = inventory(original);
    NodeFS.cpSync(original, copy, { recursive: true });
    assertSameInventory(expected, inventory(copy));
    NodeFS.writeFileSync(NodePath.join(copy, "app.asar"), "changed app");
    NodeAssert.throws(() => assertSameInventory(expected, inventory(copy)));
    NodeFS.rmSync(NodePath.join(copy, "app.asar"));
    NodeAssert.throws(() => assertSameInventory(expected, inventory(copy)));
    NodeFS.writeFileSync(NodePath.join(copy, "app.asar"), "tested app");
    NodeFS.writeFileSync(NodePath.join(copy, "unexpected"), "extra");
    NodeAssert.throws(() => assertSameInventory(expected, inventory(copy)));
  });
});

NodeTest.test("payload inventory rejects runtime credential files", async () => {
  await fixture(async (root) => {
    NodeFS.writeFileSync(NodePath.join(root, "device.dpapi"), "fixture");
    NodeAssert.throws(() => inventory(root), /runtime state/);
  });
});

async function processFixture(source, run) {
  await fixture(async (root) => {
    const script = NodePath.join(root, "child.cjs"),
      marker = NodePath.join(root, "marker.json");
    NodeFS.writeFileSync(script, source);
    await run({ executable: process.execPath, args: [script, marker], marker });
  });
}

NodeTest.test("probe acceptance awaits actual process close and successful marker", async () => {
  await processFixture(
    `require('node:fs').writeFileSync(process.argv[2],JSON.stringify({nativeProbe:'passed'}));`,
    async (input) => {
      const result = await superviseProbe(input);
      NodeAssert.equal(result.code, 0);
      NodeAssert.equal(result.marker.nativeProbe, "passed");
    },
  );
});

NodeTest.test("success marker followed by nonzero exit is rejected", async () => {
  await processFixture(
    `require('node:fs').writeFileSync(process.argv[2],JSON.stringify({nativeProbe:'passed'}));process.exitCode=1;`,
    async (input) => {
      await NodeAssert.rejects(superviseProbe(input), /exit 1/);
    },
  );
});

NodeTest.test("zero exit without success marker is rejected", async () => {
  await processFixture(`process.exitCode=0;`, async (input) => {
    await NodeAssert.rejects(superviseProbe(input), /marker/);
  });
});

NodeTest.test(
  "corrupted invocation must actually fail and cannot leave a success marker",
  async () => {
    await processFixture(`process.exitCode=3;`, async (input) => {
      const result = await superviseProbe({ ...input, expectFailure: true });
      NodeAssert.equal(result.code, 3);
    });
    await processFixture(`process.exitCode=0;`, async (input) => {
      await NodeAssert.rejects(
        superviseProbe({ ...input, expectFailure: true }),
        /unexpectedly succeeded/,
      );
    });
  },
);
