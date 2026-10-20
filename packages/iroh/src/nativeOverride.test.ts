import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as NodeChildProcess from "node:child_process";
import * as NodeFS from "node:fs";
import * as NodeOS from "node:os";
import * as NodePath from "node:path";

NodeTest.test("native environment override cannot replace the verified pinned addon", (t) => {
  const root = NodeFS.mkdtempSync(NodePath.join(NodeOS.tmpdir(), "t3-iroh-override-"));
  t.after(() => NodeFS.rmSync(root, { recursive: true, force: true }));
  const other = NodePath.join(root, "other.cjs");
  NodeFS.writeFileSync(other, "module.exports = {};\n");
  const script = `import {loadNative} from ${JSON.stringify(new URL("./native.ts", import.meta.url).href)}; const binding=loadNative(); if(typeof binding.Endpoint?.builder !== 'function') process.exit(3);`;
  const result = NodeChildProcess.spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    {
      env: {
        ELECTRON_RUN_AS_NODE: "1",
        PATH: process.env.PATH,
        NAPI_RS_NATIVE_LIBRARY_PATH: other,
        NAPI_RS_FORCE_WASI: "error",
      },
      encoding: "utf8",
    },
  );
  NodeAssert.equal(result.status, 0, result.stderr);
});
