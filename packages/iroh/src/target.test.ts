import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import { bindingTarget } from "./target.ts";
NodeTest.test("native targets are explicit, Linux unchanged and Windows MSVC x64 only", () => {
  NodeAssert.equal(bindingTarget("linux", "x64").binary, "iroh.linux-x64-gnu.node");
  NodeAssert.equal(bindingTarget("win32", "x64").binary, "iroh.win32-x64-msvc.node");
  NodeAssert.equal(bindingTarget("win32", "x64").cargoTarget, "x86_64-pc-windows-msvc");
  NodeAssert.throws(() => bindingTarget("win32", "arm64"));
  NodeAssert.throws(() => bindingTarget("darwin", "x64"));
});
