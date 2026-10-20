import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import * as Option from "effect/Option";
import { resolveDesktopBaseDir } from "../app/DesktopStatePaths.ts";

NodeTest.test(
  "experimental fork defaults to a separate T3 home while honoring explicit isolated homes",
  () => {
    NodeAssert.equal(
      resolveDesktopBaseDir({
        homeDirectory: "/home/test",
        joinPath: (...parts) => parts.join("/"),
        t3Home: Option.none(),
      }),
      "/home/test/.t3-iroh",
    );
    NodeAssert.equal(
      resolveDesktopBaseDir({
        homeDirectory: "/home/test",
        joinPath: (...parts) => parts.join("/"),
        t3Home: Option.some("/private/test"),
      }),
      "/private/test",
    );
  },
);
