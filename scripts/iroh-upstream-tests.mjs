import * as NodeModule from "node:module";
import { loadNative } from "../packages/iroh/src/native.ts";
loadNative();
const target = new URL("../packages/iroh/binding/index.cjs", import.meta.url).href;
const upstreamIndex = new URL("../.generated/iroh-ffi/iroh-js/index.js", import.meta.url).href;
NodeModule.registerHooks({
  resolve(specifier, context, next) {
    const pinnedUpstreamRelativeImport =
      specifier === "../index.js" &&
      context.parentURL !== undefined &&
      new URL(specifier, context.parentURL).href === upstreamIndex;
    return specifier === "@number0/iroh" || pinnedUpstreamRelativeImport
      ? { url: target, shortCircuit: true }
      : next(specifier, context);
  },
});
