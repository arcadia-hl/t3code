import * as NodeModule from "node:module";
import { loadNative } from "../packages/iroh/src/native.ts";
loadNative();
const target = new URL("../packages/iroh/binding/index.cjs", import.meta.url).href;
NodeModule.registerHooks({
  resolve(specifier, context, next) {
    return specifier === "@number0/iroh"
      ? { url: target, shortCircuit: true }
      : next(specifier, context);
  },
});
