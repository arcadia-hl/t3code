import * as NodeModule from "node:module";
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeURL from "node:url";
import * as NodeCrypto from "node:crypto";
import { validateRelayPolicy, type RelayPolicy, IROH_ALPN } from "./protocol.ts";
import { bindingTarget } from "./target.ts";
import type { Endpoint, EndpointAddr } from "./upstream.js";

export const IROH_BINDING_PIN = "3103bf5295be6d50c5272ff7a426e9b539f3f587";
export const IROH_BINDING_PATCH_SHA256 =
  "048145420bab2d23a32cbdd6983ddd0e12426f84f25f0eb47ffef1a3deab3f89";
type Binding = typeof import("./upstream.js");
let binding: Binding | undefined;
// oxlint-disable-next-line t3code/no-global-process-runtime -- The addon target must match the actual Node/Electron process.
const nativePlatform = process.platform;
// oxlint-disable-next-line t3code/no-global-process-runtime -- Native loading cannot use a simulated architecture.
const nativeArch = process.arch;

export function loadNative(): Binding {
  const target = bindingTarget(nativePlatform, nativeArch);
  if (binding) return binding;
  try {
    const require = NodeModule.createRequire(import.meta.url);
    let directory: string;
    try {
      directory = NodePath.dirname(require.resolve("@t3tools/iroh-binding/build.json"));
    } catch {
      directory = NodeURL.fileURLToPath(new URL("../binding/", import.meta.url));
    }
    const metadata = JSON.parse(
      NodeFS.readFileSync(NodePath.join(directory, "build.json"), "utf8"),
    );
    const expected = target.binary;
    if (
      metadata.commit !== IROH_BINDING_PIN ||
      metadata.platform !== nativePlatform ||
      metadata.arch !== nativeArch ||
      metadata.binary !== expected ||
      metadata.patchSha256 !== IROH_BINDING_PATCH_SHA256
    )
      throw new Error();
    const bytes = NodeFS.readFileSync(NodePath.join(directory, expected));
    if (NodeCrypto.createHash("sha256").update(bytes).digest("hex") !== metadata.sha256)
      throw new Error();
    binding = require(NodePath.join(directory, expected)) as Binding;
    return binding;
  } catch {
    throw new Error(
      "Patched Iroh binding unavailable. Run packages/iroh/build.mjs with Rust installed; published 1.1.0 is intentionally unsupported.",
    );
  }
}

export async function bindEndpoint(input: {
  readonly seed?: Uint8Array;
  readonly policy: RelayPolicy;
  readonly host?: boolean;
}): Promise<Endpoint> {
  validateRelayPolicy(input.policy);
  const native = loadNative();
  const builder = native.Endpoint.builder();
  // Private mode never installs the public discovery/relay preset.
  if (input.policy.mode === "private-only") builder.applyMinimal();
  else builder.applyN0();
  if (input.seed) builder.secretKey(Array.from(input.seed));
  builder.alpns([IROH_ALPN]);
  if (input.policy.relayOnly === true) builder.clearIpTransports();
  if (input.policy.mode !== "automatic" || input.policy.relays?.length) {
    const map = native.RelayMap.empty();
    for (const relay of input.policy.relays ?? [])
      map.insert({
        url: relay.url,
        ...(relay.authToken === undefined ? {} : { authToken: relay.authToken }),
      });
    builder.relayMode(native.RelayMode.custom(map));
  }
  return builder.bind();
}

export function peerAddress(
  hostId: string,
  relays: readonly string[],
  policy: RelayPolicy,
): EndpointAddr {
  validateRelayPolicy(policy, relays);
  const native = loadNative();
  return new native.EndpointAddr(native.EndpointId.fromString(hostId), relays[0]);
}
