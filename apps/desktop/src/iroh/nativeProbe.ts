import { loadNative, IROH_BINDING_PIN, IROH_BINDING_PATCH_SHA256 } from "@t3tools/iroh/native";

// This entry uses the desktop's CJS bundling and packaged dependency resolution
// without acquiring Electron UI services or creating a window.
async function probe() {
  const binding = loadNative();
  const relayOnly = binding.Endpoint.builder();
  relayOnly.applyMinimal();
  relayOnly.clearIpTransports();
  const builder = binding.Endpoint.builder();
  builder.applyMinimal();
  const endpoint = await builder.bind();
  try {
    if (endpoint.id().toBytes().length !== 32) throw new Error("Invalid endpoint identity.");
  } finally {
    await endpoint.close();
  }
  process.stdout.write(
    JSON.stringify({
      nativeProbe: "passed",
      pin: IROH_BINDING_PIN,
      patchSha256: IROH_BINDING_PATCH_SHA256,
    }) + "\n",
  );
}
void probe().catch(() => {
  process.stderr.write("Iroh packaged native probe failed.\n");
  process.exitCode = 1;
});
