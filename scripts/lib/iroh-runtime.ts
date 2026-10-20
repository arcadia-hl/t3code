// Native loaders must retain a real filesystem location after the application is bundled.
import * as NodeFSP from "node:fs/promises";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import { IROH_BINDING_PIN, IROH_BINDING_PATCH_SHA256 } from "../../packages/iroh/src/native.ts";

import { bindingTarget } from "../../packages/iroh/src/target.ts";

export async function stageIrohRuntime(input: {
  source: string;
  stage: string;
  platform: string;
  arch: string;
}): Promise<Record<string, string>> {
  if (input.platform !== "linux" && input.platform !== "win") return {};
  const platform = input.platform === "win" ? "win32" : "linux";
  const target = bindingTarget(platform, input.arch);
  const metadata = JSON.parse(
    await NodeFSP.readFile(NodePath.join(input.source, "build.json"), "utf8"),
  );
  const binary = target.binary;
  if (
    metadata.commit !== IROH_BINDING_PIN ||
    metadata.patchSha256 !== IROH_BINDING_PATCH_SHA256 ||
    metadata.platform !== platform ||
    metadata.arch !== input.arch ||
    metadata.binary !== binary
  )
    throw new Error(
      "Iroh binding pin or target mismatch. Build the reviewed source for the artifact target.",
    );
  const hash = (bytes: Buffer) => NodeCrypto.createHash("sha256").update(bytes).digest("hex");
  if (
    hash(await NodeFSP.readFile(NodePath.join(input.source, binary))) !== metadata.sha256 ||
    hash(await NodeFSP.readFile(NodePath.join(input.source, "upstream.patch"))) !==
      IROH_BINDING_PATCH_SHA256
  )
    throw new Error("Iroh binding integrity mismatch.");
  const directory = NodePath.join(input.stage, "iroh-binding");
  await NodeFSP.mkdir(directory, { recursive: true });
  for (const name of [
    binary,
    "index.cjs",
    "package.json",
    "build.json",
    "upstream.patch",
    "LICENSE-MIT",
    "LICENSE-APACHE",
  ])
    await NodeFSP.cp(NodePath.join(input.source, name), NodePath.join(directory, name), {
      errorOnExist: true,
      force: false,
    });
  return { "@t3tools/iroh-binding": "file:./iroh-binding" };
}
