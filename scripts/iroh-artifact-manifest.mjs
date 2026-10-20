import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import * as NodeChildProcess from "node:child_process";
const directory = NodePath.resolve(process.argv[2]);
const sourceCommit = NodeChildProcess.execFileSync("git", ["rev-parse", "HEAD"], {
  encoding: "utf8",
}).trim();
const binding = JSON.parse(
  NodeFS.readFileSync(new URL("../packages/iroh/binding/build.json", import.meta.url)),
);
const artifacts = NodeFS.readdirSync(directory)
  .filter((name) => /\.(exe|zip|AppImage|tar\.gz)$/.test(name))
  .map((name) => {
    const bytes = NodeFS.readFileSync(NodePath.join(directory, name));
    return {
      name,
      bytes: bytes.length,
      sha256: NodeCrypto.createHash("sha256").update(bytes).digest("hex"),
    };
  });
if (!artifacts.length) throw new Error("No completed artifacts found.");
NodeFS.writeFileSync(
  NodePath.join(directory, "manifest.json"),
  JSON.stringify(
    {
      sourceCommit,
      binding,
      artifacts,
      verification: {
        unsigned: true,
        nativeRegressions:
          "See successful runner steps; this manifest alone does not prove a test passed.",
        twoHost: "pending",
        installedDesktop: "pending",
      },
    },
    null,
    2,
  ),
);
NodeFS.writeFileSync(
  NodePath.join(directory, "README.txt"),
  `T3 Code Iroh — unsigned experimental test build\nSource: ${sourceCommit}\nNative Iroh: ${binding.commit}; reviewed patch SHA256 ${binding.patchSha256}\n\nUse a separate experimental app/home. Automatic update feeds are disabled.\nThe Iroh host is Linux-only. Windows x64 supports the desktop client route.\nIn Settings > Connections, add a remote host and paste the one-time t3-iroh link\ninto Host. Read access is the default; command access requires matching invitation\nand local host approval. Verify the pending device ID on the Linux host.\nWindows protects the complete profile with Electron safeStorage (no plaintext\nfallback); do not copy Linux profile files to Windows. Removing a connection\nforgets its profile and closes gateways; revoke-device on the host revokes access.\nCustom/private relay enrollment is currently Linux CLI only.\n\nNot acceptance-proven: Windows installed GUI, Windows-to-Linux/two-machine and\ncross-NAT operation, mobile/macOS/browser Iroh, private relay deployment, media\nplayback/WebRTC and server browser previews. Windows Iroh hosting is unsupported.\nNo bundled WSL runtime. No signing. No cloud discovery, account sync, webhooks,\noffline access or push parity with Connect. Signed asset URLs may remain valid\nup to one hour through another reachable route after device revocation.\nSee manifest and build-run logs for checks actually executed; packaging is not\nan installed-desktop or cross-OS acceptance result.\n`,
);
