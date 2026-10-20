// @effect-diagnostics nodeBuiltinImport:off -- CLI adapter uses a private Unix socket and the native owner-only filesystem boundary.
// CLI boundary: enrollment secrets enter on stdin; native and session credentials never print.
import * as Console from "effect/Console";
import * as Effect from "effect/Effect";
import * as NodeHttp from "node:http";
import * as NodePath from "node:path";
import * as NodeFS from "node:fs";
import { AuthStandardClientScopes } from "@t3tools/contracts";
import {
  enrollDevice,
  openClientGateway,
  readDeviceProfile,
  savedDevices,
} from "@t3tools/iroh/client";
import { ensurePrivateDirectory, publishPrivateFile, readPrivateFile } from "@t3tools/iroh/keys";
import { validateRelayPolicy, type RelayPolicy } from "@t3tools/iroh/protocol";

const readScopes = ["orchestration:read", "filesystem:read", "terminal:read"];
function option(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}
function directory(args: readonly string[], name: string): string {
  const path = option(args, name);
  if (!path || !NodePath.isAbsolute(path)) throw new Error(`Provide an absolute ${name} path.`);
  return NodePath.resolve(path);
}
function relayPolicy(args: readonly string[]): RelayPolicy {
  const config = option(args, "--relay-config");
  if (!config) return { mode: "automatic" };
  const bytes = readPrivateFile(NodePath.resolve(config), 16 * 1024);
  try {
    return validateRelayPolicy(JSON.parse(bytes.toString("utf8")) as RelayPolicy);
  } finally {
    bytes.fill(0);
  }
}
async function admin(stateDir: string, body: unknown): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const outgoing = NodeHttp.request(
      {
        socketPath: NodePath.join(stateDir, "iroh/admin.sock"),
        method: "POST",
        path: "/",
        headers: { "content-type": "application/json" },
      },
      (incoming) => {
        const chunks: Buffer[] = [];
        let length = 0;
        incoming.on("data", (chunk: Buffer) => {
          length += chunk.length;
          if (length > 64 * 1024) incoming.destroy();
          else chunks.push(chunk);
        });
        incoming.on("error", () => reject(new Error("Iroh local control response failed.")));
        incoming.on("end", () => {
          try {
            const result = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            if (!result.ok) throw new Error();
            resolve(result.value);
          } catch {
            reject(new Error("Iroh command rejected. Check device status and requested scopes."));
          }
        });
      },
    );
    outgoing.on("error", () =>
      reject(new Error("Iroh local control unavailable. Start the opted-in T3 host first.")),
    );
    outgoing.setTimeout(10_000, () => outgoing.destroy());
    outgoing.end(JSON.stringify(body));
  });
}
async function invitationFromStdin(): Promise<string> {
  let value = "";
  for await (const chunk of process.stdin) {
    value += String(chunk);
    if (value.length > 8192) throw new Error("Invalid invitation.");
    if (value.includes("\n")) break;
  }
  return value.trim();
}
export async function runIrohCli(args: readonly string[]) {
  const command = args[0];
  const scopes = args.includes("--control") ? [...AuthStandardClientScopes] : readScopes;
  if (command === "help" || !command) {
    await Effect.runPromise(
      Console.log(
        "Linux Iroh (experimental): enable|disable|invite|devices|approve|revoke-device|revoke-invitation --state-dir ABS; pair|connect|profiles|forget --profiles-dir ABS. Pair reads the invitation link from stdin. connect PROFILE --lease-file ABS writes an owner-only local capability. Approval/invites default to view-only; --control grants command execution as the host user.",
      ),
    );
    return;
  }
  if (command === "enable" || command === "disable") {
    const root = NodePath.join(directory(args, "--state-dir"), "iroh");
    ensurePrivateDirectory(root);
    const path = NodePath.join(root, "host.json");
    if (command === "disable") {
      readPrivateFile(path, 16 * 1024).fill(0);
      NodeFS.unlinkSync(path);
    } else
      publishPrivateFile(
        path,
        Buffer.from(
          JSON.stringify({
            enabled: true,
            relay: relayPolicy(args),
            ...(option(args, "--systemd-credential")
              ? { systemdCredentialPath: directory(args, "--systemd-credential") }
              : {}),
          }),
        ),
      );
    await Effect.runPromise(
      Console.log(
        "Iroh configuration saved. Restart this T3 host to apply it; identity and device grants were retained.",
      ),
    );
    return;
  }
  if (command === "pair") {
    const result = await enrollDevice({
      link: await invitationFromStdin(),
      directory: directory(args, "--profiles-dir"),
      scopes,
      relayPolicy: relayPolicy(args),
    });
    await Effect.runPromise(Console.log(JSON.stringify(result)));
    return;
  }
  if (command === "profiles") {
    await Effect.runPromise(
      Console.log(JSON.stringify(savedDevices(directory(args, "--profiles-dir")), null, 2)),
    );
    return;
  }
  if (command === "forget") {
    const root = directory(args, "--profiles-dir");
    const id = args[1] ?? "";
    readDeviceProfile(root, id);
    NodeFS.unlinkSync(NodePath.join(root, `${id}.json`));
    await Effect.runPromise(
      Console.log(
        "Local Iroh profile removed. Revoke the device on its host to remove host access.",
      ),
    );
    return;
  }
  if (command === "connect") {
    const root = directory(args, "--profiles-dir");
    const profileId = args[1] ?? "";
    const profile = readDeviceProfile(root, profileId);
    const gateway = await openClientGateway({
      directory: root,
      profileId,
      expectedHostId: profile.hostId,
      expectedEnvironmentId: profile.environmentId,
      allowedOrigin: "t3code://app",
    });
    const lease = directory(args, "--lease-file");
    try {
      publishPrivateFile(
        lease,
        Buffer.from(
          JSON.stringify({
            httpBaseUrl: gateway.httpBaseUrl,
            socketUrl: gateway.socketUrl,
            gatewayToken: gateway.gatewayToken,
          }),
        ),
      );
    } catch {
      await gateway.close();
      throw new Error("Cannot publish the private gateway lease file.");
    }
    await Effect.runPromise(
      Console.log(
        "Iroh gateway ready. Local capability is in the requested owner-only lease file.",
      ),
    );
    await new Promise<void>((resolve) => {
      process.once("SIGINT", resolve);
      process.once("SIGTERM", resolve);
    });
    await gateway.close();
    NodeFS.unlinkSync(lease);
    return;
  }
  const state = directory(args, "--state-dir");
  let result: unknown;
  if (command === "invite") result = await admin(state, { operation: "invite", scopes });
  else if (command === "devices") result = await admin(state, { operation: "devices" });
  else if (command === "approve")
    result = await admin(state, { operation: "approve", deviceId: args[1], scopes });
  else if (command === "revoke-device")
    result = await admin(state, { operation: "revoke-device", deviceId: args[1] });
  else if (command === "revoke-invitation")
    result = await admin(state, { operation: "revoke-invitation", invitationId: args[1] });
  else throw new Error("Unknown Iroh command. Use iroh help.");
  // invite deliberately prints the one-time enrollment link, the explicit owner-facing output.
  await Effect.runPromise(Console.log(JSON.stringify(result, null, 2)));
}
