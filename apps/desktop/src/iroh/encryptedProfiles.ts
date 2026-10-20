// @effect-diagnostics nodeBuiltinImport:off -- Main-process protected-storage adapter; all operations are invoked by DesktopIroh.
import * as NodeFS from "node:fs";
import * as NodePath from "node:path";
import * as NodeCrypto from "node:crypto";
import { validateDeviceProfile, type DeviceProfileStore } from "@t3tools/iroh/client";

export function encryptedProfileStore(input: {
  directory: string;
  privateRoot: string;
  crypto: {
    available(): Promise<boolean>;
    encrypt(text: string): Promise<Uint8Array>;
    decrypt(bytes: Uint8Array): Promise<string>;
  };
}): DeviceProfileStore {
  const directory = NodePath.resolve(input.directory);
  const root = NodePath.resolve(input.privateRoot);
  const idPath = (id: string) => {
    if (!/^[a-f0-9-]{36}$/.test(id)) throw new Error("Invalid Iroh profile ID.");
    return NodePath.join(directory, `${id}.dpapi`);
  };
  const ready = async () => {
    const relative = NodePath.relative(root, directory);
    if (
      !relative ||
      relative.startsWith("..") ||
      NodePath.isAbsolute(relative) ||
      directory.startsWith("\\\\") ||
      directory.startsWith("//")
    )
      throw new Error("Protected Iroh storage must be inside the local user profile.");
    // Windows permissions are inherited from the local user profile ACL. POSIX modes are not an ACL substitute.
    let current = NodePath.parse(directory).root;
    for (const part of directory.slice(current.length).split(NodePath.sep)) {
      current = NodePath.join(current, part);
      if (!NodeFS.existsSync(current)) NodeFS.mkdirSync(current);
      const info = NodeFS.lstatSync(current);
      if (
        info.isSymbolicLink() ||
        !info.isDirectory() ||
        NodeFS.realpathSync(current).toLowerCase() !== current.toLowerCase()
      )
        throw new Error("Redirected Iroh storage is unsupported.");
    }
    if (!(await input.crypto.available()))
      throw new Error("Windows protected storage is unavailable. No plaintext fallback.");
  };
  const read: DeviceProfileStore["read"] = async (id) => {
    const path = idPath(id);
    await ready();
    const info = NodeFS.lstatSync(path);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 65536)
      throw new Error("Invalid protected profile file.");
    const bytes = NodeFS.readFileSync(path);
    try {
      const text = await input.crypto.decrypt(bytes);
      if (Buffer.byteLength(text) > 16384) throw new Error("Profile is too large.");
      return validateDeviceProfile(JSON.parse(text), id);
    } catch {
      throw new Error("Protected Iroh profile could not be decrypted. Profile was not replaced.");
    } finally {
      bytes.fill(0);
    }
  };
  return {
    read,
    list: async () => {
      await ready();
      const names = NodeFS.readdirSync(directory).filter((name) =>
        /^[a-f0-9-]{36}\.dpapi$/.test(name),
      );
      if (names.length > 256) throw new Error("Too many protected profiles.");
      return Promise.all(
        names.map(async (name) => {
          const p = await read(name.slice(0, -6));
          return {
            profileId: p.profileId,
            hostId: p.hostId,
            environmentId: p.environmentId,
            label: p.label,
          };
        }),
      );
    },
    create: async (profile) => {
      const path = idPath(profile.profileId);
      await ready();
      validateDeviceProfile(profile, profile.profileId);
      const text = JSON.stringify(profile);
      if (Buffer.byteLength(text) > 16384) throw new Error("Profile is too large.");
      const bytes = await input.crypto.encrypt(text);
      if (bytes.length === 0 || bytes.length > 65536)
        throw new Error("Invalid protected profile size.");
      const temporary = `${path}.${NodeCrypto.randomUUID()}.tmp`;
      try {
        const fd = NodeFS.openSync(temporary, "wx");
        try {
          NodeFS.writeFileSync(fd, bytes);
          NodeFS.fsyncSync(fd);
        } finally {
          NodeFS.closeSync(fd);
        }
        // NTFS hardlink publication is exclusive: an existing identity is never overwritten.
        NodeFS.linkSync(temporary, path);
      } finally {
        bytes.fill(0);
        NodeFS.rmSync(temporary, { force: true });
      }
    },
    forget: async (id) => {
      const path = idPath(id);
      await ready();
      NodeFS.unlinkSync(path);
    },
  };
}
