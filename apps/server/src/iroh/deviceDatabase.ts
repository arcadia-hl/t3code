// @effect-diagnostics nodeBuiltinImport:off -- Native SQLite transactions and O_NOFOLLOW/ownership checks are the synchronous persistence boundary.
// Synchronous SQLite and filesystem ownership checks form the native persistence boundary.
import * as NodeSqlite from "node:sqlite";
import * as NodeFS from "node:fs";
import * as NodeCrypto from "node:crypto";
import * as NodePath from "node:path";
import { ensurePrivateDirectory } from "@t3tools/iroh/keys";
import {
  deviceThumbprint,
  INVITATION_TTL_MS,
  publicDeviceKey,
  verifyDeviceProof,
} from "@t3tools/iroh/protocol";

interface DeviceRow {
  deviceId: string;
  publicKey: string;
  thumbprint: string;
  scopes: string;
  status: "pending" | "approved" | "revoked";
}
interface InviteRow {
  verifier: string;
  scopes: string;
  expiresAt: number;
}
const verifier = (secret: string) => NodeCrypto.createHash("sha256").update(secret).digest("hex");
function invalidInvite(): never {
  throw new Error("Invalid invitation.");
}
function invalidProof(): never {
  throw new Error("Invalid device proof.");
}
function subset(requested: readonly string[], granted: readonly string[]): void {
  if (
    !requested.length ||
    requested.length > 32 ||
    new Set(requested).size !== requested.length ||
    requested.some((scope) => !granted.includes(scope))
  )
    throw new Error("Scope escalation.");
}

export function openDeviceDatabase(options: {
  readonly path: string;
  readonly hostId: string;
  readonly environmentId: string;
  readonly now?: () => number;
}) {
  ensurePrivateDirectory(NodePath.dirname(options.path));
  try {
    const fd = NodeFS.openSync(
      options.path,
      NodeFS.constants.O_WRONLY |
        NodeFS.constants.O_CREAT |
        NodeFS.constants.O_EXCL |
        NodeFS.constants.O_NOFOLLOW,
      0o600,
    );
    NodeFS.closeSync(fd);
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "EEXIST") throw error;
  }
  const stat = NodeFS.lstatSync(options.path);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    stat.uid !== process.getuid?.() ||
    (stat.mode & 0o777) !== 0o600 ||
    stat.nlink !== 1
  )
    throw new Error("Unsafe pairing database.");
  const sql = new NodeSqlite.DatabaseSync(options.path);
  sql.exec("PRAGMA busy_timeout=5000; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;");
  const version = sql.prepare("PRAGMA user_version").get()?.user_version;
  if (version !== 0 && version !== 1) {
    sql.close();
    throw new Error("Unsupported pairing database version.");
  }
  sql.exec(`
    CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK(id=1), hostId TEXT NOT NULL, environmentId TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS invitations (id TEXT PRIMARY KEY, verifier TEXT NOT NULL, scopes TEXT NOT NULL, expiresAt INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS devices (deviceId TEXT PRIMARY KEY, publicKey TEXT NOT NULL, thumbprint TEXT NOT NULL, scopes TEXT NOT NULL, status TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS challenges (nonce TEXT PRIMARY KEY, peerId TEXT NOT NULL, operation TEXT NOT NULL, expiresAt INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (sessionId TEXT PRIMARY KEY, deviceId TEXT NOT NULL, expiresAt INTEGER NOT NULL);
    PRAGMA user_version=1;
  `);
  sql
    .prepare("INSERT OR IGNORE INTO identity VALUES (1, ?, ?)")
    .run(options.hostId, options.environmentId);
  const identity = sql.prepare("SELECT hostId, environmentId FROM identity WHERE id=1").get();
  if (identity?.hostId !== options.hostId || identity?.environmentId !== options.environmentId) {
    sql.close();
    throw new Error("Pairing database identity mismatch.");
  }
  const now = options.now ?? Date.now;
  let closed = false;
  function transaction<A>(body: () => A): A {
    sql.exec("BEGIN IMMEDIATE");
    try {
      const result = body();
      sql.exec("COMMIT");
      return result;
    } catch (error) {
      sql.exec("ROLLBACK");
      throw error;
    }
  }
  function cleanup() {
    sql.prepare("DELETE FROM challenges WHERE expiresAt <= ?").run(now());
    sql.prepare("DELETE FROM invitations WHERE expiresAt <= ?").run(now());
    sql.prepare("DELETE FROM sessions WHERE expiresAt <= ?").run(now());
  }
  function capacity(table: "invitations" | "devices" | "challenges", limit: number) {
    const row = sql.prepare(`SELECT count(*) AS count FROM ${table}`).get();
    if (Number(row?.count) >= limit) throw new Error("Pairing capacity reached.");
  }
  function device(id: string): DeviceRow {
    const row = sql.prepare("SELECT * FROM devices WHERE deviceId=?").get(id) as unknown as
      | DeviceRow
      | undefined;
    if (!row || row.status !== "approved") throw new Error("Device not approved.");
    return row;
  }
  function useChallenge(nonce: string, peerId: string, operation: "enroll" | "renew") {
    const result = sql
      .prepare(
        "DELETE FROM challenges WHERE nonce=? AND peerId=? AND operation=? AND expiresAt>? RETURNING nonce",
      )
      .get(nonce, peerId, operation, now());
    if (!result) invalidProof();
  }
  function enrollmentBody(
    invitationId: string,
    secret: string,
    publicKey: NodeCrypto.JsonWebKey,
    scopes: readonly string[],
  ) {
    if (!/^[\w-]{43}$/.test(secret)) invalidInvite();
    return {
      invitationId,
      verifier: verifier(secret),
      publicKey: publicDeviceKey(publicKey),
      scopes,
    };
  }
  return {
    close() {
      if (!closed) {
        closed = true;
        sql.close();
      }
    },
    invite(scopes: readonly string[]) {
      subset(scopes, scopes);
      return transaction(() => {
        cleanup();
        capacity("invitations", 64);
        const invitationId = NodeCrypto.randomUUID();
        const secret = NodeCrypto.randomBytes(32).toString("base64url");
        const expiresAt = now() + INVITATION_TTL_MS;
        sql
          .prepare("INSERT INTO invitations (id, verifier, scopes, expiresAt) VALUES (?, ?, ?, ?)")
          .run(invitationId, verifier(secret), JSON.stringify(scopes), expiresAt);
        return { invitationId, secret, expiresAt };
      });
    },
    revokeInvitation(id: string) {
      return (
        sql.prepare("UPDATE invitations SET revoked=1 WHERE id=? AND consumed=0").run(id).changes >
        0
      );
    },
    challenge(peerId: string, operation: "enroll" | "renew") {
      return transaction(() => {
        cleanup();
        capacity("challenges", 256);
        const nonce = NodeCrypto.randomBytes(32).toString("base64url");
        sql
          .prepare("INSERT INTO challenges VALUES (?, ?, ?, ?)")
          .run(nonce, peerId, operation, now() + 30_000);
        return nonce;
      });
    },
    enrollmentBody,
    redeem(input: {
      readonly peerId: string;
      readonly challenge: string;
      readonly invitationId: string;
      readonly secret: string;
      readonly publicKey: NodeCrypto.JsonWebKey;
      readonly scopes: readonly string[];
      readonly proof: string;
    }) {
      const body = enrollmentBody(input.invitationId, input.secret, input.publicKey, input.scopes);
      // Failed proofs consume the challenge too, preventing unlimited verification attempts.
      useChallenge(input.challenge, input.peerId, "enroll");
      if (
        !verifyDeviceProof(
          input.publicKey,
          {
            hostId: options.hostId,
            environmentId: options.environmentId,
            operation: "enroll",
            challenge: input.challenge,
            body,
          },
          input.proof,
        )
      )
        invalidProof();
      return transaction(() => {
        const invite = sql
          .prepare(
            "SELECT verifier, scopes, expiresAt FROM invitations WHERE id=? AND expiresAt>? AND consumed=0 AND revoked=0",
          )
          .get(input.invitationId, now()) as unknown as InviteRow | undefined;
        if (
          !invite ||
          !NodeCrypto.timingSafeEqual(
            Buffer.from(invite.verifier, "hex"),
            Buffer.from(body.verifier, "hex"),
          )
        )
          invalidInvite();
        subset(input.scopes, JSON.parse(invite.scopes));
        capacity("devices", 256);
        if (
          sql
            .prepare(
              "UPDATE invitations SET consumed=1 WHERE id=? AND consumed=0 AND revoked=0 AND expiresAt>?",
            )
            .run(input.invitationId, now()).changes !== 1
        )
          invalidInvite();
        const deviceId = NodeCrypto.randomUUID();
        sql
          .prepare("INSERT INTO devices VALUES (?, ?, ?, ?, 'pending')")
          .run(
            deviceId,
            JSON.stringify(body.publicKey),
            deviceThumbprint(body.publicKey),
            JSON.stringify(input.scopes),
          );
        return { deviceId, status: "pending" as const };
      });
    },
    approve(deviceId: string, scopes: readonly string[]) {
      transaction(() => {
        const row = sql
          .prepare("SELECT scopes FROM devices WHERE deviceId=? AND status='pending'")
          .get(deviceId);
        if (!row) throw new Error("Device not approved.");
        subset(scopes, JSON.parse(String(row.scopes)));
        sql
          .prepare("UPDATE devices SET status='approved', scopes=? WHERE deviceId=?")
          .run(JSON.stringify(scopes), deviceId);
      });
    },
    renew(input: {
      readonly peerId: string;
      readonly challenge: string;
      readonly deviceId: string;
      readonly scopes: readonly string[];
      readonly proof: string;
    }) {
      useChallenge(input.challenge, input.peerId, "renew");
      const row = device(input.deviceId);
      const body = { deviceId: input.deviceId, scopes: input.scopes };
      if (
        !verifyDeviceProof(
          JSON.parse(row.publicKey),
          {
            hostId: options.hostId,
            environmentId: options.environmentId,
            operation: "renew",
            challenge: input.challenge,
            body,
          },
          input.proof,
        )
      )
        invalidProof();
      subset(input.scopes, JSON.parse(row.scopes));
      return { deviceId: row.deviceId, thumbprint: row.thumbprint, scopes: input.scopes };
    },
    attachSession(deviceId: string, sessionId: string, expiresAt: number) {
      return transaction(() => {
        cleanup();
        const row = sql.prepare("SELECT status FROM devices WHERE deviceId=?").get(deviceId);
        if (row?.status !== "approved") return false;
        sql.prepare("INSERT INTO sessions VALUES (?, ?, ?)").run(sessionId, deviceId, expiresAt);
        return true;
      });
    },
    revokeDevice(deviceId: string) {
      return transaction(() => {
        sql.prepare("UPDATE devices SET status='revoked' WHERE deviceId=?").run(deviceId);
        return sql
          .prepare("SELECT sessionId FROM sessions WHERE deviceId=? ORDER BY rowid")
          .all(deviceId)
          .map((row) => String(row.sessionId));
      });
    },
    devices() {
      return sql
        .prepare("SELECT deviceId, thumbprint, scopes, status FROM devices ORDER BY rowid")
        .all()
        .map((row) => ({
          deviceId: String(row.deviceId),
          thumbprint: String(row.thumbprint),
          scopes: JSON.parse(String(row.scopes)) as string[],
          status: String(row.status),
        }));
    },
  };
}
