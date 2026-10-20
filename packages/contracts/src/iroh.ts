import * as Schema from "effect/Schema";
import { EnvironmentId } from "./baseSchemas.ts";
import { AuthEnvironmentScopes } from "./auth.ts";

const BoundedId = Schema.String.check(Schema.isPattern(/^[\w-]{1,128}$/));
export const IrohEndpointId = Schema.String.check(Schema.isPattern(/^[a-f0-9]{64}$/));
export const IrohRoute = Schema.Struct({ profileId: BoundedId, hostId: IrohEndpointId });
export type IrohRoute = typeof IrohRoute.Type;
export const IrohSavedDevice = Schema.Struct({
  ...IrohRoute.fields,
  environmentId: EnvironmentId,
  label: Schema.String.check(Schema.isMaxLength(128)),
});
export type IrohSavedDevice = typeof IrohSavedDevice.Type;
export const IrohGatewayOpen = Schema.Struct({
  ...IrohRoute.fields,
  environmentId: EnvironmentId,
});
export type IrohGatewayOpen = typeof IrohGatewayOpen.Type;
export const IrohGatewayLease = Schema.Struct({
  leaseId: BoundedId,
  httpBaseUrl: Schema.String,
  socketUrl: Schema.String,
  gatewayToken: Schema.String,
});
export type IrohGatewayLease = typeof IrohGatewayLease.Type;
export const IrohPublicDeviceKey = Schema.Struct({
  kty: Schema.Literal("EC"),
  crv: Schema.Literal("P-256"),
  x: Schema.String.check(Schema.isPattern(/^[\w-]{43}$/)),
  y: Schema.String.check(Schema.isPattern(/^[\w-]{43}$/)),
  d: Schema.optionalKey(Schema.Never),
});
const Nonce = Schema.String.check(Schema.isPattern(/^[\w-]{43}$/));
const Signature = Schema.String.check(Schema.isPattern(/^[\w-]{86}$/));
const Version = Schema.Literal(1);
export const IrohControlRequest = Schema.Union([
  Schema.Struct({
    version: Version,
    operation: Schema.Literal("challenge"),
    purpose: Schema.Literals(["enroll", "renew"]),
  }),
  Schema.Struct({
    version: Version,
    operation: Schema.Literal("enroll"),
    challenge: Nonce,
    invitationId: BoundedId,
    secret: Nonce,
    publicKey: IrohPublicDeviceKey,
    scopes: AuthEnvironmentScopes,
    proof: Signature,
  }),
  Schema.Struct({
    version: Version,
    operation: Schema.Literal("renew"),
    challenge: Nonce,
    deviceId: BoundedId,
    scopes: AuthEnvironmentScopes,
    proof: Signature,
  }),
  Schema.Struct({ version: Version, operation: Schema.Literal("http") }),
]);
export type IrohControlRequest = typeof IrohControlRequest.Type;
export const IrohLocalAdminRequest = Schema.Union([
  Schema.Struct({ operation: Schema.Literal("invite"), scopes: AuthEnvironmentScopes }),
  Schema.Struct({ operation: Schema.Literal("devices") }),
  Schema.Struct({
    operation: Schema.Literal("approve"),
    deviceId: BoundedId,
    scopes: AuthEnvironmentScopes,
  }),
  Schema.Struct({ operation: Schema.Literal("revoke-device"), deviceId: BoundedId }),
  Schema.Struct({ operation: Schema.Literal("revoke-invitation"), invitationId: BoundedId }),
]);
export type IrohLocalAdminRequest = typeof IrohLocalAdminRequest.Type;
