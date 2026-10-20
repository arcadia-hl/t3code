import type { PreparedConnection } from "./model.ts";

type GatewayConnection = Pick<PreparedConnection, "httpBaseUrl"> & {
  readonly nativeTransport?: "iroh" | undefined;
  readonly httpAuthorization?: PreparedConnection["httpAuthorization"] | undefined;
};
export function nativeGatewayToken(prepared: GatewayConnection): string | undefined {
  return prepared.nativeTransport === "iroh" && prepared.httpAuthorization?._tag === "Bearer"
    ? prepared.httpAuthorization.token
    : undefined;
}
export function gatewayCapabilityUrl(prepared: GatewayConnection, value: string): string {
  const url = new URL(value, prepared.httpBaseUrl);
  const token = nativeGatewayToken(prepared);
  if (token !== undefined && url.origin === new URL(prepared.httpBaseUrl).origin)
    url.searchParams.set("gatewayToken", token);
  return url.href;
}
