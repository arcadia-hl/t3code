import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import { gatewayCapabilityUrl, nativeGatewayToken } from "./nativeGateway.ts";
const prepared = {
  httpBaseUrl: "http://127.0.0.1:1234",
  nativeTransport: "iroh" as const,
  httpAuthorization: { _tag: "Bearer" as const, token: "local-capability" },
};
NodeTest.test(
  "URL-only asset/upload consumers carry the attempt capability only to the same gateway",
  () => {
    const url = new URL(gatewayCapabilityUrl(prepared, "/api/assets?signed=asset"));
    NodeAssert.equal(url.searchParams.get("gatewayToken"), "local-capability");
    NodeAssert.equal(url.searchParams.get("signed"), "asset");
    NodeAssert.equal(
      gatewayCapabilityUrl(prepared, "https://external.example/api/assets"),
      "https://external.example/api/assets",
    );
    NodeAssert.equal(nativeGatewayToken({ httpBaseUrl: prepared.httpBaseUrl }), undefined);
    NodeAssert.equal(
      gatewayCapabilityUrl({ ...prepared, nativeTransport: undefined }, "/api/assets"),
      "http://127.0.0.1:1234/api/assets",
    );
  },
);
