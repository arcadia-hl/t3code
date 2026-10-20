import * as NodeTest from "node:test";
import * as NodeAssert from "node:assert/strict";
import {
  gatewayAccess,
  forwardingHeaders,
  allowedServicePath,
  createDpopProof,
} from "./gateway.ts";
import * as NodeCrypto from "node:crypto";

const options = { host: "127.0.0.1:12345", token: "A".repeat(43), allowedOrigin: "t3://app" };
NodeTest.test(
  "loopback caller protection requires capability and checks origin and exact host",
  () => {
    NodeAssert.equal(
      gatewayAccess(
        {
          host: options.host,
          authorization: `Bearer ${options.token}`,
          origin: options.allowedOrigin,
        },
        "/api/auth/session",
        options,
      ),
      true,
    );
    NodeAssert.equal(gatewayAccess({ host: options.host }, "/api/auth/session", options), false);
    NodeAssert.equal(
      gatewayAccess(
        { host: "evil.example", authorization: `Bearer ${options.token}` },
        "/api/auth/session",
        options,
      ),
      false,
    );
    NodeAssert.equal(
      gatewayAccess(
        {
          host: options.host,
          authorization: `Bearer ${options.token}`,
          origin: "https://preview.example",
        },
        "/api/auth/session",
        options,
      ),
      false,
    );
    NodeAssert.equal(
      gatewayAccess({ host: options.host }, `/api/assets?gatewayToken=${options.token}`, options),
      true,
    );
    NodeAssert.equal(
      gatewayAccess(
        { host: options.host },
        `http://evil.example/api/assets?gatewayToken=${options.token}`,
        options,
      ),
      false,
    );
  },
);

NodeTest.test(
  "fixed-service paths reject destination overrides and drop forwarded/cookie/hop headers",
  () => {
    for (const path of [
      "/api/assets?range=1",
      "/api/attachments/upload",
      "/ws?orchestrationProtocol=2",
      "/.well-known/t3/environment",
    ])
      NodeAssert.equal(allowedServicePath(path), true);
    for (const path of [
      "http://evil.example/",
      "//evil.example/",
      "/../admin",
      "/api/../admin",
      "/api/%2e%2e/admin",
      "/api/%2fadmin",
      "/oauth/authorize",
    ])
      NodeAssert.equal(allowedServicePath(path), false);
    const headers = forwardingHeaders(
      {
        host: "evil.example",
        forwarded: "host=evil",
        "x-forwarded-host": "evil",
        "x-forwarded-proto": "https",
        cookie: "local=private",
        connection: "x-hidden",
        "x-hidden": "private",
        range: "bytes=0-2",
        authorization: "DPoP abc",
      },
      "pinned.iroh.invalid",
    );
    NodeAssert.equal(headers.host, "pinned.iroh.invalid");
    NodeAssert.equal(headers.range, "bytes=0-2");
    NodeAssert.equal(headers.authorization, "DPoP abc");
    for (const name of ["cookie", "forwarded", "x-forwarded-host", "x-forwarded-proto", "x-hidden"])
      NodeAssert.equal(headers[name], undefined);
  },
);

NodeTest.test(
  "native DPoP signs the fixed logical origin rather than ephemeral loopback origin",
  () => {
    const { publicKey, privateKey } = NodeCrypto.generateKeyPairSync("ec", {
      namedCurve: "prime256v1",
    });
    const publicJwk = publicKey.export({ format: "jwk" });
    const proof = createDpopProof(
      privateKey,
      publicJwk,
      "GET",
      "http://pinned.iroh.invalid/api/assets?query=1",
      "access-token",
    );
    const [header, payload, signature] = proof.split(".");
    NodeAssert.ok(header && payload && signature);
    NodeAssert.equal(
      JSON.parse(Buffer.from(payload, "base64url").toString()).htu,
      "http://pinned.iroh.invalid/api/assets",
    );
    NodeAssert.equal(
      NodeCrypto.verify(
        "sha256",
        Buffer.from(`${header}.${payload}`),
        {
          key: NodeCrypto.createPublicKey({ key: publicJwk, format: "jwk" }),
          dsaEncoding: "ieee-p1363",
        },
        Buffer.from(signature, "base64url"),
      ),
      true,
    );
    NodeAssert.equal(JSON.parse(Buffer.from(header, "base64url").toString()).jwk.d, undefined);
  },
);

NodeTest.test(
  "actual HTTP parser/proxy preserves streaming uploads, range bytes and HEAD through in-memory streams",
  { timeout: 5000 },
  async (t) => {
    const Http = await import("node:http");
    const { Duplex, PassThrough } = await import("node:stream");
    const { fixedHttpProxy, httpSocket } = await import("./gateway.ts");
    function pair() {
      const a = new PassThrough({ highWaterMark: 64 * 1024 });
      const b = new PassThrough({ highWaterMark: 64 * 1024 });
      return [
        httpSocket(Duplex.from({ readable: a, writable: b })),
        httpSocket(Duplex.from({ readable: b, writable: a })),
      ] as const;
    }
    let uploaded = 0;
    const application = Http.createServer(async (request, response) => {
      NodeAssert.equal(request.headers["x-forwarded-host"], undefined);
      NodeAssert.equal(request.headers.host, "pinned.iroh.invalid");
      if (request.method === "POST") {
        for await (const chunk of request) uploaded += Buffer.byteLength(chunk);
        response.end("uploaded");
        return;
      }
      response.writeHead(206, {
        "content-range": "bytes 1-3/6",
        "content-length": 3,
        "content-type": "application/octet-stream",
      });
      response.end(request.method === "HEAD" ? undefined : "bcd");
    });
    const proxy = fixedHttpProxy({
      logicalHost: "pinned.iroh.invalid",
      open: async () => {
        const [client, host] = pair();
        application.emit("connection", host);
        return client;
      },
    });
    t.after(() => {
      proxy.close();
      application.close();
    });
    async function request(method: string, bytes = Buffer.alloc(0)) {
      const [client, host] = pair();
      proxy.emit("connection", host);
      const agent = new Http.Agent({ keepAlive: false });
      agent.createConnection = () => client;
      t.after(() => agent.destroy());
      return new Promise<{
        status: number | undefined;
        body: Buffer;
        headers: import("node:http").IncomingHttpHeaders;
      }>((resolve, reject) => {
        const outgoing = Http.request(
          {
            host: "pinned.iroh.invalid",
            path: "/api/assets",
            method,
            agent,
            headers: { range: "bytes=1-3", "x-forwarded-host": "untrusted.example" },
          },
          (incoming) => {
            const chunks: Buffer[] = [];
            incoming.on("data", (chunk) => chunks.push(chunk));
            incoming.on("error", reject);
            incoming.on("end", () =>
              resolve({
                status: incoming.statusCode,
                headers: incoming.headers,
                body: Buffer.concat(chunks),
              }),
            );
          },
        );
        outgoing.on("error", reject);
        outgoing.end(bytes);
      });
    }
    const range = await request("GET");
    NodeAssert.equal(range.status, 206);
    NodeAssert.equal(range.body.toString(), "bcd");
    NodeAssert.equal(range.headers["content-range"], "bytes 1-3/6");
    const head = await request("HEAD");
    NodeAssert.equal(head.body.length, 0);
    NodeAssert.equal(head.headers["content-length"], "3");
    const upload = await request("POST", Buffer.alloc(2 * 1024 * 1024, 9));
    NodeAssert.equal(upload.body.toString(), "uploaded");
    NodeAssert.equal(uploaded, 2 * 1024 * 1024);
  },
);

NodeTest.test(
  "non-ASCII capability of matching character length is denied without throwing",
  () => {
    NodeAssert.equal(
      gatewayAccess(
        { host: options.host, authorization: `Bearer ${"é".repeat(43)}` },
        "/api/auth/session",
        options,
      ),
      false,
    );
  },
);

NodeTest.test(
  "injected native HTTP sockets cannot bypass the global connection limit",
  async (t) => {
    const { PassThrough } = await import("node:stream");
    const { fixedHttpProxy, httpSocket } = await import("./gateway.ts");
    const proxy = fixedHttpProxy({
      logicalHost: "pinned.iroh.invalid",
      open: async () => {
        throw new Error("headers must arrive first");
      },
    });
    t.after(() => proxy.close());
    for (let i = 0; i < 64; i++) proxy.emit("connection", httpSocket(new PassThrough()));
    const excess = httpSocket(new PassThrough());
    proxy.emit("connection", excess);
    NodeAssert.equal(excess.destroyed, true);
  },
);
