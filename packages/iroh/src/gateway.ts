import * as NodeCrypto from "node:crypto";
import * as NodeHttp from "node:http";
import type * as NodeStream from "node:stream";
import { MAX_STREAMS } from "./protocol.ts";

const hopHeaders = new Set([
  "connection",
  "proxy-connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "proxy-authenticate",
  "proxy-authorization",
]);
const stripHeaders = new Set(["forwarded", "cookie", "origin", "referer", "host", "set-cookie"]);

export function allowedServicePath(path: string): boolean {
  if (
    path.length > 16384 ||
    !path.startsWith("/") ||
    path.startsWith("//") ||
    path.includes("\\") ||
    /%(?:2e|2f|5c)/i.test(path.split("?")[0] ?? "") ||
    path.split("?")[0]?.split("/").includes("..")
  )
    return false;
  return (
    path === "/.well-known/t3/environment" || /^\/ws(?:\?|$)/.test(path) || path.startsWith("/api/")
  );
}

function equalSecret(actual: string | undefined, expected: string): boolean {
  if (actual === undefined) return false;
  const received = Buffer.from(actual);
  const wanted = Buffer.from(expected);
  return received.length === wanted.length && NodeCrypto.timingSafeEqual(received, wanted);
}

export function gatewayAccess(
  headers: NodeHttp.IncomingHttpHeaders,
  path: string,
  options: { readonly host: string; readonly token: string; readonly allowedOrigin: string },
): boolean {
  if (
    headers.host !== options.host ||
    (headers.origin !== undefined && headers.origin !== options.allowedOrigin) ||
    !allowedServicePath(path)
  )
    return false;
  const url = new URL(path, `http://${options.host}`);
  return (
    equalSecret(headers.authorization, `Bearer ${options.token}`) ||
    equalSecret(url.searchParams.get("gatewayToken") ?? undefined, options.token)
  );
}

export function forwardingHeaders(
  headers: NodeHttp.IncomingHttpHeaders,
  host: string,
): NodeHttp.OutgoingHttpHeaders {
  const connection = new Set(
    (headers.connection ?? "")
      .toLowerCase()
      .split(",")
      .map((value) => value.trim()),
  );
  const result: NodeHttp.OutgoingHttpHeaders = { host };
  for (const [name, value] of Object.entries(headers)) {
    if (
      value === undefined ||
      hopHeaders.has(name) ||
      stripHeaders.has(name) ||
      connection.has(name) ||
      name.startsWith("x-forwarded-") ||
      name.startsWith("sec-fetch-") ||
      name === "x-t3-iroh-gateway"
    )
      continue;
    result[name] = value;
  }
  return result;
}

export function createDpopProof(
  key: NodeCrypto.KeyObject,
  publicKey: NodeCrypto.JsonWebKey,
  method: string,
  logicalUrl: string,
  accessToken: string,
): string {
  const url = new URL(logicalUrl);
  url.search = "";
  url.hash = "";
  const jwk = { kty: publicKey.kty, crv: publicKey.crv, x: publicKey.x, y: publicKey.y };
  const header = Buffer.from(JSON.stringify({ typ: "dpop+jwt", alg: "ES256", jwk })).toString(
    "base64url",
  );
  const payload = Buffer.from(
    JSON.stringify({
      htm: method.toUpperCase(),
      htu: url.href,
      jti: NodeCrypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
      ath: NodeCrypto.createHash("sha256").update(accessToken).digest("base64url"),
    }),
  ).toString("base64url");
  const input = `${header}.${payload}`;
  return `${input}.${NodeCrypto.sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" }).toString("base64url")}`;
}

// Node's HTTP parser accepts a Duplex; these socket controls are no-ops for QUIC streams.
export function httpSocket(stream: NodeStream.Duplex): NodeStream.Duplex {
  return Object.assign(stream, {
    setNoDelay: () => stream,
    setKeepAlive: () => stream,
    setTimeout: () => stream,
    ref: () => stream,
    unref: () => stream,
  });
}

interface ForwardOptions {
  readonly logicalHost: string;
  readonly open: () => Promise<NodeStream.Duplex>;
  readonly authorize?: (
    method: string,
    path: string,
    headers: NodeHttp.OutgoingHttpHeaders,
    upgrade: boolean,
  ) => Promise<{ path: string; headers: NodeHttp.OutgoingHttpHeaders }>;
  readonly access?: (request: NodeHttp.IncomingMessage) => boolean;
  readonly allowedOrigin?: string;
}

export function fixedHttpProxy(options: ForwardOptions): NodeHttp.Server {
  const active = new Set<NodeStream.Duplex>();
  let requests = 0;
  const headerTimers = new Map<NodeStream.Duplex, ReturnType<typeof setTimeout>>();
  const server = NodeHttp.createServer({
    maxHeaderSize: 16 * 1024,
    headersTimeout: 10_000,
    requestTimeout: 0,
    keepAlive: false,
  });
  server.maxConnections = 64;
  server.on("connection", (socket) => {
    if (active.size >= 64) {
      socket.destroy();
      return;
    }
    active.add(socket);
    // HttpServer's listening timer is absent for QUIC-injected sockets.
    const timer = setTimeout(() => socket.destroy(), 10_000);
    timer.unref();
    headerTimers.set(socket, timer);
    socket.on("error", () => {});
    socket.once("close", () => {
      active.delete(socket);
      clearTimeout(headerTimers.get(socket));
      headerTimers.delete(socket);
    });
  });
  const responseHeaders = (headers: NodeHttp.IncomingHttpHeaders) => {
    const result = forwardingHeaders(headers, options.logicalHost);
    delete result.host;
    if (options.allowedOrigin) {
      result["access-control-allow-origin"] = options.allowedOrigin;
      result.vary = "Origin";
    }
    return result;
  };
  const open = async (request: NodeHttp.IncomingMessage, upgrade: boolean) => {
    if (requests >= MAX_STREAMS) throw new Error("Gateway capacity reached.");
    if (!allowedServicePath(request.url ?? "/") || (options.access && !options.access(request)))
      throw new Error("Gateway access denied.");
    requests++;
    let socket: NodeStream.Duplex | undefined;
    try {
      let path = request.url ?? "/";
      let headers = forwardingHeaders(request.headers, options.logicalHost);
      if (options.authorize)
        ({ path, headers } = await options.authorize(
          request.method ?? "GET",
          path,
          headers,
          upgrade,
        ));
      if (upgrade) {
        headers.connection = "Upgrade";
        headers.upgrade = "websocket";
      } else headers.connection = "close";
      socket = httpSocket(await options.open());
      if (request.destroyed) {
        socket.destroy();
        throw new Error("Request cancelled.");
      }
      const agent = new NodeHttp.Agent({ keepAlive: false, maxSockets: 1 });
      agent.createConnection = () => socket;
      const outgoing = NodeHttp.request({
        host: options.logicalHost,
        port: 80,
        path,
        method: request.method,
        headers,
        agent,
      });
      outgoing.once("close", () => {
        requests--;
        agent.destroy();
      });
      outgoing.on("error", () => {});
      request.once("aborted", () => outgoing.destroy());
      return outgoing;
    } catch {
      requests--;
      socket?.destroy();
      throw new Error("Gateway request failed.");
    }
  };
  server.on("request", (request, response) => {
    clearTimeout(headerTimers.get(request.socket));
    headerTimers.delete(request.socket);
    if (
      request.method === "OPTIONS" &&
      options.allowedOrigin &&
      request.headers.origin === options.allowedOrigin &&
      options.access
    ) {
      response.writeHead(204, {
        "access-control-allow-origin": options.allowedOrigin,
        "access-control-allow-methods": "GET,HEAD,POST,PUT,DELETE,OPTIONS",
        "access-control-allow-headers":
          "authorization,content-type,dpop,x-t3-orchestration-protocol,range",
        "access-control-max-age": "600",
        vary: "Origin",
      });
      response.end();
      return;
    }
    void open(request, false)
      .then((outgoing) => {
        outgoing.once("response", (incoming) => {
          response.writeHead(incoming.statusCode ?? 502, responseHeaders(incoming.headers));
          incoming.pipe(response);
          incoming.on("error", () => response.destroy());
          response.once("close", () => {
            if (!response.writableFinished) outgoing.destroy();
          });
        });
        outgoing.once("error", () => {
          if (!response.headersSent) response.writeHead(502);
          response.end();
        });
        request.pipe(outgoing);
      })
      .catch(() => {
        response.writeHead(403);
        response.end();
      });
  });
  server.on("upgrade", (request, downstream, head) => {
    clearTimeout(headerTimers.get(request.socket));
    headerTimers.delete(request.socket);
    if (request.headers.upgrade?.toLowerCase() !== "websocket") {
      downstream.destroy();
      return;
    }
    void open(request, true)
      .then((outgoing) => {
        outgoing.once("upgrade", (incoming, upstream, upstreamHead) => {
          const headers = responseHeaders(incoming.headers);
          headers.connection = "Upgrade";
          headers.upgrade = "websocket";
          downstream.write(
            `HTTP/1.1 101 Switching Protocols\r\n${Object.entries(headers)
              .map(([key, value]) => `${key}: ${value}`)
              .join("\r\n")}\r\n\r\n`,
          );
          if (upstreamHead.length) downstream.write(upstreamHead);
          if (head.length) upstream.write(head);
          downstream.pipe(upstream).pipe(downstream);
          downstream.once("close", () => upstream.destroy());
          upstream.once("close", () => downstream.destroy());
          upstream.on("error", () => downstream.destroy());
        });
        outgoing.once("response", (incoming) => {
          incoming.resume();
          downstream.destroy();
        });
        outgoing.once("error", () => downstream.destroy());
        downstream.once("close", () => outgoing.destroy());
        outgoing.end();
      })
      .catch(() => downstream.destroy());
  });
  server.on("clientError", (_error, socket) => socket.destroy());
  const close = server.close.bind(server);
  server.close = (callback) => {
    for (const socket of active) socket.destroy();
    return close(callback);
  };
  return server;
}

export async function listenGateway(
  server: NodeHttp.Server,
  token = NodeCrypto.randomBytes(32).toString("base64url"),
) {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("Gateway failed to bind loopback.");
  return { httpBaseUrl: `http://127.0.0.1:${address.port}`, gatewayToken: token };
}
