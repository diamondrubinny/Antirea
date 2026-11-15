/*!
 * Antirea — anti reverse-engineering toolkit.
 * @author Diamond Rubinny
 * @license Apache-2.0
 * Copyright (c) 2026 Diamond Rubinny. All rights reserved.
 * Credit required: keep this notice (Apache-2.0 §4) in all copies and derivatives.
 */
/**
 * Bridge from Node's `(IncomingMessage, ServerResponse)` to the Fetch-API
 * handler (`@antirea/secure-fn/node`). Use it with `node:http` directly, or
 * with frameworks that expose the raw request and response (Fastify).
 *
 * The request body is streamed to the handler, which enforces its own size
 * limit; nothing is buffered here. The socket address is passed as the
 * connection IP, so `trustProxy` works the same as in the other adapters.
 */
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import type { SecureFnHandler } from "./web.js";

export type NodeListener = (req: IncomingMessage, res: ServerResponse) => void;

/** Wrap a Fetch-API secure-fn handler as a Node request listener. */
export function createNodeListener(handler: SecureFnHandler): NodeListener {
  return (req, res) => {
    void (async () => {
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers)) {
        if (value === undefined) continue;
        if (Array.isArray(value)) for (const v of value) headers.append(name, v);
        else headers.set(name, value);
      }
      const method = req.method ?? "GET";
      const hasBody = method !== "GET" && method !== "HEAD";
      // The host only makes the URL absolute; the handler routes on the path.
      const url = new URL(req.url ?? "/", "http://localhost");
      const request = new Request(url, {
        method,
        headers,
        body: hasBody ? (Readable.toWeb(req) as ReadableStream<Uint8Array>) : undefined,
        // Required by Node for a streamed request body.
        ...(hasBody ? { duplex: "half" } : {}),
      } as RequestInit);

      const response = await handler(request, { ip: req.socket.remoteAddress ?? "" });
      res.statusCode = response.status;
      response.headers.forEach((value, name) => res.setHeader(name, value));
      res.end(Buffer.from(await response.arrayBuffer()));
    })().catch(() => {
      // Never leak internals; the handler itself already answers errors as JSON.
      if (!res.headersSent) {
        res.statusCode = 500;
        res.setHeader("content-type", "application/json; charset=utf-8");
      }
      res.end('{"error":"internal"}');
    });
  };
}
