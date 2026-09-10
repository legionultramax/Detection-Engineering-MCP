// Transport selection.
//
// stdio remains the default, so a Claude Desktop configuration that has always
// worked keeps working and nothing about this file affects it. HTTP is opt-in
// via HAWKEYE_TRANSPORT=http, and exists because Open WebUI cannot speak stdio
// MCP — without it the server is unreachable from the browser regardless of how
// well everything else works.
//
// The HTTP transport runs stateless: one transport, no session table, a JSON
// response per request. That is the shape an OpenAPI bridge wants, and it means
// there is no session state to leak between callers or to leave behind when one
// disconnects mid-request.

import http from 'node:http';
import { timingSafeEqual, randomUUID } from 'node:crypto';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';

export type TransportKind = 'stdio' | 'http';

export interface HttpConfig {
  host: string;
  port: number;
  token: string | null;
  path: string;
}

export class TransportConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TransportConfigError';
  }
}

/** Loopback addresses, where an unauthenticated listener is defensible. */
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);

export function resolveTransport(env: NodeJS.ProcessEnv = process.env): TransportKind {
  const raw = (env.HAWKEYE_TRANSPORT ?? '').trim().toLowerCase();
  if (raw === '' || raw === 'stdio') return 'stdio';
  if (raw === 'http' || raw === 'streamable-http') return 'http';
  throw new TransportConfigError(
    `Unknown HAWKEYE_TRANSPORT "${env.HAWKEYE_TRANSPORT}". Use "stdio" (default) or "http".`
  );
}

/**
 * Read and validate the HTTP configuration.
 *
 * Refuses to bind a non-loopback address without a token. The database holds
 * client detection logic, and an unauthenticated listener on 0.0.0.0 hands it
 * to anyone who can route to the host. Failing to start is the correct response
 * to that configuration, not a warning nobody reads.
 */
export function resolveHttpConfig(env: NodeJS.ProcessEnv = process.env): HttpConfig {
  const host = (env.HAWKEYE_HTTP_HOST ?? '127.0.0.1').trim();
  const portRaw = (env.HAWKEYE_HTTP_PORT ?? '8765').trim();
  const port = Number(portRaw);
  const token = (env.HAWKEYE_HTTP_TOKEN ?? '').trim() || null;
  const path = (env.HAWKEYE_HTTP_PATH ?? '/mcp').trim();

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new TransportConfigError(
      `HAWKEYE_HTTP_PORT must be a port number between 1 and 65535, got "${portRaw}".`
    );
  }
  if (!path.startsWith('/')) {
    throw new TransportConfigError(`HAWKEYE_HTTP_PATH must start with "/", got "${path}".`);
  }
  if (!LOOPBACK.has(host) && !token) {
    throw new TransportConfigError(
      `Refusing to bind ${host} without HAWKEYE_HTTP_TOKEN. This server exposes the detection ` +
      'corpus and the tool surface; on a non-loopback address that needs authentication. Either ' +
      'set a token, or bind 127.0.0.1 and reach it through a tunnel.'
    );
  }
  return { host, port, token, path };
}

/** Constant-time bearer comparison, so the token cannot be probed byte by byte. */
function tokenMatches(expected: string, presented: string): boolean {
  const a = Buffer.from(expected);
  const b = Buffer.from(presented);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function authorized(req: http.IncomingMessage, token: string | null): boolean {
  if (!token) return true;
  const header = req.headers.authorization ?? '';
  const m = /^Bearer\s+(.+)$/i.exec(header);
  if (!m) return false;
  return tokenMatches(token, m[1].trim());
}

function firstHeader(v: string | string[] | undefined): string | undefined {
  if (Array.isArray(v)) return v[0];
  return v;
}

/** Is this the request that starts a session? */
function isInitializeRequest(body: unknown): boolean {
  if (!body) return false;
  const one = (b: unknown) =>
    typeof b === 'object' && b !== null && (b as { method?: unknown }).method === 'initialize';
  return Array.isArray(body) ? body.some(one) : one(body);
}

/** Body size ceiling, so an oversized POST cannot exhaust memory. */
const MAX_BODY_BYTES = 4 * 1024 * 1024;

async function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > MAX_BODY_BYTES) {
      throw new Error(`Request body exceeds ${MAX_BODY_BYTES} bytes.`);
    }
    chunks.push(buf);
  }
  if (total === 0) return undefined;
  const text = Buffer.concat(chunks).toString('utf8');
  try {
    return JSON.parse(text);
  } catch {
    // Let the transport produce the protocol-shaped parse error rather than
    // inventing one here.
    return undefined;
  }
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

export interface StartedHttpServer {
  close(): Promise<void>;
  url: string;
}

/**
 * Serve MCP over HTTP.
 *
 * Resolves once the socket is listening, so a caller can report a real address
 * rather than announcing a port that may not have bound.
 */
export async function startHttpTransport(
  createServer: () => Server,
  cfg: HttpConfig
): Promise<StartedHttpServer> {
  // A session owns a transport and a Server, because neither can be shared.
  //
  // The tempting alternative is one stateless transport handling every request.
  // That does not work: in stateless mode the transport completes after a single
  // exchange, so initialize succeeds and the next request gets a 500. The SDK's
  // own stateless example builds a fresh transport *and* server per request for
  // exactly this reason.
  //
  // Sessions are the better trade here anyway. createServer() is cheap — the
  // tool registry is a module singleton, so only the protocol wrapper and the
  // generated instructions are per-session — and a session gives each client
  // its own protocol state instead of interleaving them.
  const sessions = new Map<string, StreamableHTTPServerTransport>();

  const httpServer = http.createServer((req, res) => {
    void (async () => {
      try {
        const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);

        // Unauthenticated liveness check. Deliberately says nothing about the
        // corpus or the tool surface — enough to answer "is it up?" and no more.
        if (url.pathname === '/health') {
          sendJson(res, 200, { status: 'ok', transport: 'http', sessions: sessions.size });
          return;
        }

        if (url.pathname !== cfg.path) {
          sendJson(res, 404, {
            error: 'not_found',
            message: `No handler for ${url.pathname}. MCP is served at ${cfg.path}.`,
          });
          return;
        }

        if (!authorized(req, cfg.token)) {
          res.setHeader('WWW-Authenticate', 'Bearer');
          sendJson(res, 401, {
            error: 'unauthorized',
            message: 'Provide the bearer token in an Authorization header.',
          });
          return;
        }

        // The body has to be read here rather than left to the transport,
        // because routing depends on whether this is an initialize request.
        const body = req.method === 'POST' ? await readJsonBody(req) : undefined;
        const sessionId = firstHeader(req.headers['mcp-session-id']);

        let transport = sessionId ? sessions.get(sessionId) : undefined;

        if (!transport) {
          if (!isInitializeRequest(body)) {
            sendJson(res, 400, {
              jsonrpc: '2.0',
              error: {
                code: -32000,
                message: sessionId
                  ? `Unknown session ${sessionId}. Send an initialize request to start a new one.`
                  : 'No Mcp-Session-Id header. Send an initialize request first, then include ' +
                    'the Mcp-Session-Id it returns on every subsequent request.',
              },
              id: null,
            });
            return;
          }

          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            enableJsonResponse: true,
            onsessioninitialized: (sid: string) => {
              sessions.set(sid, transport as StreamableHTTPServerTransport);
            },
          });
          // Drop the session when the client goes away, so a long-lived server
          // does not accumulate transports for clients that never come back.
          transport.onclose = () => {
            const sid = transport?.sessionId;
            if (sid) sessions.delete(sid);
          };
          await createServer().connect(transport);
        }

        await transport.handleRequest(req, res, body);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(`[transport] request failed: ${message}`);
        if (!res.headersSent) {
          sendJson(res, 500, { error: 'internal_error', message });
        } else {
          res.end();
        }
      }
    })();
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(cfg.port, cfg.host, () => {
      httpServer.removeListener('error', reject);
      resolve();
    });
  });

  const shown = cfg.host === '::1' ? `[${cfg.host}]` : cfg.host;
  const url = `http://${shown}:${cfg.port}${cfg.path}`;

  console.error(`[transport] MCP over HTTP at ${url}`);
  console.error(`[transport] health check at http://${shown}:${cfg.port}/health`);
  console.error(
    cfg.token
      ? '[transport] bearer token required'
      : '[transport] no token set — acceptable on loopback only'
  );

  return {
    url,
    close: async () => {
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
      for (const t of sessions.values()) {
        try { await t.close(); } catch { /* already closing */ }
      }
      sessions.clear();
    },
  };
}

/** Serve MCP over stdio. The default, and what Claude Desktop uses. */
export async function startStdioTransport(server: Server): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
