import dns from "node:dns";
import https from "node:https";
import net from "node:net";
import type { IncomingHttpHeaders } from "node:http";

export const USER_AGENT =
  "ReconSuite/1.0 (passive inspection; read-only requests; portfolio project)";

const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const DOMAIN_RE = new RegExp(
  `^(?=.{1,253}$)(?:${LABEL}\\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$`,
);
const BLOCKED_SUFFIXES = [".local", ".localhost", ".internal", ".lan", ".home", ".corp"];

/** Normalises user input to a bare hostname, or null when it is not an acceptable public domain. */
export function normalizeDomain(input: string): string | null {
  let s = input.trim().toLowerCase();
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "").split(/[/?#]/)[0].replace(/\.$/, "");
  if (!s || net.isIP(s)) return null;
  if (!DOMAIN_RE.test(s)) return null;
  if (s === "localhost" || BLOCKED_SUFFIXES.some((x) => s.endsWith(x))) return null;
  return s;
}

export function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b, c] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0 && c === 0) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === "::" || l === "::1") return true;
    const mapped = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIp(mapped[1]);
    if (l.startsWith("::ffff:") || l.startsWith("64:ff9b:") || l.startsWith("2001:db8")) return true;
    const first = parseInt(l.split(":")[0] || "0", 16);
    return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00;
  }
  return true;
}

/**
 * DNS lookup used for every outbound connection. It runs at connect time, so a hostname
 * that resolves to a private/loopback/link-local address (SSRF, DNS rebinding) is refused.
 */
export const safeLookup = ((hostname: string, options: dns.LookupOptions, cb: (...args: unknown[]) => void) => {
  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err);
    const list = addrs as dns.LookupAddress[];
    if (list.length === 0 || list.some((a) => isPrivateIp(a.address))) {
      const e = new Error(`blocked: ${hostname} resolves to a non-public address`) as NodeJS.ErrnoException;
      e.code = "EBLOCKED";
      return cb(e);
    }
    if (options.all) return cb(null, list);
    cb(null, list[0].address, list[0].family);
  });
}) as net.LookupFunction;

export interface HttpResult {
  status: number;
  headers: IncomingHttpHeaders;
  setCookies: string[];
  body: string;
  host: string;
  path: string;
}

export interface RequestOpts {
  path?: string;
  headers?: Record<string, string>;
  maxBytes?: number;
  timeoutMs?: number;
}

/** A single HTTPS GET on port 443. No redirects followed, body capped, certificate errors tolerated (reported by the tls module). */
export function httpsGet(host: string, opts: RequestOpts = {}): Promise<HttpResult> {
  const path = opts.path ?? "/";
  const maxBytes = opts.maxBytes ?? 512 * 1024;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host,
        port: 443,
        path,
        method: "GET",
        lookup: safeLookup,
        servername: host,
        rejectUnauthorized: false,
        headers: {
          "user-agent": USER_AGENT,
          accept: "text/html,application/xhtml+xml,*/*;q=0.8",
          "accept-encoding": "identity",
          ...opts.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let finished = false;
        const finish = () => {
          if (finished) return;
          finished = true;
          clearTimeout(deadline);
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            setCookies: res.headersDistinct["set-cookie"] ?? [],
            body: Buffer.concat(chunks).toString("utf8"),
            host,
            path,
          });
        };
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size <= maxBytes) chunks.push(c);
          else res.destroy();
        });
        res.on("end", finish);
        res.on("close", finish);
        res.on("error", finish);
      },
    );
    const deadline = setTimeout(() => {
      const e = new Error("request timed out") as NodeJS.ErrnoException;
      e.code = "ETIMEDOUT";
      req.destroy(e);
    }, timeoutMs);
    req.on("error", (e) => {
      clearTimeout(deadline);
      reject(e);
    });
    req.end();
  });
}

/** Turns low-level errors into terminal-style one-liners (never a stack trace). */
export function friendlyError(e: unknown): string {
  const err = e as NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException };
  const code = err?.code ?? err?.cause?.code;
  switch (code) {
    case "ENOTFOUND":
    case "ENODATA":
    case "EAI_AGAIN":
      return "host could not be resolved (no DNS record)";
    case "ETIMEDOUT":
    case "ESOCKETTIMEDOUT":
    case "UND_ERR_CONNECT_TIMEOUT":
      return "connection timed out";
    case "ECONNREFUSED":
      return "connection refused on port 443";
    case "ECONNRESET":
      return "connection reset by peer";
    case "EBLOCKED":
      return "target resolves to a non-public address; refusing to connect";
  }
  if (err?.name === "TimeoutError" || err?.name === "AbortError") return "operation timed out";
  const msg = err instanceof Error ? err.message : String(e);
  return msg.split("\n")[0].slice(0, 160);
}

export function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      const e = new Error("module timed out") as NodeJS.ErrnoException;
      e.code = "ETIMEDOUT";
      reject(e);
    }, ms);
    p.then(
      (v) => { clearTimeout(t); resolve(v); },
      (e) => { clearTimeout(t); reject(e); },
    );
  });
}
