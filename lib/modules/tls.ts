import tls from "node:tls";
import { safeLookup } from "../net";
import type { Finding } from "../types";

interface Handshake {
  protocol: string | null;
  cipher: string | null;
  cert: tls.PeerCertificate;
  authorized: boolean;
  authError: string | null;
}

function handshake(host: string, extra: tls.ConnectionOptions = {}): Promise<Handshake> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host, port: 443, servername: host, lookup: safeLookup, rejectUnauthorized: false, timeout: 8000, ...extra,
    }, () => {
      const result: Handshake = {
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name ?? null,
        cert: socket.getPeerCertificate(),
        authorized: socket.authorized,
        authError: socket.authorizationError ? String(socket.authorizationError) : null,
      };
      socket.end();
      resolve(result);
    });
    socket.on("timeout", () => {
      const e = new Error("tls handshake timed out") as NodeJS.ErrnoException;
      e.code = "ETIMEDOUT";
      socket.destroy(e);
    });
    socket.on("error", reject);
  });
}

export async function tlsModule(domain: string): Promise<Finding[]> {
  const hs = await handshake(domain);
  const out: Finding[] = [];

  if (!hs.authorized) {
    out.push({
      id: "tls.untrusted", severity: "high", title: "Certificate is not trusted",
      detail: `Verification failed: ${hs.authError ?? "unknown reason"}. Browsers will show a full-page warning.`,
      fix: "Install a certificate from a public CA that covers this hostname, including the full intermediate chain.",
    });
  } else {
    out.push({ id: "tls.trusted", severity: "ok", title: "Certificate chain is trusted and matches hostname", detail: `Issuer: ${issuerOf(hs.cert)}`, fix: "" });
  }

  const validTo = hs.cert.valid_to ? new Date(hs.cert.valid_to) : null;
  if (validTo && !Number.isNaN(validTo.getTime())) {
    const days = Math.floor((validTo.getTime() - Date.now()) / 86_400_000);
    const when = validTo.toISOString().slice(0, 10);
    if (days < 0) {
      out.push({ id: "tls.expired", severity: "critical", title: "Certificate has expired", detail: `Expired ${-days} day(s) ago (${when}).`, fix: "Renew immediately and automate renewal (ACME / Let's Encrypt, certbot, or your CDN's managed certs)." });
    } else if (days < 14) {
      out.push({ id: "tls.expiring", severity: "high", title: `Certificate expires in ${days} day(s)`, detail: `Not valid after ${when}.`, fix: "Renew now and verify automated renewal is working." });
    } else if (days < 30) {
      out.push({ id: "tls.expiring", severity: "medium", title: `Certificate expires in ${days} days`, detail: `Not valid after ${when}.`, fix: "Schedule renewal; confirm automation." });
    } else {
      out.push({ id: "tls.expiry.ok", severity: "ok", title: `Certificate valid for ${days} more days`, detail: `Not valid after ${when}.`, fix: "" });
    }
  }

  const proto = hs.protocol ?? "unknown";
  if (/^(SSLv|TLSv1(\.0|\.1)?$)/.test(proto)) {
    out.push({ id: "tls.protocol.old", severity: "high", title: `Negotiated protocol is ${proto}`, detail: "TLS below 1.2 is deprecated (RFC 8996) and has known weaknesses.", fix: "Disable TLS 1.0/1.1 and SSLv3; allow TLS 1.2 and 1.3 only." });
  } else {
    out.push({ id: "tls.protocol.ok", severity: "ok", title: `Negotiated ${proto}`, detail: hs.cipher ? `Cipher: ${hs.cipher}` : "", fix: "" });
  }

  // Legacy acceptance: a normal handshake that only offers TLS 1.0/1.1. Best-effort; modern
  // OpenSSL builds may refuse to offer these at all, in which case the probe is inconclusive.
  try {
    const legacy = await handshake(domain, { minVersion: "TLSv1", maxVersion: "TLSv1.1" });
    out.push({ id: "tls.legacy.accepted", severity: "high", title: `Server still accepts ${legacy.protocol ?? "TLS 1.0/1.1"}`, detail: "A handshake offering only legacy protocol versions succeeded.", fix: "Set the minimum protocol to TLS 1.2 on the server / load balancer." });
  } catch {
    out.push({ id: "tls.legacy.rejected", severity: "ok", title: "Legacy TLS 1.0/1.1 not accepted", detail: "Handshake offering only TLS 1.0/1.1 was refused (or this client cannot offer them).", fix: "" });
  }

  return out;
}

function issuerOf(cert: tls.PeerCertificate): string {
  const i = cert.issuer as Record<string, string | string[]> | undefined;
  const v = i?.O ?? i?.CN;
  return Array.isArray(v) ? v.join(", ") : (v ?? "unknown");
}
