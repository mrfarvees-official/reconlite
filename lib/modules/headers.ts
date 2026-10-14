import type { ScanContext } from "../context";
import type { Finding } from "../types";

/** Reads headers from the normal homepage response. Nothing is sent beyond a plain GET. */
export async function headersModule(_domain: string, ctx: ScanContext): Promise<Finding[]> {
  const { final } = await ctx.page();
  const h = final.headers;
  const out: Finding[] = [];
  const str = (v: string | string[] | undefined) => (Array.isArray(v) ? v.join(", ") : (v ?? ""));

  // Content-Security-Policy
  const csp = str(h["content-security-policy"]);
  if (!csp) {
    out.push({
      id: "headers.csp.missing", severity: "medium", title: "Content-Security-Policy missing",
      detail: "No CSP header. Injected scripts (XSS) run unrestricted if an injection bug exists.",
      fix: "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self' — then loosen per resource.",
    });
  } else {
    const weak: string[] = [];
    const scriptDirective = /(?:^|;)\s*(?:script-src|default-src)\s+([^;]*)/i.exec(csp)?.[1] ?? "";
    if (/'unsafe-inline'/.test(scriptDirective) && !/'nonce-|'sha(256|384|512)-/.test(scriptDirective)) weak.push("'unsafe-inline' in script policy");
    if (/'unsafe-eval'/.test(scriptDirective)) weak.push("'unsafe-eval' in script policy");
    if (/(^|\s)\*(\s|$)/.test(scriptDirective)) weak.push("wildcard (*) script source");
    if (/(^|\s)https?:(\s|$)/.test(scriptDirective)) weak.push("scheme-wide script source (http:/https:)");
    if (weak.length) {
      out.push({
        id: "headers.csp.weak", severity: "medium", title: "Content-Security-Policy is permissive",
        detail: `CSP present but weakened by: ${weak.join("; ")}.`,
        fix: "Replace 'unsafe-inline' with nonces or hashes, drop 'unsafe-eval', and list explicit script origins.",
      });
    } else {
      out.push({ id: "headers.csp.ok", severity: "ok", title: "Content-Security-Policy present", detail: "CSP is set with no obviously unsafe script sources.", fix: "" });
    }
  }

  // Strict-Transport-Security
  const hsts = str(h["strict-transport-security"]);
  if (!hsts) {
    out.push({
      id: "headers.hsts.missing", severity: "medium", title: "Strict-Transport-Security missing",
      detail: "Browsers are not told to insist on HTTPS, leaving first-visit and downgrade/SSL-strip windows open.",
      fix: "Strict-Transport-Security: max-age=31536000; includeSubDomains (add preload only after verifying all subdomains).",
    });
  } else {
    const age = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0);
    if (age < 15_552_000) {
      out.push({
        id: "headers.hsts.short", severity: "low", title: "HSTS max-age is short",
        detail: `max-age=${age} (< 180 days). Protection lapses quickly between visits.`,
        fix: "Raise max-age to at least 31536000 (1 year).",
      });
    } else {
      out.push({ id: "headers.hsts.ok", severity: "ok", title: "Strict-Transport-Security configured", detail: hsts, fix: "" });
    }
  }

  // Clickjacking: X-Frame-Options or CSP frame-ancestors
  const xfo = str(h["x-frame-options"]);
  const hasFrameAncestors = /frame-ancestors/i.test(csp);
  if (!xfo && !hasFrameAncestors) {
    out.push({
      id: "headers.xfo.missing", severity: "medium", title: "Clickjacking protection missing",
      detail: "Neither X-Frame-Options nor CSP frame-ancestors is set, so the site can be framed by any origin.",
      fix: "X-Frame-Options: DENY (or SAMEORIGIN), or preferably CSP frame-ancestors 'none'/'self'.",
    });
  } else if (xfo && !/^(deny|sameorigin)$/i.test(xfo.trim())) {
    out.push({
      id: "headers.xfo.invalid", severity: "low", title: "X-Frame-Options value unrecognised",
      detail: `Value "${xfo}" is obsolete or invalid (ALLOW-FROM is ignored by modern browsers).`,
      fix: "Use DENY or SAMEORIGIN, or CSP frame-ancestors.",
    });
  } else {
    out.push({ id: "headers.xfo.ok", severity: "ok", title: "Clickjacking protection present", detail: xfo || "via CSP frame-ancestors", fix: "" });
  }

  // X-Content-Type-Options
  const xcto = str(h["x-content-type-options"]);
  if (!/nosniff/i.test(xcto)) {
    out.push({
      id: "headers.xcto.missing", severity: "low", title: "X-Content-Type-Options missing",
      detail: "Without nosniff, browsers may MIME-sniff responses and execute content as a different type.",
      fix: "X-Content-Type-Options: nosniff",
    });
  } else {
    out.push({ id: "headers.xcto.ok", severity: "ok", title: "X-Content-Type-Options: nosniff", detail: "", fix: "" });
  }

  // Referrer-Policy
  const rp = str(h["referrer-policy"]).toLowerCase();
  if (!rp) {
    out.push({
      id: "headers.referrer.missing", severity: "low", title: "Referrer-Policy missing",
      detail: "Browser defaults apply; full URLs (possibly containing tokens or IDs) may leak to third parties.",
      fix: "Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
    });
  } else if (/(^|,\s*)(unsafe-url|no-referrer-when-downgrade|origin-when-cross-origin)\s*$/.test(rp)) {
    out.push({
      id: "headers.referrer.weak", severity: "low", title: "Referrer-Policy leaks full URLs",
      detail: `Value "${rp}" may send path/query data cross-origin.`,
      fix: "Use strict-origin-when-cross-origin, same-origin or no-referrer.",
    });
  } else {
    out.push({ id: "headers.referrer.ok", severity: "ok", title: "Referrer-Policy configured", detail: rp, fix: "" });
  }

  // Permissions-Policy
  if (!str(h["permissions-policy"])) {
    out.push({
      id: "headers.permissions.missing", severity: "low", title: "Permissions-Policy missing",
      detail: "Powerful browser features (camera, mic, geolocation) are not explicitly restricted.",
      fix: "Permissions-Policy: camera=(), microphone=(), geolocation=() — enable only what the site uses.",
    });
  } else {
    out.push({ id: "headers.permissions.ok", severity: "ok", title: "Permissions-Policy configured", detail: "", fix: "" });
  }

  return out;
}
