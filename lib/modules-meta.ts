import type { ModuleMeta } from "./types";

// Client-safe module metadata (no Node imports) shared by the terminal and the scan route.
export const MODULE_META: ModuleMeta[] = [
  { id: "headers", title: "HTTP security headers", description: "CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy" },
  { id: "cookies", title: "Cookie flags", description: "Secure / HttpOnly / SameSite on Set-Cookie headers" },
  { id: "cors", title: "CORS configuration", description: "Access-Control-Allow-Origin / -Credentials response to a test Origin header" },
  { id: "tls", title: "TLS certificate & protocol", description: "Cert validity, expiry, negotiated protocol, legacy-protocol acceptance" },
  { id: "dns", title: "DNS email policy", description: "SPF and DMARC TXT records via DNS-over-HTTPS" },
  { id: "tech", title: "Technology fingerprint", description: "Server / X-Powered-By headers, generator meta tag, JS library filenames" },
  { id: "cve", title: "CVE match (NVD)", description: "Version-based CVE lookup for fingerprinted products" },
  { id: "sqlleak", title: "DB error-string leak (passive)", description: "Looks for verbose DB errors in responses that would be served anyway" },
];

export const CVE_CAVEAT =
  "version-based matching can produce false positives if a fix was backported without a version bump.";
