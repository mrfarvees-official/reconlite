# Recon Suite: a passive security inspector with a deliberately small scope

**Stack:** Next.js (App Router), TypeScript, Tailwind, Server-Sent Events. **Posture:** inspection only.

## The idea
I wanted a project that shows I can read a site's security posture the way a reviewer would, without touching anything that
could harm it. Recon Suite takes a domain, runs eight checks server-side in parallel and streams each module's findings into
a Kali-style terminal as they finish. Every check reads something the target already publishes: response headers, cookie
flags, certificate metadata, DNS TXT records, version banners. "No payloads sent — inspection only" is on screen at all times.

## What each module checks
| Module | What it reads | Why it matters |
|---|---|---|
| **headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | Missing or weak headers remove browser-enforced defenses against XSS, downgrade and clickjacking. Findings include a copy-pasteable fix. |
| **cookies** | `Set-Cookie` attributes | `Secure`, `HttpOnly` and `SameSite` limit theft and cross-site sending. Session-looking names are rated higher. |
| **cors** | `Access-Control-Allow-*` for a made-up `Origin` | See below. |
| **tls** | Cert trust, expiry, negotiated protocol, whether a legacy-only handshake is accepted | Expired or untrusted certs and TLS < 1.2 are the classic transport failures. |
| **dns** | SPF and DMARC TXT via DNS-over-HTTPS | Without enforced SPF/DMARC anyone can spoof the domain in email. |
| **tech** | `Server`, `X-Powered-By`, `<meta generator>`, JS library filenames | Exact versions tell an attacker which known bugs to try. |
| **cve** | NVD lookup by CPE for fingerprinted product+version | Turns banners into a concrete patching to-do list. Cached, rate-limit aware. |
| **sqlleak** | Verbose DB error text in responses served anyway | `SQLSTATE`, `ORA-`, `pg_query()` in a page shows engine and query structure. Only the homepage, `/robots.txt` and `/.well-known/security.txt` are inspected; nothing malformed is sent. |

## Why CORS + credentials is dangerous
Browsers stop a page on `evil.example` from reading responses from `bank.example`. CORS is how a server relaxes that rule.
If the server reflects whatever `Origin` it receives into `Access-Control-Allow-Origin` and also sends
`Access-Control-Allow-Credentials: true`, then any website a logged-in user visits can make a request with the user's cookies
and read the authenticated response. That is account data exfiltration without any bug in the victim's session handling.
The module sends one normal request with `Origin: https://cors-probe.local` and reads the answer. If that fake origin comes
back reflected alongside credentials, it's rated high. No cross-origin request is ever completed against user data.

## The version-to-CVE false-positive caveat
The `cve` module matches a disclosed version string to NVD entries. That is a hint, not proof. Distributions routinely
backport a security fix into an older version number (Debian's `nginx 1.18.0` may be patched), so the banner says
"vulnerable" while the binary isn't. The reverse also happens: a hidden banner doesn't mean patched. So the UI always says:
*version-based matching can produce false positives if a fix was backported without a version bump.* Results are phrased as
"verify the real patch level" rather than "you are vulnerable".

## Engineering notes
- **SSRF is the real risk of a scanner.** A tool that fetches user-supplied hostnames can be pointed at `169.254.169.254`
  or `localhost`. All sockets go through a custom `lookup` that rejects private, loopback and link-local results at connect
  time (which also defeats DNS rebinding), IP literals and non-public suffixes are refused up front, and only HTTPS/443 is used.
- **Abuse controls:** consent checkbox enforced server-side, 5 scans per 10 minutes and one concurrent scan per IP,
  capped response bodies, per-module timeouts.
- **Streaming:** modules run with `Promise.all`; each emits an SSE frame as it completes and the terminal replaces its
  "scanning…" line in place. A shared memoised page fetch means the target sees one homepage request, not four.
- **NVD limits:** unauthenticated access allows 5 requests per 30 s, so lookups are spaced globally, cached for six hours and
  capped at four per scan; `NVD_API_KEY` raises the limit.
- **Errors:** unresolved domains, timeouts and refused connections print one terminal-style line, never a stack trace.
  Report HTML escapes all scanned text, because it comes from a server I don't control.

## What I didn't build, and why
I deliberately left out active exploitation testing: SQL injection, XSS and command-injection payloads, brute-forcing
logins, and directory enumeration.

- **Authorization is the line.** Reading public headers needs no permission; sending an exploit string to a system does.
  A public web form can't verify that a visitor owns the target, and a checkbox only reduces misuse, it doesn't prevent it.
- **Harm is asymmetric.** A payload that triggers a bug can corrupt data or take down a service. A missing HSTS header can't.
- **It would change what the project is.** A passive inspector is a defensible reporting tool; an active scanner is a weapon
  that needs scoping documents, rules of engagement and rate controls I can't provide from a portfolio site.
- **I can still find the same classes of problem safely.** The sql-error-leak module looks for database errors in responses
  the site would serve anyway. It shows the weakness without causing it.

If I extended this for real engagements, active testing would live in a separate tool that requires verified domain
ownership (DNS TXT challenge or a well-known file), a signed scope, and an audit log, not a checkbox.

## Limitations
Single-page view (landing page, not authenticated flows); in-memory rate limiting; heuristic parsing of banners;
organizational-domain detection for DMARC fallback is naïve for multi-part TLDs like `co.uk`.
