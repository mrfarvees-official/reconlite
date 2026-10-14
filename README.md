# Recon Suite — Passive Website Security Inspector

A Kali-style terminal in the browser that runs **passive** security checks against a domain.
**No payloads sent — inspection only.** Every check reads what a server, DNS zone or page already discloses.

```bash
npm install
npm run dev        # http://localhost:3000
```

Optional: `NVD_API_KEY=<key>` raises the NVD rate limit from 5 to 50 requests / 30 s.

## Commands
`scan <domain>` · `modules` · `report` (`report pdf`) · `clear` · `help` — ↑/↓ history, Tab completion, Ctrl+C aborts a scan.

## Architecture
- `app/api/scan/route.ts` — POST, streams Server-Sent Events as each module finishes. All checks run server-side.
- `lib/modules/*` — one isolated function per check, each returning `{ id, severity, title, detail, fix }[]`.
- `lib/net.ts` — every outbound connection resolves through `safeLookup`, which refuses private/loopback/link-local
  addresses at connect time (SSRF and DNS-rebinding guard). Only HTTPS/443, bodies capped, timeouts everywhere.
- `lib/ratelimit.ts` — 5 scans / 10 min and 1 concurrent scan per IP (in-memory; swap for Redis/KV if scaled out).
- The server rejects scans unless the authorization checkbox was confirmed.
- `components/Terminal.tsx` — hidden `<input>` + styled text + separate blinking caret element.

## Modules
headers · cookies · cors · tls · dns · tech · cve · sqlleak — see `CASE_STUDY.md`.

## Scope (will not be added)
Active SQLi/XSS/command-injection testing, brute-force login or directory enumeration, or any request designed to break or exploit a target.

## Notes
- CVE matching is version-based and can produce false positives when fixes are backported without a version bump.
- `x-forwarded-for` is trusted for rate limiting; deploy behind a proxy that sets it correctly.
