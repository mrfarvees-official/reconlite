import type { ScanContext } from "../context";
import { httpsGet } from "../net";
import type { Finding } from "../types";

const PROBE_ORIGIN = "https://cors-probe.local";

/**
 * Config check only: one ordinary GET carrying a made-up Origin header, then we read how the
 * server answers. No cross-origin request is completed against user data.
 */
export async function corsModule(_domain: string, ctx: ScanContext): Promise<Finding[]> {
  const { host } = await ctx.page();
  const res = await httpsGet(host, { headers: { origin: PROBE_ORIGIN }, maxBytes: 4096 });
  const acao = String(res.headers["access-control-allow-origin"] ?? "");
  const creds = String(res.headers["access-control-allow-credentials"] ?? "").toLowerCase() === "true";
  const note = " (Checked on the landing page only; APIs on this origin may differ.)";

  if (!acao) {
    return [{ id: "cors.none", severity: "ok", title: "No CORS headers returned for a foreign Origin", detail: "Cross-origin reads are denied by the browser's same-origin policy." + note, fix: "" }];
  }
  if (acao === PROBE_ORIGIN) {
    return creds
      ? [{
          id: "cors.reflected.credentials", severity: "high", title: "Origin reflected with Access-Control-Allow-Credentials: true",
          detail: `The server echoed an arbitrary origin (${PROBE_ORIGIN}) and allows credentials. Any website a logged-in user visits could read authenticated responses from this origin.`,
          fix: "Validate Origin against an explicit allow-list; never reflect it blindly. Do not combine credentials with dynamic origins unless the list is strict.",
        }]
      : [{
          id: "cors.reflected", severity: "medium", title: "Arbitrary Origin is reflected",
          detail: `The server echoed ${PROBE_ORIGIN} in Access-Control-Allow-Origin. Without credentials the exposure is limited to non-authenticated data, but it signals a permissive config.` + note,
          fix: "Replace reflection with an allow-list of trusted origins and add Vary: Origin.",
        }];
  }
  if (acao === "*") {
    return creds
      ? [{
          id: "cors.wildcard.credentials", severity: "high", title: "Wildcard ACAO with Access-Control-Allow-Credentials: true",
          detail: "Browsers refuse this combination, but it shows the CORS config is confused and often accompanies a reflection fallback on other routes.",
          fix: "Pick one: an explicit origin allow-list with credentials, or a wildcard without credentials for fully public data.",
        }]
      : [{
          id: "cors.wildcard", severity: "low", title: "Access-Control-Allow-Origin: *",
          detail: "Any origin may read this response. Fine for genuinely public assets; a problem if any sensitive data is served without extra auth." + note,
          fix: "Restrict to known origins unless the resource is intentionally public.",
        }];
  }
  if (acao === "null") {
    return [{
      id: "cors.null", severity: creds ? "high" : "medium", title: "Access-Control-Allow-Origin: null",
      detail: "The null origin can be produced by sandboxed iframes and local files, so trusting it is effectively trusting anyone." + (creds ? " Combined with credentials this is exploitable." : ""),
      fix: "Never allow the null origin.",
    }];
  }
  return [{ id: "cors.fixed", severity: "ok", title: "CORS restricted to a specific origin", detail: `Allow-Origin: ${acao.slice(0, 200)}${creds ? " (credentials allowed — confirm this origin is trusted)" : ""}`, fix: "" }];
}
