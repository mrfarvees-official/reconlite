import type { ScanContext } from "../context";
import type { Finding } from "../types";

const SESSIONISH = /sess|auth|token|jwt|sid|login|csrf|xsrf/i;

export async function cookiesModule(_domain: string, ctx: ScanContext): Promise<Finding[]> {
  const { setCookies } = await ctx.page();
  if (setCookies.length === 0) {
    return [{ id: "cookies.none", severity: "ok", title: "No cookies set on the initial response", detail: "Nothing to inspect for the landing page.", fix: "" }];
  }

  const out: Finding[] = [];
  for (const raw of setCookies) {
    const [pair, ...attrs] = raw.split(";").map((s) => s.trim());
    const name = pair.split("=")[0];
    const flags = new Map(attrs.map((a) => {
      const [k, ...v] = a.split("=");
      return [k.toLowerCase(), v.join("=")] as const;
    }));
    const sensitive = SESSIONISH.test(name);
    const problems: string[] = [];
    let sev: Finding["severity"] = "low";

    if (!flags.has("secure")) { problems.push("missing Secure"); sev = sensitive ? "medium" : "low"; }
    if (!flags.has("httponly")) { problems.push("missing HttpOnly"); if (sensitive) sev = "medium"; }
    const ss = flags.get("samesite")?.toLowerCase();
    if (!ss) problems.push("missing SameSite");
    else if (ss === "none" && !flags.has("secure")) { problems.push("SameSite=None without Secure (rejected by browsers)"); sev = "medium"; }

    if (problems.length === 0) {
      out.push({ id: `cookies.${name}.ok`, severity: "ok", title: `Cookie "${name}" has Secure, HttpOnly and SameSite`, detail: "", fix: "" });
    } else {
      out.push({
        id: `cookies.${name}.flags`, severity: sev, title: `Cookie "${name}": ${problems.join(", ")}`,
        detail: `${sensitive ? "Name looks session/auth related. " : ""}Secure stops sending over plain HTTP, HttpOnly hides it from JavaScript (limits XSS theft), SameSite limits cross-site sending (CSRF).`,
        fix: `Set-Cookie: ${name}=…; Secure; HttpOnly; SameSite=Lax (or Strict) — HttpOnly may be skipped only if client scripts genuinely need the value.`,
      });
    }
  }
  return out;
}
