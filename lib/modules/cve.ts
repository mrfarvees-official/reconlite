import type { ScanContext } from "../context";
import { CVE_CAVEAT } from "../modules-meta";
import type { Finding, Severity } from "../types";

const NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const API_KEY = process.env.NVD_API_KEY;
// Unauthenticated: 5 requests / 30s. With a key: 50 / 30s. Space calls evenly, with margin.
const SPACING_MS = API_KEY ? 700 : 6500;
const CACHE_TTL_MS = 6 * 60 * 60 * 1000;
const MAX_LOOKUPS_PER_SCAN = 4;

/** product name (as fingerprinted) -> CPE vendor:product */
const CPE: Record<string, string> = {
  nginx: "f5:nginx",
  apache: "apache:http_server",
  "microsoft-iis": "microsoft:internet_information_services",
  lighttpd: "lighttpd:lighttpd",
  php: "php:php",
  wordpress: "wordpress:wordpress",
  drupal: "drupal:drupal",
  jquery: "jquery:jquery",
  bootstrap: "getbootstrap:bootstrap",
  lodash: "lodash:lodash",
  moment: "momentjs:moment",
  vue: "vuejs:vue",
  backbone: "backbonejs:backbone",
  handlebars: "handlebarsjs:handlebars",
  prototype: "prototypejs:prototype",
  openssl: "openssl:openssl",
};

interface CveHit { id: string; score: number }
interface CacheEntry { at: number; total: number; hits: CveHit[] }

const g = globalThis as unknown as { __nvdCache?: Map<string, CacheEntry>; __nvdNext?: number };
const cache = (g.__nvdCache ??= new Map());

/** Serialises NVD calls across concurrent scans so we never exceed the public rate limit. */
async function throttle(): Promise<void> {
  const now = Date.now();
  const slot = Math.max(now, g.__nvdNext ?? 0);
  g.__nvdNext = slot + SPACING_MS;
  if (slot > now) await new Promise((r) => setTimeout(r, slot - now));
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

async function lookup(cpeName: string): Promise<CacheEntry> {
  const hit = cache.get(cpeName);
  if (hit && Date.now() - hit.at < CACHE_TTL_MS) return hit;
  await throttle();
  const url = `${NVD}?cpeName=${encodeURIComponent(cpeName)}&noRejected&resultsPerPage=200`;
  const res = await fetch(url, {
    headers: API_KEY ? { apiKey: API_KEY } : {},
    signal: AbortSignal.timeout(20_000),
    cache: "no-store",
  });
  if (res.status === 403 || res.status === 429) throw new Error("NVD rate limit reached — try again in a minute (set NVD_API_KEY for higher limits)");
  if (!res.ok) throw new Error(`NVD returned HTTP ${res.status}`);
  const json = (await res.json()) as {
    totalResults: number;
    vulnerabilities: { cve: { id: string; metrics?: Record<string, { cvssData: { baseScore: number } }[]> } }[];
  };
  const hits: CveHit[] = json.vulnerabilities.map(({ cve }) => {
    const m = cve.metrics ?? {};
    const score = (m.cvssMetricV31 ?? m.cvssMetricV30 ?? m.cvssMetricV40 ?? m.cvssMetricV2 ?? [])[0]?.cvssData.baseScore ?? 0;
    return { id: cve.id, score };
  }).sort((a, b) => b.score - a.score);
  const entry = { at: Date.now(), total: json.totalResults, hits };
  cache.set(cpeName, entry);
  return entry;
}

export async function cveModule(_domain: string, ctx: ScanContext): Promise<Finding[]> {
  const products = (await ctx.products()).filter((p) => p.version);
  const out: Finding[] = [];
  const queries = products.filter((p) => CPE[p.name]).slice(0, MAX_LOOKUPS_PER_SCAN);

  if (products.length === 0) {
    out.push({ id: "cve.noversions", severity: "ok", title: "No versioned products to match", detail: "Nothing disclosed a version, so no CVE lookup was possible (which is the goal of banner hiding).", fix: "" });
  } else if (queries.length === 0) {
    out.push({ id: "cve.unmapped", severity: "info", title: "Versioned products found but none are in the CPE map", detail: products.map((p) => `${p.name} ${p.version}`).join(", "), fix: "" });
  }

  for (const p of queries) {
    const cpe = `cpe:2.3:a:${CPE[p.name]}:${p.version}:*:*:*:*:*:*:*`;
    try {
      const r = await lookup(cpe);
      if (r.total === 0) {
        out.push({ id: `cve.${p.name}.none`, severity: "ok", title: `${p.name} ${p.version}: no CVEs listed in NVD`, detail: cpe, fix: "" });
        continue;
      }
      const top = r.hits[0]?.score ?? 0;
      const list = r.hits.slice(0, 5).map((h) => `${h.id} (CVSS ${h.score.toFixed(1)})`).join(", ");
      out.push({
        id: `cve.${p.name}`, severity: severityFromScore(top),
        title: `${p.name} ${p.version}: ${r.total} CVE(s) matched, highest CVSS ${top.toFixed(1)}`,
        detail: `Top: ${list}. Source: ${p.source}.`,
        fix: `Verify the real patch level (distro packages often backport fixes without changing the version string), then upgrade to a supported release.`,
      });
    } catch (e) {
      out.push({ id: `cve.${p.name}.error`, severity: "info", title: `${p.name} ${p.version}: lookup failed`, detail: e instanceof Error ? e.message : "NVD lookup error", fix: "" });
    }
  }

  out.push({ id: "cve.caveat", severity: "info", title: "Caveat", detail: `Note: ${CVE_CAVEAT}`, fix: "" });
  return out;
}
