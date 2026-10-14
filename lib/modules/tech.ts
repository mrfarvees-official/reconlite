import type { Product, ScanContext } from "../context";
import type { Finding } from "../types";

const LIBS = ["jquery", "bootstrap", "angular", "react", "vue", "lodash", "moment", "backbone", "underscore", "d3", "axios", "handlebars", "prototype", "mootools"];

/** Pulls product/version pairs out of headers, the generator meta tag and <script src> filenames. */
export async function fingerprint(ctx: ScanContext): Promise<Product[]> {
  const { final } = await ctx.page();
  const products: Product[] = [];
  const h = final.headers;

  const server = String(h.server ?? "");
  for (const m of server.matchAll(/([A-Za-z][\w.-]*)\/(\d[\w.]*)/g)) {
    products.push({ name: m[1].toLowerCase(), version: m[2], source: "Server header" });
  }
  if (server && !/\//.test(server)) products.push({ name: server.split(/[\s(]/)[0].toLowerCase(), source: "Server header" });

  const powered = String(h["x-powered-by"] ?? "");
  for (const part of powered.split(",").map((s) => s.trim()).filter(Boolean)) {
    const m = /^([A-Za-z][\w. -]*?)(?:\/(\d[\w.]*))?$/.exec(part);
    if (m) products.push({ name: m[1].toLowerCase(), version: m[2], source: "X-Powered-By header" });
  }

  const html = final.body;
  const gen =
    /<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)["']/i.exec(html)?.[1] ??
    /<meta[^>]+content=["']([^"']+)["'][^>]*name=["']generator["']/i.exec(html)?.[1];
  if (gen) {
    const m = /^(.*?)[\s/]+v?(\d[\w.]*)$/.exec(gen.trim());
    products.push({ name: (m?.[1] ?? gen).trim().toLowerCase(), version: m?.[2], source: "meta generator" });
  }

  for (const s of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
    const src = s[1];
    for (const lib of LIBS) {
      const ver = new RegExp(`(?:^|[/_.@-])${lib}(?:\\.min)?(?:[-@/.]v?|/)(\\d+\\.\\d+(?:\\.\\d+)?)`, "i").exec(src)?.[1];
      if (ver) products.push({ name: lib, version: ver, source: `script ${src.split("?")[0].slice(-60)}` });
      else if (new RegExp(`(?:^|[/_.@-])${lib}(?:\\.min)?\\.js`, "i").test(src)) products.push({ name: lib, source: `script ${src.split("?")[0].slice(-60)}` });
    }
  }

  const seen = new Set<string>();
  return products.filter((p) => {
    const k = `${p.name}@${p.version ?? ""}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export async function techModule(_domain: string, ctx: ScanContext): Promise<Finding[]> {
  const products = await ctx.products();
  if (products.length === 0) {
    return [{ id: "tech.none", severity: "ok", title: "No technology banners disclosed", detail: "No Server/X-Powered-By version, generator tag or recognisable JS library files found.", fix: "" }];
  }
  const out: Finding[] = [];
  for (const p of products) {
    const label = p.version ? `${p.name} ${p.version}` : p.name;
    const fromHeader = p.source.endsWith("header");
    out.push({
      id: `tech.${p.name}`, severity: p.version && (fromHeader || p.source === "meta generator") ? "low" : "info",
      title: `${label}  (${p.source})`,
      detail: p.version && fromHeader ? "Exact version disclosed in a response header; it tells anyone which known bugs to look for." : "Disclosed in normal page content.",
      fix: p.version && (fromHeader || p.source === "meta generator") ? "Suppress version banners (nginx: server_tokens off; Apache: ServerTokens Prod; PHP: expose_php=Off)." : "",
    });
  }
  return out;
}
