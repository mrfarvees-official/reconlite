import { httpsGet, type HttpResult } from "./net";

export interface PageResult {
  /** Final response after following same-site https redirects. */
  final: HttpResult;
  /** Every hop (status + url) for transparency. */
  chain: { url: string; status: number }[];
  /** Set-Cookie headers from every hop. */
  setCookies: string[];
  host: string;
}

export interface Product {
  name: string;
  version?: string;
  source: string;
}

export interface ScanContext {
  domain: string;
  /** Memoised homepage fetch shared by headers/cookies/tech/sqlleak so the target sees one request. */
  page(): Promise<PageResult>;
  /** Memoised fingerprint shared by tech and cve. */
  products(): Promise<Product[]>;
}

function sameSite(domain: string, host: string): boolean {
  const strip = (h: string) => h.replace(/^www\./, "");
  return strip(host) === strip(domain);
}

async function fetchPage(domain: string): Promise<PageResult> {
  let host = domain;
  let path = "/";
  const chain: PageResult["chain"] = [];
  const setCookies: string[] = [];
  for (let hop = 0; hop < 4; hop++) {
    const res = await httpsGet(host, { path });
    chain.push({ url: `https://${host}${path}`, status: res.status });
    setCookies.push(...res.setCookies);
    const loc = res.headers.location;
    if (res.status >= 300 && res.status < 400 && loc) {
      try {
        const next = new URL(loc, `https://${host}${path}`);
        if (next.protocol === "https:" && !next.port && sameSite(domain, next.hostname)) {
          host = next.hostname;
          path = next.pathname + next.search;
          continue;
        }
      } catch {
        /* malformed Location: stop here */
      }
    }
    return { final: res, chain, setCookies, host };
  }
  throw new Error("too many redirects");
}

/** `fingerprint` is injected so context.ts stays free of module imports. */
export function createContext(
  domain: string,
  fingerprint: (ctx: ScanContext) => Promise<Product[]>,
): ScanContext {
  let page: Promise<PageResult> | undefined;
  let products: Promise<Product[]> | undefined;
  const ctx: ScanContext = {
    domain,
    page: () => (page ??= fetchPage(domain)),
    products: () => (products ??= fingerprint(ctx)),
  };
  return ctx;
}
