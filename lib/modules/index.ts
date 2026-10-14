import type { ScanContext } from "../context";
import { MODULE_META } from "../modules-meta";
import type { Finding, ModuleMeta } from "../types";
import { cookiesModule } from "./cookies";
import { corsModule } from "./cors";
import { cveModule } from "./cve";
import { dnsModule } from "./dns";
import { headersModule } from "./headers";
import { sqlLeakModule } from "./sqlleak";
import { fingerprint, techModule } from "./tech";
import { tlsModule } from "./tls";

export { fingerprint };

type Runner = (domain: string, ctx: ScanContext) => Promise<Finding[]>;

const RUNNERS: Record<string, { run: Runner; timeoutMs: number }> = {
  headers: { run: headersModule, timeoutMs: 20_000 },
  cookies: { run: cookiesModule, timeoutMs: 20_000 },
  cors: { run: corsModule, timeoutMs: 25_000 },
  tls: { run: tlsModule, timeoutMs: 25_000 },
  dns: { run: dnsModule, timeoutMs: 20_000 },
  tech: { run: techModule, timeoutMs: 20_000 },
  cve: { run: cveModule, timeoutMs: 60_000 },
  sqlleak: { run: sqlLeakModule, timeoutMs: 30_000 },
};

export const MODULES: (ModuleMeta & { run: Runner; timeoutMs: number })[] = MODULE_META.map((m) => ({
  ...m,
  ...RUNNERS[m.id],
}));
