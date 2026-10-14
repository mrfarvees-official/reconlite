// In-memory limiter: fine for a single-process portfolio deployment. Use Redis/KV if you scale out.
const WINDOW_MS = 10 * 60 * 1000;
const MAX_SCANS_PER_WINDOW = 5;

const g = globalThis as unknown as {
  __scanHits?: Map<string, number[]>;
  __scanActive?: Set<string>;
};
const hits = (g.__scanHits ??= new Map<string, number[]>());
const active = (g.__scanActive ??= new Set<string>());

export type Admission = { ok: true; release: () => void } | { ok: false; message: string; retryAfter: number };

export function admit(ip: string): Admission {
  const now = Date.now();
  const recent = (hits.get(ip) ?? []).filter((t) => now - t < WINDOW_MS);
  if (active.has(ip)) return { ok: false, message: "a scan is already running for your address", retryAfter: 10 };
  if (recent.length >= MAX_SCANS_PER_WINDOW) {
    const retryAfter = Math.ceil((recent[0] + WINDOW_MS - now) / 1000);
    return { ok: false, message: `rate limit: ${MAX_SCANS_PER_WINDOW} scans per 10 minutes. retry in ${retryAfter}s`, retryAfter };
  }
  recent.push(now);
  hits.set(ip, recent);
  active.add(ip);
  return { ok: true, release: () => void active.delete(ip) };
}
