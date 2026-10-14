import type { NextRequest } from "next/server";
import { createContext } from "@/lib/context";
import { fingerprint, MODULES } from "@/lib/modules";
import { friendlyError, normalizeDomain, safeLookup, withTimeout } from "@/lib/net";
import { admit } from "@/lib/ratelimit";
import type { ScanEvent } from "@/lib/types";

function resolvePublic(domain: string): Promise<void> {
  return new Promise((resolve, reject) => {
    (safeLookup as unknown as (h: string, o: object, cb: (e: Error | null) => void) => void)(domain, { all: true }, (e) =>
      e ? reject(e) : resolve(),
    );
  });
}

export async function POST(req: NextRequest) {
  let body: { domain?: unknown; consent?: unknown };
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "invalid request body" }, { status: 400 });
  }
  if (body.consent !== true) {
    return Response.json({ error: "authorization not confirmed: tick the ownership/authorization checkbox first" }, { status: 403 });
  }
  const domain = typeof body.domain === "string" ? normalizeDomain(body.domain) : null;
  if (!domain) {
    return Response.json({ error: "invalid domain: enter a public hostname such as example.com (no IPs, ports or paths)" }, { status: 400 });
  }

  const ip = req.headers.get("x-forwarded-for")?.split(",")[0].trim() || "local";
  const admission = admit(ip);
  if (!admission.ok) {
    return Response.json({ error: admission.message }, { status: 429, headers: { "retry-after": String(admission.retryAfter) } });
  }

  const encoder = new TextEncoder();
  let cancelled = false;
  const stream = new ReadableStream({
    async start(controller) {
      const send = (ev: ScanEvent) => {
        if (cancelled) return;
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(ev)}\n\n`));
        } catch {
          cancelled = true;
        }
      };
      try {
        try {
          await withTimeout(resolvePublic(domain), 8000);
        } catch (e) {
          send({ type: "fatal", message: `${domain}: ${friendlyError(e)}` });
          return;
        }

        const ctx = createContext(domain, fingerprint);
        send({ type: "start", domain, modules: MODULES.map(({ id, title, description }) => ({ id, title, description })) });

        await Promise.all(
          MODULES.map(async (m) => {
            send({ type: "module_start", id: m.id });
            const t0 = Date.now();
            try {
              const findings = await withTimeout(m.run(domain, ctx), m.timeoutMs);
              send({ type: "module_done", id: m.id, findings, ms: Date.now() - t0 });
            } catch (e) {
              send({ type: "module_error", id: m.id, message: friendlyError(e) });
            }
          }),
        );
        send({ type: "done" });
      } finally {
        admission.release();
        try {
          controller.close();
        } catch {
          /* already closed */
        }
      }
    },
    cancel() {
      cancelled = true;
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store, no-transform",
      "x-accel-buffering": "no",
    },
  });
}
