"use client";

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { completeCommand, parseCommand } from "@/lib/commands";
import { CVE_CAVEAT, MODULE_META } from "@/lib/modules-meta";
import { countBySeverity, openPrintableReport, type ScanRecord, type ScanSection } from "@/lib/report";
import { SEVERITY_ORDER, type Finding, type ScanEvent, type Severity } from "@/lib/types";

type Tone = "normal" | "dim" | "err" | "ok" | "warn";
type LineData =
  | { kind: "text"; text: string; tone?: Tone }
  | { kind: "cmd"; text: string }
  | { kind: "section"; title: string }
  | { kind: "loading"; text: string }
  | { kind: "finding"; f: Finding }
  | { kind: "counts"; counts: Record<Severity, number> }
  | { kind: "pdf" };
interface Entry { key: number; line: LineData }

const SEV_CLASS: Record<Severity, string> = {
  critical: "text-red-400",
  high: "text-red-400",
  medium: "text-amber-400",
  low: "text-sky-400",
  info: "text-term-dim",
  ok: "text-term-green",
};
const SEV_TAG: Record<Severity, string> = {
  critical: "[CRIT]", high: "[HIGH]", medium: "[MED ]", low: "[LOW ]", info: "[INFO]", ok: "[ OK ]",
};
const TONE_CLASS: Record<Tone, string> = {
  normal: "text-term-green", dim: "text-term-dim", err: "text-red-400", ok: "text-term-green", warn: "text-amber-400",
};

const HISTORY_KEY = "recon.history";
const CONSENT_KEY = "recon.consent";
const BANNER = [
  "  ____  _____ ____ ___  _   _",
  " |  _ \\| ____/ ___/ _ \\| \\ | |",
  " | |_) |  _|| |  | | | |  \\| |",
  " |  _ <| |__| |__| |_| | |\\  |",
  " |_| \\_\\_____\\____\\___/|_| \\_|  suite // passive inspector",
].join("\n");

function lsGet(key: string): string | null {
  try { return localStorage.getItem(key); } catch { return null; }
}
function lsSet(key: string, value: string) {
  try { localStorage.setItem(key, value); } catch { /* storage unavailable */ }
}

// Consent lives in localStorage; a tiny external store keeps SSR/hydration consistent.
const consentListeners = new Set<() => void>();
const subscribeConsent = (cb: () => void) => {
  consentListeners.add(cb);
  window.addEventListener("storage", cb);
  return () => { consentListeners.delete(cb); window.removeEventListener("storage", cb); };
};
const readConsent = () => lsGet(CONSENT_KEY) === "1";

const INTRO: LineData[] = [
  { kind: "text", text: BANNER },
  { kind: "text", text: "No payloads sent — inspection only. Every check reads what the target already publishes.", tone: "warn" },
  { kind: "text", text: "Type 'help' for commands. Try: scan example.com", tone: "dim" },
];

export default function Terminal() {
  const [entries, setEntries] = useState<Entry[]>(() => INTRO.map((line, key) => ({ key, line })));
  const [input, setInput] = useState("");
  const [caret, setCaret] = useState(0);
  const [scanning, setScanning] = useState(false);
  const consent = useSyncExternalStore(subscribeConsent, readConsent, () => false);
  const [consentNudge, setConsentNudge] = useState(false);
  const [focused, setFocused] = useState(false);

  const inputRef = useRef<HTMLInputElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const keyRef = useRef(INTRO.length);
  const historyRef = useRef<string[]>([]);
  const histIdx = useRef(-1);
  const draft = useRef("");
  const abortRef = useRef<AbortController | null>(null);
  const lastScan = useRef<ScanRecord | null>(null);
  const lastDomain = useRef("");

  const mk = (line: LineData): Entry => ({ key: keyRef.current++, line });
  const push = useCallback((...lines: LineData[]) => {
    setEntries((prev) => [...prev, ...lines.map((line) => ({ key: keyRef.current++, line }))]);
  }, []);
  const text = useCallback((t: string, tone?: Tone) => push({ kind: "text", text: t, tone }), [push]);

  /** Replace the entry with `key` by `lines` (used to swap a loading line for results in place). */
  const replace = useCallback((key: number, lines: LineData[]) => {
    setEntries((prev) => {
      const i = prev.findIndex((e) => e.key === key);
      const next = lines.map((line) => ({ key: keyRef.current++, line }));
      if (i < 0) return [...prev, ...next];
      return [...prev.slice(0, i), ...next, ...prev.slice(i + 1)];
    });
  }, []);

  useEffect(() => {
    try { historyRef.current = JSON.parse(lsGet(HISTORY_KEY) ?? "[]"); } catch { historyRef.current = []; }
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [entries, input]);

  const setConsentPersist = (v: boolean) => {
    lsSet(CONSENT_KEY, v ? "1" : "0");
    consentListeners.forEach((cb) => cb());
    if (v) setConsentNudge(false);
  };

  const runScan = useCallback(async (rawDomain: string) => {
    const t0 = new Date();
    const controller = new AbortController();
    abortRef.current = controller;
    setScanning(true);
    lastDomain.current = rawDomain;

    const record: ScanRecord = { domain: rawDomain, startedAt: t0.toISOString(), sections: [] };
    const loadKeys = new Map<string, number>();
    const titles = new Map<string, string>();

    const handle = (ev: ScanEvent) => {
      switch (ev.type) {
        case "start": {
          record.domain = ev.domain;
          lastDomain.current = ev.domain;
          const lines: Entry[] = [mk({ kind: "text", text: `[*] target resolved: ${ev.domain}`, tone: "dim" })];
          for (const m of ev.modules) {
            titles.set(m.id, m.title);
            const e = mk({ kind: "loading", text: `scanning ${m.id}...` });
            loadKeys.set(m.id, e.key);
            lines.push(e);
          }
          setEntries((prev) => [...prev, ...lines]);
          break;
        }
        case "module_done": {
          const title = titles.get(ev.id) ?? ev.id;
          const sec: ScanSection = { id: ev.id, title, findings: ev.findings };
          record.sections.push(sec);
          replace(loadKeys.get(ev.id)!, [
            { kind: "section", title: `${title}  (${ev.ms} ms)` },
            ...ev.findings.map((f): LineData => ({ kind: "finding", f })),
          ]);
          break;
        }
        case "module_error": {
          const title = titles.get(ev.id) ?? ev.id;
          record.sections.push({ id: ev.id, title, findings: [], error: ev.message });
          replace(loadKeys.get(ev.id)!, [
            { kind: "section", title },
            { kind: "text", text: `[!] ${ev.id}: ${ev.message}`, tone: "err" },
          ]);
          break;
        }
        case "fatal":
          text(`[!] ${ev.message}`, "err");
          break;
        case "done":
          lastScan.current = record;
          text(`[*] scan complete. Run 'report' for a summary. No payloads sent — inspection only.`, "dim");
          break;
      }
    };

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain: rawDomain, consent: true }),
        signal: controller.signal,
      });
      if (!res.ok || !res.body) {
        const err = (await res.json().catch(() => null)) as { error?: string } | null;
        text(`[!] ${err?.error ?? `server returned HTTP ${res.status}`}`, "err");
        return;
      }
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += value;
        let idx: number;
        while ((idx = buf.indexOf("\n\n")) >= 0) {
          const chunk = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          const data = chunk.split("\n").find((l) => l.startsWith("data: "));
          if (data) {
            try { handle(JSON.parse(data.slice(6)) as ScanEvent); } catch { /* ignore malformed frame */ }
          }
        }
      }
    } catch (e) {
      if ((e as Error).name === "AbortError") {
        // Drop spinners for modules that never finished.
        setEntries((prev) => prev.filter((en) => en.line.kind !== "loading"));
        text("^C scan aborted", "warn");
      } else {
        text("[!] connection to the scan service was lost", "err");
      }
    } finally {
      abortRef.current = null;
      setScanning(false);
    }
  }, [replace, text]);

  const execute = useCallback((raw: string) => {
    const line = raw.trim();
    push({ kind: "cmd", text: raw });
    if (line) {
      const h = historyRef.current;
      if (h[h.length - 1] !== line) h.push(line);
      historyRef.current = h.slice(-100);
      lsSet(HISTORY_KEY, JSON.stringify(historyRef.current));
    }
    histIdx.current = -1;

    const parsed = parseCommand(raw);
    if (parsed.kind === "empty") return;
    if (parsed.kind === "unknown") return text(`command not found: ${parsed.name}`, "err");

    switch (parsed.name) {
      case "help":
        text(
          [
            "Commands:",
            "  scan <domain>   run all passive modules against a domain",
            "  modules         list the check modules",
            "  report          summary of the last scan (+ PDF download)",
            "  clear           clear the screen",
            "  help            show this help",
            "",
            "Keys: ↑/↓ history · Tab complete · Ctrl+C abort scan · Ctrl+L clear",
          ].join("\n"),
        );
        return;
      case "modules":
        text(
          ["Modules (all passive — no payloads sent):", ...MODULE_META.map((m) => `  ${m.id.padEnd(8)} ${m.description}`), "", `Note: ${CVE_CAVEAT}`].join("\n"),
        );
        return;
      case "clear":
        setEntries([]);
        return;
      case "report": {
        const scan = lastScan.current;
        if (!scan) return text("no scan results yet. run: scan <domain>", "warn");
        const counts = countBySeverity(scan);
        push({ kind: "section", title: `Report: ${scan.domain}  (${scan.startedAt})` }, { kind: "counts", counts });
        const issues = scan.sections.flatMap((s) => s.findings.map((f) => ({ s, f })))
          .filter(({ f }) => f.severity === "critical" || f.severity === "high");
        if (issues.length) {
          text("Priority fixes:", "warn");
          for (const { s, f } of issues) text(`  • [${s.id}] ${f.title}${f.fix ? `\n      → ${f.fix}` : ""}`, "normal");
        } else {
          text("No critical/high findings.", "ok");
        }
        const failed = scan.sections.filter((s) => s.error);
        if (failed.length) text(`Modules with errors: ${failed.map((s) => s.id).join(", ")}`, "err");
        if (parsed.args[0] === "pdf") {
          if (!openPrintableReport(scan)) text("popup blocked — allow popups, then run: report pdf", "warn");
        } else {
          push({ kind: "pdf" });
        }
        return;
      }
      case "scan": {
        if (scanning) return text("a scan is already running (Ctrl+C to abort)", "warn");
        const target = parsed.args[0];
        if (!target) return text("usage: scan <domain>   e.g. scan example.com", "warn");
        if (!consent) {
          setConsentNudge(true);
          return text("authorization not confirmed. tick “I confirm I own this domain or am authorized to test it” below, then retry.", "err");
        }
        void runScan(target);
        return;
      }
    }
  }, [consent, push, runScan, scanning, text]);

  const setValue = (v: string, c = v.length) => {
    setInput(v);
    setCaret(c);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    const h = historyRef.current;
    if (e.key === "Enter") {
      e.preventDefault();
      execute(input);
      setValue("");
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (h.length === 0) return;
      if (histIdx.current === -1) { draft.current = input; histIdx.current = h.length - 1; }
      else histIdx.current = Math.max(0, histIdx.current - 1);
      setValue(h[histIdx.current]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (histIdx.current === -1) return;
      if (histIdx.current >= h.length - 1) { histIdx.current = -1; setValue(draft.current); }
      else { histIdx.current++; setValue(h[histIdx.current]); }
    } else if (e.key === "Tab") {
      e.preventDefault();
      const matches = completeCommand(input);
      if (matches.length === 1) setValue(matches[0] + " ");
      else if (matches.length > 1) {
        push({ kind: "cmd", text: input }, { kind: "text", text: matches.join("  "), tone: "dim" });
        const first = matches[0];
        let common = first;
        for (const m of matches) while (!m.startsWith(common)) common = common.slice(0, -1);
        if (common.length > input.length) setValue(common);
      }
    } else if (e.ctrlKey && e.key.toLowerCase() === "c") {
      if (window.getSelection()?.toString()) return;
      e.preventDefault();
      if (abortRef.current) abortRef.current.abort();
      else { push({ kind: "cmd", text: input + "^C" }); setValue(""); }
    } else if (e.ctrlKey && e.key.toLowerCase() === "l") {
      e.preventDefault();
      setEntries([]);
    }
  };

  const syncCaret = (el: HTMLInputElement) => setCaret(el.selectionStart ?? el.value.length);

  const quick = (cmd: string) => {
    if (cmd === "scan") {
      setValue("scan ");
      inputRef.current?.focus();
      return;
    }
    execute(cmd);
    inputRef.current?.focus();
  };

  return (
    <div className="mx-auto flex h-dvh w-full max-w-4xl flex-col gap-2 p-2 sm:p-4">
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-lg border border-term-border bg-black shadow-[0_0_40px_rgba(51,255,102,0.08)]">
        <div className="flex items-center gap-2 border-b border-term-border bg-term-bar px-3 py-2 text-xs text-term-dim">
          <span className="h-3 w-3 rounded-full bg-red-500/80" />
          <span className="h-3 w-3 rounded-full bg-amber-400/80" />
          <span className="h-3 w-3 rounded-full bg-green-500/80" />
          <span className="ml-2 truncate">root@recon: ~</span>
          <span className="ml-auto whitespace-nowrap font-semibold text-amber-400" role="note">
            No payloads sent — inspection only
          </span>
        </div>

        <div
          ref={scrollRef}
          className="min-h-0 flex-1 cursor-text overflow-y-auto px-3 py-2 text-[13px] leading-relaxed sm:text-sm"
          onClick={() => { if (!window.getSelection()?.toString()) inputRef.current?.focus(); }}
        >
          {entries.map((en) => <Row key={en.key} line={en.line} onPdf={() => { if (lastScan.current && !openPrintableReport(lastScan.current)) text("popup blocked — allow popups, then run: report pdf", "warn"); }} />)}

          <div className="relative mt-1 flex whitespace-pre-wrap break-all">
            <span className="shrink-0 text-term-green">
              <span className="text-sky-400">root@recon</span>:~#
            </span>
            <span className="text-term-green">
              {input.slice(0, caret)}
              <span aria-hidden className={`caret ${focused ? "caret-blink" : "caret-idle"}`} />
              {input.slice(caret)}
            </span>
            <input
              ref={inputRef}
              value={input}
              onChange={(e) => { setInput(e.target.value); syncCaret(e.target); }}
              onKeyDown={onKeyDown}
              onKeyUp={(e) => syncCaret(e.currentTarget)}
              onSelect={(e) => syncCaret(e.currentTarget)}
              onFocus={() => setFocused(true)}
              onBlur={() => setFocused(false)}
              className="pointer-events-none absolute h-0 w-0 opacity-0"
              aria-label="terminal input"
              autoCapitalize="off"
              autoCorrect="off"
              autoComplete="off"
              spellCheck={false}
              enterKeyHint="go"
            />
          </div>
        </div>
      </div>

      <div className="flex flex-wrap gap-2" role="toolbar" aria-label="quick commands">
        {["scan", "modules", "report", "help", "clear"].map((c) => (
          <button key={c} type="button" onClick={() => quick(c)}
            className="rounded border border-term-border bg-term-bar px-3 py-1.5 text-sm text-term-green hover:border-term-green active:bg-term-green active:text-black">
            {c === "scan" ? "scan …" : c}
          </button>
        ))}
        {scanning && (
          <button type="button" onClick={() => abortRef.current?.abort()}
            className="rounded border border-red-500/60 px-3 py-1.5 text-sm text-red-400 hover:bg-red-500/10">
            abort
          </button>
        )}
      </div>

      <label className={`flex items-start gap-2 rounded border px-3 py-2 text-xs sm:text-sm ${consentNudge ? "border-red-500 text-red-300" : "border-term-border text-term-dim"}`}>
        <input type="checkbox" checked={consent} onChange={(e) => setConsentPersist(e.target.checked)} className="mt-0.5 h-4 w-4 shrink-0 accent-green-500" />
        <span>
          I confirm I own this domain or am authorized to test it. Scans are rate limited (5 per 10 min).
          <span className="block text-amber-400">No payloads sent — inspection only.</span>
        </span>
      </label>
    </div>
  );
}

function Row({ line, onPdf }: { line: LineData; onPdf: () => void }) {
  switch (line.kind) {
    case "text":
      return <div className={`whitespace-pre-wrap break-words ${TONE_CLASS[line.tone ?? "normal"]}`}>{line.text}</div>;
    case "cmd":
      return (
        <div className="whitespace-pre-wrap break-all text-term-green">
          <span className="text-sky-400">root@recon</span>:~# {line.text}
        </div>
      );
    case "section":
      return <div className="mt-3 border-b border-term-border pb-0.5 font-bold text-term-green">══ {line.title}</div>;
    case "loading":
      return <div className="animate-pulse text-term-dim">[~] {line.text}</div>;
    case "finding": {
      const { f } = line;
      return (
        <div className={`mt-1 whitespace-pre-wrap break-words ${SEV_CLASS[f.severity]}`}>
          <span className="font-bold">{SEV_TAG[f.severity]}</span> {f.title}
          {f.detail && <div className="pl-[7ch] text-term-dim">{f.detail}</div>}
          {f.fix && <div className="pl-[7ch]">fix: <span className="text-term-green">{f.fix}</span></div>}
        </div>
      );
    }
    case "counts":
      return (
        <div className="my-1 flex flex-wrap gap-x-4 gap-y-1">
          {SEVERITY_ORDER.map((s) => (
            <span key={s} className={SEV_CLASS[s]}>{SEV_TAG[s]} {line.counts[s]}</span>
          ))}
        </div>
      );
    case "pdf":
      return (
        <div className="mt-1 text-term-dim">
          <button type="button" className="cursor-pointer text-sky-400 underline" onClick={(e) => { e.stopPropagation(); onPdf(); }}>
            [ download as PDF ]
          </button>{" "}
          (opens print dialog → “Save as PDF”)
        </div>
      );
  }
}
