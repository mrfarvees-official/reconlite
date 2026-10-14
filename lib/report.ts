import { CVE_CAVEAT } from "./modules-meta";
import { SEVERITY_ORDER, type Finding, type Severity } from "./types";

export interface ScanSection {
  id: string;
  title: string;
  findings: Finding[];
  error?: string;
}

export interface ScanRecord {
  domain: string;
  startedAt: string;
  sections: ScanSection[];
}

export function countBySeverity(scan: ScanRecord): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>;
  for (const sec of scan.sections) for (const f of sec.findings) counts[f.severity]++;
  return counts;
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

const COLORS: Record<Severity, string> = {
  critical: "#b91c1c", high: "#dc2626", medium: "#b45309", low: "#1d4ed8", info: "#4b5563", ok: "#15803d",
};

/** Printable HTML; the user saves it as PDF via the browser print dialog. All scanned text is escaped. */
export function buildReportHtml(scan: ScanRecord): string {
  const counts = countBySeverity(scan);
  const summary = SEVERITY_ORDER.map(
    (s) => `<span class="pill" style="border-color:${COLORS[s]};color:${COLORS[s]}">${s.toUpperCase()}: ${counts[s]}</span>`,
  ).join(" ");
  const sections = scan.sections
    .map((sec) => {
      const rows = sec.error
        ? `<p class="err">module error: ${escapeHtml(sec.error)}</p>`
        : sec.findings
            .map(
              (f) => `<div class="f"><b style="color:${COLORS[f.severity]}">[${f.severity.toUpperCase()}]</b> ${escapeHtml(f.title)}${
                f.detail ? `<div class="d">${escapeHtml(f.detail)}</div>` : ""
              }${f.fix ? `<div class="d"><i>Fix:</i> ${escapeHtml(f.fix)}</div>` : ""}</div>`,
            )
            .join("");
      return `<h2>${escapeHtml(sec.title)}</h2>${rows}`;
    })
    .join("");
  return `<!doctype html><html><head><meta charset="utf-8"><title>Recon report - ${escapeHtml(scan.domain)}</title>
<style>body{font:13px/1.5 ui-monospace,Menlo,Consolas,monospace;color:#111;max-width:820px;margin:24px auto;padding:0 16px}
h1{font-size:20px;margin-bottom:0}h2{font-size:15px;border-bottom:1px solid #ccc;padding-bottom:2px;margin-top:22px}
.pill{border:1px solid;border-radius:4px;padding:1px 6px;margin-right:4px;display:inline-block}
.f{margin:8px 0}.d{margin-left:18px;color:#444}.err{color:#b91c1c}.note{margin-top:24px;color:#555;font-size:12px}
@media print{body{margin:0}}</style></head><body>
<h1>Recon Suite - passive inspection report</h1>
<div>Target: <b>${escapeHtml(scan.domain)}</b> &middot; ${escapeHtml(scan.startedAt)}</div>
<p>${summary}</p>${sections}
<p class="note">No payloads sent - inspection only. All data was read from normal, publicly disclosed responses. CVE note: ${escapeHtml(CVE_CAVEAT)}</p>
<script>window.addEventListener("load",function(){setTimeout(function(){window.print()},300)})</script>
</body></html>`;
}

export function openPrintableReport(scan: ScanRecord): boolean {
  const url = URL.createObjectURL(new Blob([buildReportHtml(scan)], { type: "text/html" }));
  const w = window.open(url, "_blank");
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
  return w !== null;
}
