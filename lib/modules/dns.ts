import type { Finding } from "../types";

interface DohAnswer { type: number; data: string }

async function txt(name: string): Promise<string[]> {
  const res = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
    { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(8000), cache: "no-store" },
  );
  if (!res.ok) throw new Error(`DoH resolver returned HTTP ${res.status}`);
  const json = (await res.json()) as { Answer?: DohAnswer[] };
  return (json.Answer ?? [])
    .filter((a) => a.type === 16)
    .map((a) => a.data.replace(/"\s+"/g, "").replace(/^"|"$/g, ""));
}

export async function dnsModule(domain: string): Promise<Finding[]> {
  const out: Finding[] = [];
  const labels = domain.split(".");
  const orgDomain = labels.length > 2 ? labels.slice(-2).join(".") : domain;

  const spfRecords = (await txt(domain)).filter((r) => /^v=spf1\b/i.test(r));
  if (spfRecords.length === 0) {
    out.push({ id: "dns.spf.missing", severity: "medium", title: "No SPF record", detail: "Anyone can send mail claiming to be from this domain without failing SPF.", fix: 'Publish a TXT record such as "v=spf1 include:<your-mail-provider> -all". If the domain sends no mail: "v=spf1 -all".' });
  } else if (spfRecords.length > 1) {
    out.push({ id: "dns.spf.multiple", severity: "medium", title: "Multiple SPF records", detail: "RFC 7208 allows exactly one; receivers return a permanent error and ignore SPF.", fix: "Merge them into a single record." });
  } else {
    const spf = spfRecords[0];
    const all = /([+\-~?]?)all\s*$/i.exec(spf.trim())?.[1] ?? "";
    if (all === "-") out.push({ id: "dns.spf.ok", severity: "ok", title: "SPF present with hard fail (-all)", detail: spf, fix: "" });
    else if (all === "~") out.push({ id: "dns.spf.softfail", severity: "low", title: "SPF uses soft fail (~all)", detail: spf, fix: "Move to -all once all legitimate senders are covered." });
    else out.push({ id: "dns.spf.permissive", severity: "high", title: `SPF is permissive (${all || "+"}all or no all-mechanism)`, detail: spf, fix: "End the record with -all (or at least ~all)." });
  }

  let dmarc = (await txt(`_dmarc.${domain}`)).filter((r) => /^v=DMARC1/i.test(r));
  let inherited = false;
  if (dmarc.length === 0 && orgDomain !== domain) {
    dmarc = (await txt(`_dmarc.${orgDomain}`)).filter((r) => /^v=DMARC1/i.test(r));
    inherited = dmarc.length > 0;
  }
  if (dmarc.length === 0) {
    out.push({ id: "dns.dmarc.missing", severity: "medium", title: "No DMARC record", detail: "Receivers have no policy for spoofed mail and you get no abuse reports.", fix: 'Add TXT at _dmarc.<domain>: "v=DMARC1; p=none; rua=mailto:dmarc@<domain>", then tighten to quarantine/reject.' });
  } else {
    const rec = dmarc[0];
    const p = /(?:^|;)\s*p=(\w+)/i.exec(rec)?.[1]?.toLowerCase();
    const src = inherited ? ` (inherited from ${orgDomain})` : "";
    if (p === "reject" || p === "quarantine") out.push({ id: "dns.dmarc.ok", severity: "ok", title: `DMARC enforced (p=${p})${src}`, detail: rec, fix: "" });
    else out.push({ id: "dns.dmarc.monitor", severity: "low", title: `DMARC in monitor-only mode (p=${p ?? "?"})${src}`, detail: rec, fix: "After reviewing reports, move to p=quarantine then p=reject." });
    if (!/rua=/i.test(rec)) out.push({ id: "dns.dmarc.norua", severity: "info", title: "DMARC has no aggregate report address (rua)", detail: "", fix: "Add rua=mailto:… to receive reports." });
  }
  return out;
}
