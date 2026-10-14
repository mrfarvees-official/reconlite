export type Severity = "critical" | "high" | "medium" | "low" | "info" | "ok";

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
}

export interface ModuleMeta {
  id: string;
  title: string;
  description: string;
}

export type ScanEvent =
  | { type: "start"; domain: string; modules: ModuleMeta[] }
  | { type: "module_start"; id: string }
  | { type: "module_done"; id: string; findings: Finding[]; ms: number }
  | { type: "module_error"; id: string; message: string }
  | { type: "done" }
  | { type: "fatal"; message: string };

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "ok",
];
