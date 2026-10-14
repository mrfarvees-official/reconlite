import type { ScanContext } from "../context";
import { httpsGet } from "../net";
import type { Finding } from "../types";

const PATTERNS: { re: RegExp; label: string }[] = [
  { re: /SQLSTATE\[[A-Z0-9]+\]/, label: "PDO SQLSTATE" },
  { re: /\bORA-\d{5}\b/, label: "Oracle ORA- error" },
  { re: /pg_query\(\)|pg_exec\(\)|PSQLException|PostgreSQL.{0,40}ERROR/i, label: "PostgreSQL error" },
  { re: /You have an error in your SQL syntax|mysql_fetch_|mysqli_sql_exception|com\.mysql\.jdbc/i, label: "MySQL error" },
  { re: /Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server|ODBC SQL Server Driver|System\.Data\.SqlClient\.SqlException/i, label: "SQL Server error" },
  { re: /SQLite3?::|SQLITE_ERROR|sqlite3\.OperationalError/i, label: "SQLite error" },
  { re: /java\.sql\.SQLException|Hibernate.{0,30}Exception/i, label: "JDBC/Hibernate exception" },
];

/**
 * Inspects only responses that happen in normal use: the homepage plus two standard well-known
 * files that commonly 404. Nothing malformed is ever sent to provoke an error.
 */
export async function sqlLeakModule(_domain: string, ctx: ScanContext): Promise<Finding[]> {
  const page = await ctx.page();
  const targets: { label: string; status: number; body: string }[] = [
    { label: "/", status: page.final.status, body: page.final.body },
  ];
  for (const path of ["/robots.txt", "/.well-known/security.txt"]) {
    try {
      const r = await httpsGet(page.host, { path, maxBytes: 128 * 1024 });
      targets.push({ label: path, status: r.status, body: r.body });
    } catch {
      /* unreachable path is not a finding */
    }
  }

  const out: Finding[] = [];
  for (const t of targets) {
    for (const p of PATTERNS) {
      const m = p.re.exec(t.body);
      if (m) {
        out.push({
          id: `sqlleak.${p.label}`, severity: "high", title: `${p.label} text visible in response for ${t.label} (HTTP ${t.status})`,
          detail: `Matched: "${m[0].slice(0, 80)}". Verbose database errors reveal engine, schema or query structure to anyone.`,
          fix: "Disable debug/verbose errors in production, log details server-side, and serve a generic error page.",
        });
      }
    }
  }
  if (out.length === 0) {
    out.push({ id: "sqlleak.none", severity: "ok", title: `No database error strings in ${targets.length} normal response(s)`, detail: `Inspected: ${targets.map((t) => `${t.label} [${t.status}]`).join(", ")}.`, fix: "" });
  }
  return out;
}
