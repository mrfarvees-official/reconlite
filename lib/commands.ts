export const COMMANDS = ["scan", "modules", "report", "clear", "help"] as const;
export type CommandName = (typeof COMMANDS)[number];

export type Parsed =
  | { kind: "empty" }
  | { kind: "command"; name: CommandName; args: string[] }
  | { kind: "unknown"; name: string };

export function parseCommand(line: string): Parsed {
  const parts = line.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return { kind: "empty" };
  const name = parts[0].toLowerCase();
  if ((COMMANDS as readonly string[]).includes(name)) {
    return { kind: "command", name: name as CommandName, args: parts.slice(1) };
  }
  return { kind: "unknown", name: parts[0] };
}

/** Tab completion on the first word only. Returns the candidates. */
export function completeCommand(input: string): string[] {
  if (/\s/.test(input.trimStart())) return [];
  const prefix = input.trim().toLowerCase();
  return COMMANDS.filter((c) => c.startsWith(prefix));
}
