// Presentation formatters. Private semantics are formatted for local display
// only; nothing here writes to the URL, title or persistent storage.

export function formatAge(ageMsValue: number): string {
  if (!Number.isFinite(ageMsValue) || ageMsValue < 0) return "—";
  if (ageMsValue < 1_000) return `${Math.round(ageMsValue)}ms`;
  if (ageMsValue < 60_000) return `${(ageMsValue / 1_000).toFixed(ageMsValue < 10_000 ? 1 : 0)}s`;
  if (ageMsValue < 3_600_000) return `${Math.round(ageMsValue / 60_000)}m`;
  return `${Math.round(ageMsValue / 3_600_000)}h`;
}

export function formatUsd(value: number | null | undefined, digits = 2): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  const abs = Math.abs(value);
  if (abs >= 1_000_000_000) return `$${(value / 1_000_000_000).toFixed(2)}B`;
  if (abs >= 1_000_000) return `$${(value / 1_000_000).toFixed(2)}M`;
  if (abs >= 10_000) return `$${(value / 1_000).toFixed(2)}K`;
  return `$${value.toFixed(digits)}`;
}

export function formatAmount(value: number | null | undefined, digits = 6): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  if (value === 0) return "0";
  const abs = Math.abs(value);
  if (abs >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (abs >= 1_000) return `${(value / 1_000).toFixed(2)}K`;
  if (abs < 0.000001) return value.toExponential(2);
  return value.toFixed(Math.min(digits, abs < 1 ? 8 : 4));
}

export function formatPercent(value: number | null | undefined, digits = 2): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return `${(value * 100).toFixed(digits)}%`;
}

export function formatBps(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return `${value.toFixed(value % 1 === 0 ? 0 : 1)} bps`;
}

export function truncateAddress(value: string | null | undefined, lead = 4, tail = 4): string {
  if (!value) return "—";
  if (value.length <= lead + tail + 1) return value;
  return `${value.slice(0, lead)}…${value.slice(-tail)}`;
}

export function formatClock(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "—";
  const date = new Date(ms);
  return `${String(date.getUTCHours()).padStart(2, "0")}:${String(date.getUTCMinutes()).padStart(
    2,
    "0",
  )}:${String(date.getUTCSeconds()).padStart(2, "0")}Z`;
}
