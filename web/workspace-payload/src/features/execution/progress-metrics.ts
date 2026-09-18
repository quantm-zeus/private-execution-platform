// Shared pure formatter + defensive parser for the owner-scoped
// `get_execution_progress` read.
//
// It is used by BOTH the read-only Activity > Mine surface and the mutating
// Advanced-execution panel, so the two can never drift. Every unknown stays `—`;
// no value is ever invented, and `filledAmount` / `remainingAmount` are treated
// as opaque provider strings.

import { workspaceError } from "../../core/errors";
import { formatBps, formatPercent } from "../../core/format";

/** The subset of the execution-progress contract the formatter reads. */
export interface ProgressLike {
  readonly state: string;
  readonly chunksDone: number | null;
  readonly chunksTotal: number | null;
  readonly filledAmount: string | null;
  readonly remainingAmount: string | null;
  readonly realizedVsEstimateBps: number | null;
}

export interface ProgressMetric {
  readonly label: string;
  readonly value: string;
}

/** The exact metric set the design specifies, derived from the contract only. */
export function progressMetrics(progress: ProgressLike): ProgressMetric[] {
  const done = progress.chunksDone;
  const total = progress.chunksTotal;
  return [
    { label: "State", value: progress.state.toUpperCase() },
    { label: "Chunks", value: total === null ? "—" : `${done ?? "—"}/${total}` },
    { label: "Filled", value: progress.filledAmount ?? "—" },
    { label: "Remaining", value: progress.remainingAmount ?? "—" },
    { label: "Realized vs estimate", value: formatBps(progress.realizedVsEstimateBps) },
    { label: "Progress", value: total && done !== null ? formatPercent(done / total) : "—" },
  ];
}

/**
 * Progress percentage from the CHUNK ratio only. `filledAmount` /
 * `remainingAmount` are opaque provider strings; dividing them would invent a
 * number. Returns `null` (bar omitted) when there is no positive denominator.
 */
export function progressPercent(progress: ProgressLike): number | null {
  const total = progress.chunksTotal;
  const done = progress.chunksDone;
  if (total === null || done === null || total <= 0) return null;
  return Math.round((done / total) * 100);
}

export type ExecutionState =
  | "planning"
  | "running"
  | "halted"
  | "completed"
  | "failed"
  | "unknown";

const EXEC_STATES = new Set<ExecutionState>([
  "planning",
  "running",
  "halted",
  "completed",
  "failed",
  "unknown",
]);

/** A null-safe view of one current execution. `kind` stays `null` when absent. */
export interface ProgressView extends ProgressLike {
  readonly executionId: string | null;
  readonly kind: "twap" | "rfq" | null;
  readonly state: ExecutionState;
  readonly haltReason: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function finiteOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * Parse the `get_execution_progress` success document.
 *
 * `null`/`undefined` means the read succeeded and **nothing is running** — the
 * normal idle state, deliberately distinct from "unavailable". Any other
 * non-object, or an object without a recognised lifecycle state, is a protocol
 * error so a malformed success can never render as an idle workspace.
 */
export function parseProgressView(value: unknown): ProgressView | null {
  if (value === null || value === undefined) return null;
  if (!isRecord(value)) {
    throw workspaceError("protocol", "Malformed execution progress.");
  }
  const state = value.state;
  if (typeof state !== "string" || !EXEC_STATES.has(state as ExecutionState)) {
    throw workspaceError("protocol", "Execution progress is missing a lifecycle state.");
  }
  return {
    executionId: typeof value.executionId === "string" ? value.executionId : null,
    kind: value.kind === "twap" || value.kind === "rfq" ? value.kind : null,
    state: state as ExecutionState,
    chunksTotal: finiteOrNull(value.chunksTotal),
    chunksDone: finiteOrNull(value.chunksDone),
    filledAmount: typeof value.filledAmount === "string" ? value.filledAmount : null,
    remainingAmount: typeof value.remainingAmount === "string" ? value.remainingAmount : null,
    realizedVsEstimateBps: finiteOrNull(value.realizedVsEstimateBps),
    haltReason: typeof value.haltReason === "string" ? value.haltReason : null,
  };
}
