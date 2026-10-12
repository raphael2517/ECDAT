import { useEffect, useRef } from "react";
import { useStore } from "../hooks/useStore";
import type { ProgressEvent } from "../types";

const STAGE_LABEL: Record<string, string> = {
  ingest: "INGEST",
  sbom: "SBOM",
  detect: "SEMGREP",
  enrich: "ENRICH",
  risk: "RISK",
  recommend: "RECOMMEND",
  benchmark: "BENCH",
  cbom: "CBOM",
  done: "DONE",
  error: "ERROR",
  cancelled: "CANCELLED",
};

const STAGE_ORDER = [
  "ingest",
  "sbom",
  "detect",
  "enrich",
  "risk",
  "recommend",
  "benchmark",
  "cbom",
  "done",
];

export function ScanProgress() {
  const events = useStore((s) => s.events);
  const scanning = useStore((s) => s.scanning);
  const launching = useStore((s) => s.launching);
  const error = useStore((s) => s.error);
  const box = useRef<HTMLDivElement>(null);

  // Autoscroll only while the user is already at the bottom, so scrolling back
  // to read an earlier line is not yanked away on the next event.
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
    if (nearBottom) el.scrollTop = el.scrollHeight;
  }, [events]);

  const reached = new Set(
    events.filter((e) => e.stage !== "log").map((e) => e.stage),
  );
  const terminal = events.find((e) => ["done", "error", "cancelled"].includes(e.stage));
  const progress = terminal?.progress ?? 0;
  const logs = events.filter((e) => e.stage === "log" || e.message);

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Scan Progress</h2>
        <span className="muted">
          {launching
            ? "launching…"
            : scanning
              ? `${progress}%`
              : terminal
                ? terminal.stage
                : "idle"}
        </span>
      </div>

      <div className="stages">
        {STAGE_ORDER.map((s) => {
          const done = reached.has(s);
          const active = !done && STAGE_ORDER.indexOf(s) === firstPending(reached);
          return (
            <span
              key={s}
              className={`stage ${done ? "done" : ""} ${active ? "active" : ""} ${
                s === "error" ? "err" : ""
              }`}
            >
              {STAGE_LABEL[s] ?? s}
            </span>
          );
        })}
      </div>

      <div className="bar">
        <div
          className="bar-fill"
          style={{
            width: `${progress}%`,
            background: terminal?.stage === "error" ? "var(--risk-critical)" : undefined,
          }}
        />
      </div>

      {error && <p className="error">{error}</p>}

      <div className="log" ref={box}>
        {logs.length === 0 && <p className="empty">No events yet.</p>}
        {logs.map((e, i) => (
          <LogLine key={i} e={e} />
        ))}
      </div>
    </div>
  );
}

function firstPending(reached: Set<string>): number {
  for (let i = 0; i < STAGE_ORDER.length; i++) {
    if (!reached.has(STAGE_ORDER[i])) return i;
  }
  return STAGE_ORDER.length;
}

function LogLine({ e }: { e: ProgressEvent }) {
  const structured = e.stage !== "log";
  const extra = Object.entries(e.detail ?? {})
    .filter(([k]) => k !== "scan_id")
    .map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`)
    .join(" ");

  return (
    <div className={`log-line ${structured ? "structured" : ""}`}>
      <span className="ts">{new Date(e.timestamp).toLocaleTimeString()}</span>
      {structured && (
        <span className="badge-sm">{STAGE_LABEL[e.stage] ?? e.stage}</span>
      )}
      <span className="msg">
        {e.message ?? ""}
        {extra && <span className="muted"> {extra}</span>}
      </span>
    </div>
  );
}
