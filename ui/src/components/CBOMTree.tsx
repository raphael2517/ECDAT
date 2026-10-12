import { useMemo, useState } from "react";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type SortingState,
} from "@tanstack/react-table";
import { useStore } from "../hooks/useStore";
import type { Finding } from "../types";

const col = createColumnHelper<Finding>();

const RISK_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function riskColor(risk: string): string {
  switch (risk) {
    case "critical":
      return "var(--risk-critical)";
    case "high":
      return "var(--risk-high)";
    case "medium":
      return "var(--risk-medium)";
    case "low":
      return "var(--risk-low)";
    default:
      return "var(--risk-info)";
  }
}

export function RiskBadge({ risk }: { risk: string }) {
  return (
    <span className="badge" style={{ background: riskColor(risk) }}>
      {risk}
    </span>
  );
}

const columns = [
  col.accessor((r) => r.risk_score, {
    id: "risk_score",
    header: "Score",
    cell: (info) => <span className="num">{info.getValue().toFixed(2)}</span>,
    sortingFn: (a, b) => a.original.risk_score - b.original.risk_score,
  }),
  col.accessor("risk", {
    header: "Risk",
    cell: (info) => <RiskBadge risk={info.getValue()} />,
    sortingFn: (a, b) =>
      (RISK_ORDER[a.original.risk] ?? 9) - (RISK_ORDER[b.original.risk] ?? 9),
  }),
  col.accessor("algorithm", {
    header: "Algorithm",
    cell: (info) => <strong>{info.getValue()}</strong>,
  }),
  col.accessor("algorithm_family", {
    header: "Family",
    cell: (info) => <span className="muted">{info.getValue()}</span>,
  }),
  col.accessor("usage", { header: "Usage" }),
  col.accessor("key_mgmt", {
    header: "Key mgmt",
    cell: (info) => {
      const v = info.getValue();
      const bad = v === "hardcoded";
      return <span className={bad ? "tag-bad" : "muted"}>{v}</span>;
    },
  }),
  col.accessor("file", {
    header: "Location",
    cell: (info) => {
      const f = info.row.original;
      return (
        <span className="loc">
          {f.file.split("/").slice(-1)[0]}
          <span className="muted">:{f.line}</span>
        </span>
      );
    },
  }),
  col.accessor("rule_id", {
    header: "Rule",
    cell: (info) => <code className="muted">{info.getValue().split(".").pop()}</code>,
  }),
  col.accessor("source", {
    header: "Src",
    cell: (info) => <span className="tag">{info.getValue()}</span>,
  }),
];

export function CBOMTree() {
  const risk = useStore((s) => s.risk);
  const cbom = useStore((s) => s.cbom);
  const selected = useStore((s) => s.selected);
  const select = useStore((s) => s.select);
  const focus = useStore((s) => s.focus);
  const setFocus = useStore((s) => s.setFocus);
  const [sorting, setSorting] = useState<SortingState>([{ id: "risk_score", desc: true }]);
  const [filter, setFilter] = useState("");

  // Heatmap drill-down narrows this table before the text filter applies.
  const all = useMemo(() => risk?.ranked ?? cbom?.findings ?? [], [risk, cbom]);
  const rows = useMemo(
    () =>
      focus
        ? all.filter(
            (f) =>
              f.algorithm_family === focus.family && f.risk === focus.severity,
          )
        : all,
    [all, focus],
  );

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting, globalFilter: filter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    globalFilterFn: "includesString",
  });

  if (!rows.length) {
    return <p className="empty">No findings. Run a scan to populate the explorer.</p>;
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>CBOM Explorer</h2>
        <input
          className="search"
          placeholder="filter algorithm, file, rule, usage…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        {focus && (
          <button
            className="tab"
            onClick={() => setFocus(null)}
            title="Clear the heatmap drill-down"
          >
            {focus.family} · {focus.severity} ✕
          </button>
        )}
        <span className="muted">
          {table.getFilteredRowModel().rows.length} / {rows.length}
        </span>
      </div>

      <div className="table-wrap">
        <table className="grid">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => (
                  <th
                    key={h.id}
                    onClick={h.column.getToggleSortingHandler()}
                    className={h.column.getCanSort() ? "sortable" : ""}
                  >
                    {flexRender(h.column.columnDef.header, h.getContext())}
                    {{ asc: " ▲", desc: " ▼" }[h.column.getIsSorted() as string] ?? ""}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => {
              const f = row.original;
              const isSel = selected === f;
              return (
                <tr
                  key={row.id}
                  className={isSel ? "sel" : ""}
                  onClick={() => select(f)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {selected && <FindingDetail f={selected} />}
    </div>
  );
}

function FindingDetail({ f }: { f: Finding }) {
  const rb = f.extra?.risk;
  const why = f.extra?.enrichment_rule;

  return (
    <div className="detail">
      <div className="detail-head">
        <h3>
          {f.algorithm} <span className="muted">· {f.usage} · {f.key_mgmt}</span>
        </h3>
        <button className="link" onClick={() => useStore.getState().select(null)}>
          close
        </button>
      </div>

      <div className="detail-grid">
        <div>
          <div className="k">File</div>
          <div className="v">
            {f.file}:{f.line}
          </div>
          <div className="k">Rule</div>
          <div className="v">
            <code>{f.rule_id}</code>
          </div>
          <div className="k">CWE</div>
          <div className="v">
            {f.cwe || "—"}
            {f.cwe2 ? ` / ${f.cwe2}` : ""}
          </div>
          <div className="k">Detected by</div>
          <div className="v">
            {f.source}
            {f.enrichment_source ? ` + ${f.enrichment_source}` : ""}
          </div>
          {why && (
            <>
              <div className="k">Why</div>
              <div className="v small">
                {why.algorithm}
                <br />
                {why.risk}
              </div>
            </>
          )}
        </div>

        <div>
          {rb && (
            <>
              <div className="k">Risk score</div>
              <div className="v">
                <span className="score" style={{ color: riskColor(f.risk) }}>
                  {rb.final_score.toFixed(2)}
                </span>{" "}
                / 10
              </div>
              <div className="k">Mosca</div>
              <div className="v small">
                X={rb.mosca_shelf_life_years}y + Y={rb.mosca_migration_years.toFixed(1)}y
                {" > "}
                Z={rb.mosca_collapse_years}y →{" "}
                <strong>{rb.mosca_triggered ? "migrate now" : "no pressure"}</strong>
              </div>
              <div className="k">Quantum effort</div>
              <div className="v small">
                {rb.quantum_toffoli.toExponential(2)} Toffoli,{" "}
                {rb.quantum_logical_qubits} logical qubits
                <br />
                <span className="muted">{rb.quantum_source}</span>
              </div>
              <div className="k">Classical weakness</div>
              <div className="v small">{rb.classical_weakness.toFixed(1)} / 1.0</div>
            </>
          )}
        </div>
      </div>

      <pre className="snippet">{f.context}</pre>
    </div>
  );
}
