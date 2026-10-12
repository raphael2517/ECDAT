import { useMemo } from "react";
import { useStore } from "../hooks/useStore";
import { riskColor } from "./CBOMTree";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const FAMILIES = ["ASYM", "SYM", "HASH", "JWT", "TLS", "KEM", "KDF", "MULTI", "UNKNOWN"];

interface Cell {
  family: string;
  severity: string;
  count: number;
  files: string[];
  maxRisk: number;
}

/**
 * Algorithm family x severity grid.
 *
 * Built with plain CSS grid rather than a charting library: the plan called for
 * Recharts, but a heatmap is a 2D table with background colours, and doing it
 * in CSS keeps the bundle ~100 kB smaller and makes the cell content (file
 * list, click-through) trivial. Recharts is still a dependency for the score
 * distribution below it, which genuinely is a chart.
 */
export function RiskHeatmap() {
  const risk = useStore((s) => s.risk);
  const setFocus = useStore((s) => s.setFocus);
  const focus = useStore((s) => s.focus);

  const { cells, families, peak } = useMemo(() => {
    const map = new Map<string, Cell>();
    const famSet = new Set<string>();
    let hi = 1;

    for (const f of risk?.ranked ?? []) {
      const family = f.algorithm_family || "UNKNOWN";
      const severity = SEVERITIES.includes(f.risk) ? f.risk : "info";
      famSet.add(family);
      const key = `${family}|${severity}`;
      const cur =
        map.get(key) ??
        ({ family, severity, count: 0, files: [], maxRisk: 0 } as Cell);
      cur.count += 1;
      cur.maxRisk = Math.max(cur.maxRisk, f.risk_score);
      if (cur.files.length < 6 && !cur.files.includes(f.file)) cur.files.push(f.file);
      map.set(key, cur);
    }

    // Order families by volume so the busiest column lands left, like a Pareto.
    const ordered = FAMILIES.filter((x) => famSet.has(x)).concat(
      [...famSet].filter((x) => !FAMILIES.includes(x)).sort(),
    );
    for (const c of map.values()) hi = Math.max(hi, c.count);

    return { cells: map, families: ordered, peak: hi };
  }, [risk]);

  if (!risk?.ranked.length) {
    return <p className="empty">No findings to plot.</p>;
  }

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Risk Heatmap</h2>
        <span className="muted">rows = algorithm family, columns = severity, fill = finding count</span>
      </div>

      <div className="heat-scroll">
        <div
          className="heat"
          style={{ gridTemplateColumns: `120px repeat(${SEVERITIES.length}, minmax(74px, 1fr))` }}
        >
          <div className="heat-corner" />
          {SEVERITIES.map((s) => (
            <div key={s} className="heat-col-label" style={{ color: riskColor(s) }}>
              {s}
            </div>
          ))}

          {families.map((fam) => (
            <Row
              key={fam}
              family={fam}
              cells={cells}
              peak={peak}
              focus={focus}
              onSelect={setFocus}
            />
          ))}
        </div>
      </div>

      <Legend peak={peak} />
    </div>
  );
}

function Row({
  family,
  cells,
  peak,
  focus,
  onSelect,
}: {
  family: string;
  cells: Map<string, Cell>;
  peak: number;
  focus: { family: string; severity: string } | null;
  onSelect: (f: { family: string; severity: string }) => void;
}) {
  const total = SEVERITIES.reduce((n, s) => n + (cells.get(`${family}|${s}`)?.count ?? 0), 0);
  return (
    <>
      <div className="heat-row-label">
        {family}
        <span className="muted"> {total}</span>
      </div>
      {SEVERITIES.map((sev) => {
        const c = cells.get(`${family}|${sev}`);
        if (!c) return <div key={sev} className="heat-cell empty" />;
        // sqrt keeps a single outlier from flattening every other cell.
        const intensity = Math.sqrt(c.count / peak);
        const active = focus?.family === family && focus?.severity === sev;
        return (
          <div
            key={sev}
            className={`heat-cell${active ? " active" : ""}`}
            style={{ background: riskColor(sev), opacity: 0.18 + intensity * 0.82 }}
            title={`${c.count} finding(s)\n${c.files.join("\n")}\n\nclick to inspect`}
            onClick={() => onSelect({ family, severity: sev })}
          >
            {c.count}
          </div>
        );
      })}
    </>
  );
}

function Legend({ peak }: { peak: number }) {
  return (
    <div className="legend">
      <span className="muted">1</span>
      {[0.25, 0.45, 0.65, 0.85, 1].map((o) => (
        <span
          key={o}
          className="swatch"
          style={{ background: "var(--risk-high)", opacity: 0.18 + o * 0.82 }}
        />
      ))}
      <span className="muted">{peak} findings</span>
      <span className="muted" style={{ marginLeft: 16 }}>
        (sqrt-scaled so a single outlier does not flatten the grid)
      </span>
    </div>
  );
}
