import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useStore } from "../hooks/useStore";
import { riskColor } from "./CBOMTree";

/**
 * Mosca collapse-time control.
 *
 * Dragging Z re-ranks the whole finding set server-side rather than in the
 * browser, so the score arithmetic has exactly one implementation and the
 * numbers here always match what the CBOM records. The request is debounced:
 * a 25-stop slider would otherwise fire 25 recalculations per drag.
 */
export function MoscaSlider() {
  const risk = useStore((s) => s.risk);
  const zEstimate = useStore((s) => s.zEstimate);
  const setZ = useStore((s) => s.setZ);
  const rerank = useStore((s) => s.rerank);
  const reranking = useStore((s) => s.reranking);
  const error = useStore((s) => s.error);

  const [local, setLocal] = useState(zEstimate);
  const [timer, setTimer] = useState<number | null>(null);

  useEffect(() => setLocal(zEstimate), [zEstimate]);

  useEffect(() => {
    if (local === zEstimate) return;
    if (timer) window.clearTimeout(timer);
    setTimer(window.setTimeout(() => void rerank(local), 260));
    return () => {
      if (timer) window.clearTimeout(timer);
    };
    // Intentionally not depending on `rerank` identity: it is stable from the
    // zustand store, and re-running this on every store change would loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [local]);

  if (!risk) return <p className="empty">Run a scan to use the Mosca model.</p>;

  const summary = risk.summary;
  const top = risk.ranked.slice(0, 12);

  const data = top.map((f) => ({
    name: `${f.algorithm}`.slice(0, 16),
    score: f.risk_score,
    fill: riskColor(f.risk),
    family: f.algorithm_family,
  }));

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Mosca Model</h2>
        <span className="muted">Risk = (X + Y) &gt; Z</span>
      </div>

      <div className="mosca">
        <label htmlFor="z">Collapse time Z</label>
        <input
          id="z"
          type="range"
          min={5}
          max={30}
          step={0.5}
          value={local}
          onChange={(e) => {
            setZ(Number(e.target.value));
            setLocal(Number(e.target.value));
          }}
        />
        <output>
          {local} years {reranking && <span className="spin">recalculating…</span>}
        </output>
      </div>

      <div className="stats">
        <Stat label="Findings" value={summary.total} />
        <Stat label="Mean score" value={summary.mean_score.toFixed(2)} />
        <Stat
          label="Migrate now"
          value={summary.above_mosca_threshold ?? 0}
          accent={Number(summary.above_mosca_threshold ?? 0) > 0}
        />
        <Stat label="Peak" value={summary.max_score.toFixed(2)} />
      </div>

      {error && <p className="error">recalculation failed: {error}</p>}

      <div className="chart">
        <ResponsiveContainer width="100%" height={Math.max(200, data.length * 26)}>
          <BarChart data={data} margin={{ top: 4, right: 16, bottom: 4, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--line)" />
            <XAxis
              dataKey="name"
              tick={{ fontSize: 11, fill: "var(--muted)" }}
              interval={0}
              angle={-30}
              textAnchor="end"
              height={70}
            />
            <YAxis
              domain={[0, 10]}
              tick={{ fontSize: 11, fill: "var(--muted)" }}
              width={32}
            />
            <Tooltip
              contentStyle={{
                background: "var(--panel)",
                border: "1px solid var(--line)",
                borderRadius: 6,
                fontSize: 12,
              }}
              formatter={(v: number, _n, p) => [
                `${v.toFixed(2)} / 10  (${(p as { payload: { family: string } }).payload.family})`,
                "score",
              ]}
            />
            <Bar dataKey="score" radius={[3, 3, 0, 0]}>
              {data.map((d, i) => (
                <Cell key={i} fill={d.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <p className="note">
        Lowering Z models a nearer quantum threat and re-ranks everything upward.
        Primitives already broken on classical hardware keep their floor and do
        not move — that is why the ceiling is often pinned at 10.
      </p>
    </div>
  );
}

function Stat({ label, value, accent }: { label: string; value: string | number; accent?: boolean }) {
  return (
    <div className="stat">
      <div className="stat-v" style={accent ? { color: "var(--risk-critical)" } : undefined}>
        {value}
      </div>
      <div className="stat-k">{label}</div>
    </div>
  );
}
