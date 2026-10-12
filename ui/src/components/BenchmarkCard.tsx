import { useStore } from "../hooks/useStore";
import type { BenchComparison, BenchRow } from "../types";

const METRIC_LABEL: Record<string, string> = {
  keygen_ms: "Key generation",
  primary_ms: "Sign / Encapsulate",
  secondary_ms: "Verify / Decapsulate",
  pub_key_bytes: "Public key size",
  payload_bytes: "Ciphertext / Sig size",
};

function fmt(metric: string, v: number): string {
  if (metric.endsWith("_ms")) return `${v.toFixed(4)} ms`;
  return `${v.toLocaleString()} B`;
}

function Row({ r }: { r: BenchRow }) {
  return (
    <tr>
      <td>
        <strong>{r.scheme}</strong>
        <span className={`tag ${r.implementation}`}>{r.implementation}</span>
      </td>
      <td className="num">{fmt("keygen_ms", r.keygen_ms)}</td>
      <td className="num">{fmt("primary_ms", r.primary_ms)}</td>
      <td className="num">{fmt("secondary_ms", r.secondary_ms)}</td>
      <td className="num">{fmt("pub_key_bytes", r.pub_key_bytes)}</td>
      <td className="num">{fmt("payload_bytes", r.payload_bytes)}</td>
    </tr>
  );
}

function Comparison({ c }: { c: BenchComparison }) {
  if (!c.pqc) {
    return (
      <div className="card">
        <h3>
          {c.classical.scheme} <span className="muted">baseline only</span>
        </h3>
        <p className="note">No counterpart measured for {c.pairs_with}.</p>
      </div>
    );
  }

  return (
    <div className="card">
      <h3>
        {c.classical.scheme} <span className="muted">→</span> {c.pairs_with}
      </h3>
      <table className="grid compact">
        <thead>
          <tr>
            <th>Metric</th>
            <th className="num">Classical</th>
            <th className="num">PQC</th>
            <th className="num">Delta</th>
            <th>Verdict</th>
          </tr>
        </thead>
        <tbody>
          {c.deltas.map((d) => (
            <tr key={d.metric}>
              <td>{METRIC_LABEL[d.metric] ?? d.metric}</td>
              <td className="num">{fmt(d.metric, d.classical)}</td>
              <td className="num">{fmt(d.metric, d.pqc)}</td>
              <td className="num" style={{ color: deltaColor(d.delta_pct, d.direction) }}>
                {d.delta_pct > 0 ? "+" : ""}
                {d.delta_pct.toFixed(1)}%
              </td>
              <td>
                <span
                  className="badge"
                  style={{ background: deltaColor(d.delta_pct, d.direction) }}
                >
                  {d.direction}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function deltaColor(pct: number, direction: string): string {
  if (direction === "same") return "var(--risk-info)";
  return pct < 0 ? "var(--risk-low)" : "var(--risk-high)";
}

export function BenchmarkCard() {
  const bench = useStore((s) => s.bench);
  const recs = useStore((s) => s.recommendations);

  if (!bench) return <p className="empty">Run a scan with benchmarks enabled.</p>;

  const ok = bench.rows.filter((r) => !r.error);
  const failed = bench.rows.filter((r) => r.error);

  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Post-Quantum Benchmarks</h2>
        <span className="muted">
          liboqs {bench.liboqs_version ?? "unavailable"} · measured in-container
        </span>
      </div>

      {!bench.liboqs_available && (
        <p className="error">
          liboqs did not load, so PQC rows are missing. Check OQS_INSTALL_PATH and
          that /opt/oqs/lib/liboqs.so exists.
        </p>
      )}

      {failed.length > 0 && (
        <p className="note">
          {failed.length} row(s) failed:{" "}
          {failed.map((f) => `${f.scheme} (${f.error})`).join(", ")}
        </p>
      )}

      <table className="grid">
        <thead>
          <tr>
            <th>Scheme</th>
            <th className="num">Keygen</th>
            <th className="num">Sign/Encaps</th>
            <th className="num">Verify/Decaps</th>
            <th className="num">Pub key</th>
            <th className="num">Payload</th>
          </tr>
        </thead>
        <tbody>
          {ok.map((r) => (
            <Row key={r.scheme} r={r} />
          ))}
        </tbody>
      </table>

      {bench.comparisons.length > 0 && (
        <>
          <h3 className="section">Before / after</h3>
          <div className="cards">
            {bench.comparisons.map((c) => (
              <Comparison key={`${c.classical.scheme}-${c.pairs_with}`} c={c} />
            ))}
          </div>
        </>
      )}

      {recs.length > 0 && (
        <>
          <h3 className="section">Migration plan</h3>
          <div className="cards">
            {recs.map((r) => (
              <div className="card" key={r.from}>
                <h3>
                  {r.from} <span className="muted">→</span> {r.migrate_to.join(" + ")}
                </h3>
                <p className="note">{r.rationale}</p>
                {r.stdlib && (
                  <p className="note">
                    <strong>Where:</strong> {r.stdlib}
                  </p>
                )}
                <p className="note muted">
                  {r.occurrences} occurrence{r.occurrences === 1 ? "" : "s"}
                </p>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
