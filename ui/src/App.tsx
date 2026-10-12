import { useState } from "react";
import { useHealth, useScanSocket } from "./hooks/useScan";
import { useStore } from "./hooks/useStore";
import { CBOMTree } from "./components/CBOMTree";
import { RiskHeatmap } from "./components/RiskHeatmap";
import { MoscaSlider } from "./components/MoscaSlider";
import { BenchmarkCard } from "./components/BenchmarkCard";
import { ScanProgress } from "./components/ScanProgress";

const TABS = [
  ["explorer", "Explorer"],
  ["heatmap", "Heatmap"],
  ["mosca", "Mosca"],
  ["benchmarks", "Benchmarks"],
  ["progress", "Progress"],
] as const;

export default function App() {
  const activeScanId = useStore((s) => s.activeScanId);
  const scanning = useStore((s) => s.scanning);
  const tab = useStore((s) => s.tab);
  const setTab = useStore((s) => s.setTab);
  const cbom = useStore((s) => s.cbom);
  const [raw, setRaw] = useState(false);

  useHealth();
  useScanSocket(scanning || !activeScanId ? activeScanId : activeScanId);

  return (
    <div className="app">
      <header>
        <div className="brand">
          ECDAT
          <span className="muted">Cryptographic Discovery &amp; Analysis</span>
        </div>
        <HealthStrip />
      </header>

      <div className="body">
        <aside>
          <ScanLauncher />
          <ScanHistory />
          <Rollup />
        </aside>

        <main>
          <nav className="tabs">
            {TABS.map(([id, label]) => (
              <button
                key={id}
                className={tab === id ? "tab on" : "tab"}
                onClick={() => setTab(id)}
              >
                {label}
              </button>
            ))}
            <span className="spacer" />
            {cbom && (
              <button
                className="tab ghost"
                onClick={() => setRaw(!raw)}
                title="Toggle the raw CycloneDX document"
              >
                {raw ? "Hide raw CBOM" : "Raw CBOM"}
              </button>
            )}
          </nav>

          <div className="content">
            {raw && cbom ? (
              <pre className="raw">{JSON.stringify(cbom.bom, null, 2)}</pre>
            ) : (
              <>
                {tab === "explorer" && <CBOMTree />}
                {tab === "heatmap" && <RiskHeatmap />}
                {tab === "mosca" && <MoscaSlider />}
                {tab === "benchmarks" && <BenchmarkCard />}
                {tab === "progress" && <ScanProgress />}
              </>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

function HealthStrip() {
  const h = useStore((s) => s.health);
  if (!h) return <span className="muted">connecting…</span>;
  const dot = (ok: boolean) => (ok ? "ok" : "bad");
  return (
    <div className="health">
      <span className={`dot ${dot(h.semgrep.ok)}`} title={`semgrep ${h.semgrep.version ?? h.semgrep.error}`} />
      <span className="muted">semgrep {h.semgrep.version ?? "—"}</span>
      <span className={`dot ${dot(h.syft.ok)}`} title={`syft ${h.syft.version ?? h.syft.error}`} />
      <span className="muted">syft</span>
      <span className={`dot ${dot(h.oqs.ok)}`} title={`liboqs ${h.oqs.version ?? h.oqs.error}`} />
      <span className="muted">liboqs {h.oqs.version ?? "—"}</span>
    </div>
  );
}

function ScanLauncher() {
  const launch = useStore((s) => s.launch);
  const launching = useStore((s) => s.launching);
  const [target, setTarget] = useState("");
  const [bench, setBench] = useState(true);

  return (
    <div className="launcher">
      <label htmlFor="target">Target</label>
      <textarea
        id="target"
        rows={2}
        placeholder="Git URL, local path, zip, or image ref"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
      />
      <label className="check">
        <input
          type="checkbox"
          checked={bench}
          onChange={(e) => setBench(e.target.checked)}
        />
        run PQC benchmarks
      </label>
      <button
        className="primary"
        disabled={launching || !target.trim()}
        onClick={() => void launch(target.trim(), bench)}
      >
        {launching ? "starting…" : "Scan"}
      </button>
    </div>
  );
}

function ScanHistory() {
  const scans = useStore((s) => s.scans);
  const active = useStore((s) => s.activeScanId);
  const selectScan = useStore((s) => s.selectScan);

  return (
    <div className="history">
      <h3>Scans</h3>
      {scans.length === 0 && <p className="empty">No scans yet.</p>}
      <ul>
        {scans.map((s) => (
          <li
            key={s.scan_id}
            className={s.scan_id === active ? "on" : ""}
            onClick={() => void selectScan(s.scan_id)}
          >
            <span className={`dot ${s.state === "done" ? "ok" : s.state === "failed" ? "bad" : "run"}`} />
            <span className="mono">{s.scan_id}</span>
            <span className="muted"> {s.finding_count}f</span>
            <div className="muted small trunc" title={s.target ?? ""}>
              {s.target}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Rollup() {
  const cbom = useStore((s) => s.cbom);
  const bench = useStore((s) => s.bench);
  if (!cbom) return null;
  const fam = cbom.summary.by_family ?? {};
  return (
    <div className="rollup">
      <h3>Inventory</h3>
      <div className="kpis">
        <div>
          <strong>{cbom.summary.total}</strong>
          <span>findings</span>
        </div>
        <div>
          <strong>
            {cbom.bom.components?.filter((c) => c.type === "cryptographic-asset").length ?? 0}
          </strong>
          <span>assets</span>
        </div>
        <div>
          <strong>
            {cbom.bom.components?.filter((c) => c.type === "library").length ?? 0}
          </strong>
          <span>libraries</span>
        </div>
        <div>
          <strong>{cbom.bom.dependencies?.length ?? 0}</strong>
          <span>dep nodes</span>
        </div>
      </div>
      <h4>By family</h4>
      <ul className="fam">
        {Object.entries(fam)
          .sort((a, b) => b[1] - a[1])
          .map(([k, v]) => (
            <li key={k}>
              <span>{k}</span>
              <span className="bar-mini">
                <span style={{ width: `${(v / (cbom.summary.total || 1)) * 100}%` }} />
              </span>
              <span className="muted">{v}</span>
            </li>
          ))}
      </ul>
      {bench && (
        <p className="muted small">liboqs {bench.liboqs_version ?? "n/a"}</p>
      )}
    </div>
  );
}
