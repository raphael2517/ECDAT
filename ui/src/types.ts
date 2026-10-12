/**
 * Types mirroring api/src/models.py. Kept deliberately hand-written rather than
 * generated: the API is a fixed internal contract, and a build-time codegen
 * step would be one more thing to keep working in an air-gapped image.
 */

export type ScanState =
  | "queued"
  | "running"
  | "done"
  | "failed"
  | "cancelled";

export interface ScanStatus {
  scan_id: string;
  state: ScanState;
  progress: number;
  target: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  elapsed_seconds: number | null;
  finding_count: number;
  error: string | null;
  result_path: string | null;
}

export interface RiskBreakdown {
  mosca_shelf_life_years: number;
  mosca_migration_years: number;
  mosca_collapse_years: number;
  mosca_ratio: number;
  mosca_normalized: number;
  quantum_toffoli: number;
  quantum_logical_qubits: number;
  quantum_normalized: number;
  quantum_source: string;
  classical_weakness: number;
  migration_urgency: number;
  final_score: number;
  mosca_triggered: boolean;
  rationale: string[];
}

export interface EnrichmentRule {
  algorithm: string;
  usage: string;
  key_mgmt: string;
  risk: string;
}

export interface Finding {
  file: string;
  line: number;
  rule_id: string;
  algorithm: string;
  algorithm_family: string;
  mode: string;
  severity: string;
  cwe: string;
  cwe2: string;
  snippet: string;
  context: string;
  source: "semgrep" | "syft";
  usage: string;
  key_mgmt: string;
  risk: string;
  risk_score: number;
  enrichment_source: string;
  extra: {
    risk?: RiskBreakdown;
    enrichment_rule?: EnrichmentRule;
    library?: string;
    version?: string;
    end_line?: number;
    message?: string;
  };
}

export interface RiskSummary {
  total: number;
  by_family: Record<string, number>;
  max_score: number;
  mean_score: number;
  above_mosca_threshold?: number;
}

export interface CBOMResponse {
  scan_id: string;
  spec_version: string;
  bom: CycloneDXBom;
  summary: RiskSummary;
  findings: Finding[];
}

export interface CycloneDXComponent {
  "bom-ref"?: string;
  type: string;
  name: string;
  version?: string;
  description?: string;
  cryptoProperties?: Record<string, unknown>;
  properties?: { name: string; value: string }[];
}

export interface CycloneDXBom {
  bomFormat: string;
  specVersion: string;
  components?: CycloneDXComponent[];
  dependencies?: { ref: string; dependsOn?: string[] }[];
  metadata?: Record<string, unknown>;
}

export interface RiskResponse {
  scan_id: string;
  z_estimate: number;
  summary: RiskSummary;
  ranked: Finding[];
}

export interface BenchRow {
  scheme: string;
  kind: string;
  implementation: "classical" | "pqc";
  keygen_ms: number;
  primary_ms: number;
  secondary_ms: number;
  pub_key_bytes: number;
  payload_bytes: number;
  sec_key_bytes: number;
  iterations: number;
  error: string;
}

export interface BenchDelta {
  metric: string;
  classical: number;
  pqc: number;
  delta_pct: number;
  direction: "better" | "worse" | "same";
  lower_is_better: boolean;
}

export interface BenchComparison {
  kind: string;
  classical: BenchRow;
  pqc: BenchRow | null;
  pairs_with: string;
  deltas: BenchDelta[];
}

export interface BenchmarkResponse {
  scan_id: string;
  rows: BenchRow[];
  comparisons: BenchComparison[];
  liboqs_available: boolean;
  liboqs_version: string | null;
}

export interface Recommendation {
  from: string;
  migrate_to: string[];
  rationale: string;
  stdlib: string | null;
  occurrences: number;
  risk_score: number;
  source_finding: Record<string, unknown>;
}

export interface ProgressEvent {
  stage: string;
  progress: number;
  scan_id: string | null;
  message: string | null;
  timestamp: string;
  detail: Record<string, unknown>;
}

export interface Health {
  status: string;
  version: string;
  semgrep: { ok: boolean; version?: string; error?: string };
  syft: { ok: boolean; version?: string; error?: string };
  oqs: {
    ok: boolean;
    version?: string;
    kem?: string[];
    sig?: string[];
    error?: string;
  };
  rules: { ok: boolean; path: string; files: string[] };
}
