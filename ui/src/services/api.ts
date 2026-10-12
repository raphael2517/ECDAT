import axios from "axios";
import type {
  BenchmarkResponse,
  CBOMResponse,
  Health,
  Recommendation,
  RiskResponse,
  ScanStatus,
} from "../types";

/**
 * Relative base: in production nginx serves the bundle on / and proxies
 * /api to uvicorn, so the same-origin path works with no configuration.
 * Pinning an absolute host would break the air-gapped, single-origin design.
 */
const api = axios.create({ baseURL: "/", timeout: 120_000 });

function problemMessage(err: unknown, fallback: string): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (detail) return JSON.stringify(detail);
    if (err.code === "ECONNABORTED") return "request timed out";
    return err.message || fallback;
  }
  return err instanceof Error ? err.message : fallback;
}

export const startScan = async (target: string, opts?: {
  zEstimate?: number;
  runBenchmarks?: boolean;
  iterations?: number;
  fastBench?: boolean;
}): Promise<ScanStatus> => {
  try {
    const { data } = await api.post<ScanStatus>("/api/scan", {
      target,
      z_estimate: opts?.zEstimate ?? 15,
      run_benchmarks: opts?.runBenchmarks ?? true,
      iterations: opts?.iterations ?? 100,
      fast_bench: opts?.fastBench ?? false,
    });
    return data;
  } catch (err) {
    throw new Error(problemMessage(err, "could not start scan"));
  }
};

export const listScans = async (): Promise<ScanStatus[]> => {
  try {
    const { data } = await api.get<ScanStatus[]>("/api/scan");
    return data;
  } catch {
    return [];
  }
};

export const scanStatus = (id: string) => api.get<ScanStatus>(`/api/scan/${id}/status`);

export const cancelScan = (id: string) => api.delete<ScanStatus>(`/api/scan/${id}`);

export const getCBOM = async (id: string): Promise<CBOMResponse> => {
  const { data } = await api.get<CBOMResponse>(`/api/cbom/${id}`);
  return data;
};

export const getRisk = async (id: string): Promise<RiskResponse> => {
  const { data } = await api.get<RiskResponse>(`/api/risk/${id}`);
  return data;
};

/** Re-rank at a new Mosca collapse time. Server-side, so there is one implementation of the maths. */
export const recalcRisk = async (id: string, z: number): Promise<RiskResponse> => {
  try {
    const { data } = await api.post<RiskResponse>(`/api/risk/recalculate/${id}`, null, {
      params: { z },
      timeout: 300_000,
    });
    return data;
  } catch (err) {
    throw new Error(problemMessage(err, "recalculation failed"));
  }
};

export const getBenchmark = async (id: string): Promise<BenchmarkResponse> => {
  const { data } = await api.get<BenchmarkResponse>(`/api/benchmark/${id}`);
  return data;
};

export const getRecommendations = async (id: string): Promise<Recommendation[]> => {
  const { data } = await api.get<Recommendation[]>(`/api/recommendations/${id}`);
  return data;
};

export const getHealth = async (): Promise<Health | null> => {
  try {
    const { data } = await api.get<Health>("/health");
    return data;
  } catch {
    return null;
  }
};

/** ws:// or wss:// depending on page protocol. */
export const wsUrl = (path: string): string => {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${path}`;
};

export default api;
