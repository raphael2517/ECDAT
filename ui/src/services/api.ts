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

const KEY_STORAGE = "ecdat.apiKey";

/**
 * The shared secret for a deployment that sets ECDAT_API_KEY.
 *
 * Held in localStorage rather than a build-time env var on purpose: anything
 * baked into the bundle at build time is readable by anyone who loads the
 * page, which makes it decoration rather than a control. Typed in by whoever
 * is using the instance, it is a real (if modest) secret.
 */
export function getApiKey(): string {
  try {
    return window.localStorage.getItem(KEY_STORAGE) ?? "";
  } catch {
    return "";
  }
}

export function setApiKey(key: string): void {
  try {
    if (key) window.localStorage.setItem(KEY_STORAGE, key);
    else window.localStorage.removeItem(KEY_STORAGE);
  } catch {
    /* private browsing; the key just will not persist */
  }
}

api.interceptors.request.use((cfg) => {
  const key = getApiKey();
  if (key) cfg.headers.set("X-ECDAT-Key", key);
  return cfg;
});

/**
 * A 401 here almost always means the key is missing or stale, which is worth
 * saying plainly rather than surfacing as a bare "Request failed with status
 * code 401".
 */
api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (axios.isAxiosError(err) && err.response?.status === 401) {
      return Promise.reject(
        new Error(
          "unauthorized: this ECDAT instance requires an API key. Enter it in the sidebar.",
        ),
      );
    }
    return Promise.reject(err);
  },
);

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
  const base = `${proto}//${window.location.host}${path}`;
  // Browsers cannot set headers on a WebSocket handshake, so the key goes in
  // the query string here. Same TLS connection, same protection.
  const key = getApiKey();
  return key ? `${base}?key=${encodeURIComponent(key)}` : base;
};

export default api;
