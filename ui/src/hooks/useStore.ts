import { create } from "zustand";
import type {
  BenchmarkResponse,
  CBOMResponse,
  Finding,
  Health,
  ProgressEvent,
  Recommendation,
  RiskResponse,
  ScanStatus,
} from "../types";
import {
  getBenchmark,
  getCBOM,
  getHealth,
  getRecommendations,
  getRisk,
  listScans,
  recalcRisk,
  scanStatus,
  startScan,
} from "../services/api";

type Tab = "explorer" | "heatmap" | "mosca" | "benchmarks" | "progress";

interface EcdatState {
  // health
  health: Health | null;

  // scans
  scans: ScanStatus[];
  activeScanId: string | null;
  scanning: boolean;
  launching: boolean;
  error: string | null;

  // live progress
  events: ProgressEvent[];

  // results
  cbom: CBOMResponse | null;
  risk: RiskResponse | null;
  bench: BenchmarkResponse | null;
  recommendations: Recommendation[];

  // ui
  tab: Tab;
  zEstimate: number;
  selected: Finding | null;
  reranking: boolean;
  /** Heatmap cell drill-down: filters the explorer to one family + severity. */
  focus: { family: string; severity: string } | null;

  // actions
  refreshHealth: () => Promise<void>;
  refreshScans: () => Promise<void>;
  launch: (target: string, runBenchmarks: boolean) => Promise<void>;
  poll: (id: string) => Promise<void>;
  selectScan: (id: string) => Promise<void>;
  pushEvent: (e: ProgressEvent) => void;
  setTab: (t: Tab) => void;
  setZ: (z: number) => void;
  rerank: (z: number) => Promise<void>;
  select: (f: Finding | null) => void;
  setFocus: (f: { family: string; severity: string } | null) => void;
  reset: () => void;
}

// Mutable empty defaults. Typed explicitly rather than `as const`: a const
// object literal infers readonly arrays, which zustand's state type rejects.
const EMPTY: Pick<
  EcdatState,
  "cbom" | "risk" | "bench" | "recommendations" | "events" | "selected"
> = {
  cbom: null,
  risk: null,
  bench: null,
  recommendations: [],
  events: [],
  selected: null,
};

export const useStore = create<EcdatState>((set, get) => ({
  health: null,
  scans: [],
  activeScanId: null,
  scanning: false,
  launching: false,
  error: null,
  events: [],
  cbom: null,
  risk: null,
  bench: null,
  recommendations: [],
  tab: "explorer",
  zEstimate: 15,
  selected: null,
  reranking: false,
  focus: null,

  refreshHealth: async () => set({ health: await getHealth() }),

  refreshScans: async () => set({ scans: await listScans() }),

  launch: async (target, runBenchmarks) => {
    set({ ...EMPTY, launching: true, error: null, tab: "explorer" });
    try {
      const job = await startScan(target, { zEstimate: get().zEstimate, runBenchmarks });
      set({ launching: false, scanning: true, activeScanId: job.scan_id });
      get().poll(job.scan_id);
    } catch (e) {
      set({ launching: false, scanning: false, error: (e as Error).message });
    }
  },

  poll: async (id) => {
    try {
      const { data } = await scanStatus(id);
      set({ scanning: data.state === "running" || data.state === "queued" });
      await get().refreshScans();
      if (data.state === "done") {
        await get().selectScan(id);
      } else if (data.state === "failed") {
        set({ scanning: false, error: data.error ?? "scan failed" });
      } else if (data.state === "running" || data.state === "queued") {
        setTimeout(() => void get().poll(id), 1500);
      }
    } catch (e) {
      set({ scanning: false, error: (e as Error).message });
    }
  },

  selectScan: async (id) => {
    set({ ...EMPTY, activeScanId: id, error: null });
    try {
      // These are independent; fetch together so the detail pane populates once.
      const [cbom, risk, bench, recs] = await Promise.all([
        getCBOM(id),
        getRisk(id),
        getBenchmark(id).catch(() => null),
        getRecommendations(id).catch((): Recommendation[] => []),
      ]);
      set({
        cbom,
        risk,
        bench,
        recommendations: recs,
        zEstimate: risk.z_estimate,
        scanning: false,
      });
    } catch (e) {
      set({ error: (e as Error).message, scanning: false });
    }
  },

  pushEvent: (e) =>
    set((s) => ({
      events: [...s.events, e].slice(-400),
      scanning: e.stage !== "done" && e.stage !== "error" && e.stage !== "cancelled",
    })),

  setTab: (tab) => set({ tab }),

  setZ: (zEstimate) => set({ zEstimate }),

  rerank: async (z) => {
    const id = get().activeScanId;
    if (!id) return;
    set({ reranking: true, zEstimate: z, error: null });
    try {
      const risk = await recalcRisk(id, z);
      // Keep the CBOM rollup in step so the sidebar counts do not go stale.
      set((s) => ({
        risk,
        cbom: s.cbom ? { ...s.cbom, risk: undefined, summary: risk.summary, findings: risk.ranked } : s.cbom,
        reranking: false,
      }));
    } catch (e) {
      set({ reranking: false, error: (e as Error).message });
    }
  },

  select: (selected) => set({ selected, tab: selected ? "explorer" : get().tab }),

  // Drill down from a heatmap cell into the explorer, filtered to that cell.
  setFocus: (focus) => {
    if (!focus) return set({ focus: null, tab: get().tab });
    set({ focus, selected: null, tab: "explorer" });
  },

  reset: () => set({ ...EMPTY, focus: null, activeScanId: null, error: null, tab: "explorer" }),
}));
