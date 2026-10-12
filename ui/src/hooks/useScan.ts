import { useEffect, useRef } from "react";
import { useStore } from "./useStore";
import { wsUrl } from "../services/api";

/**
 * Subscribe to the scan's progress WebSocket.
 *
 * The server replays the full event history to late subscribers, so this is
 * safe to connect to after a scan has already finished — which is exactly what
 * happens when the user picks a scan out of the sidebar.
 */
export function useScanSocket(scanId: string | null) {
  const pushEvent = useStore((s) => s.pushEvent);
  const seen = useRef<Set<string>>(new Set());

  useEffect(() => {
    if (!scanId) return;
    seen.current = new Set();

    const ws = new WebSocket(wsUrl(`/api/scan/${scanId}/ws`));
    ws.onmessage = (m) => {
      try {
        const evt = JSON.parse(m.data);
        // Keepalive pings carry no stage information worth recording.
        if (!evt?.stage || evt.stage === "ping") return;
        // The server replays history on connect; a resubscribe mid-scan can
        // deliver a stage twice. Key on stage+progress so replays are idempotent.
        const key = `${evt.stage}:${evt.progress}:${evt.timestamp ?? ""}`;
        if (seen.current.has(key)) return;
        seen.current.add(key);
        pushEvent(evt);
      } catch {
        /* malformed frame - ignore, the status poll is the safety net */
      }
    };
    ws.onclose = () => {
      /* server closes after the terminal stage; nothing to do */
    };
    ws.onerror = () => {
      /* polling in useStore.scanStatus keeps status correct regardless */
    };

    return () => ws.close();
  }, [scanId, pushEvent]);
}

/** Polls the health endpoint so the header reflects real component state. */
export function useHealth() {
  const refreshHealth = useStore((s) => s.refreshHealth);
  const refreshScans = useStore((s) => s.refreshScans);

  useEffect(() => {
    void refreshHealth();
    void refreshScans();
    const t = setInterval(() => {
      void refreshHealth();
      void refreshScans();
    }, 15_000);
    return () => clearInterval(t);
  }, [refreshHealth, refreshScans]);
}
