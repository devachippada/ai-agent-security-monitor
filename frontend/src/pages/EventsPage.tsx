import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { EventOut } from "../types";
import { ActionBadge, InjectionBadge, RiskBadge } from "../components/Badges";

export default function EventsPage() {
  const [events, setEvents] = useState<EventOut[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [filterAction, setFilterAction] = useState<string>("");
  const [live, setLive] = useState(false);

  async function load() {
    const data = await api.listEvents({ limit: 200 });
    setEvents(data);
    setLoading(false);
  }

  useEffect(() => {
    load();
  }, []);

  // Phase 2: live updates via Server-Sent Events instead of polling.
  // Falls back to a 5s poll if the stream can't connect.
  useEffect(() => {
    let pollId: number | undefined;
    let source: EventSource | undefined;
    try {
      source = new EventSource("/api/events/stream");
      source.onopen = () => setLive(true);
      source.onmessage = (msg) => {
        try {
          const payload = JSON.parse(msg.data);
          if (payload.type === "connected") return;
          setEvents((prev) => {
            if (prev.some((e) => e.event_id === payload.event_id)) return prev;
            return [payload as EventOut, ...prev];
          });
        } catch {
          // ignore malformed frame
        }
      };
      source.onerror = () => {
        setLive(false);
        source?.close();
        pollId = window.setInterval(load, 5000);
      };
    } catch {
      pollId = window.setInterval(load, 5000);
    }
    return () => {
      source?.close();
      if (pollId) window.clearInterval(pollId);
    };
  }, []);

  const filtered = filterAction ? events.filter((e) => e.action === filterAction) : events;

  return (
    <div className="p-4 md:p-6 space-y-4 max-w-6xl">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-semibold text-lg">Event Log</h1>
          <div className="flex items-center gap-2 mt-0.5">
            <p className="text-xs text-slate-500">Full audit trail -- every prompt that reached the security gateway.</p>
            <span className={`flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded-full ${live ? "bg-emerald-500/15 text-emerald-400" : "bg-slate-800 text-slate-500"}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${live ? "bg-emerald-400 animate-pulse" : "bg-slate-600"}`} />
              {live ? "Live (SSE)" : "Polling"}
            </span>
          </div>
        </div>
        <select
          value={filterAction}
          onChange={(e) => setFilterAction(e.target.value)}
          className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs"
        >
          <option value="">All actions</option>
          <option value="ALLOWED">Allowed</option>
          <option value="BLOCKED">Blocked</option>
          <option value="APPROVAL_REQUIRED">Approval required</option>
        </select>
      </div>

      {loading ? (
        <div className="text-sm text-slate-500">Loading…</div>
      ) : filtered.length === 0 ? (
        <div className="text-sm text-slate-500">No events yet -- try the Chat page or Attack Simulator.</div>
      ) : (
        <div className="space-y-2">
          {filtered.map((e) => (
            <div key={e.event_id} className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <button
                className="w-full text-left px-4 py-3 flex flex-wrap items-center gap-2 md:gap-3 hover:bg-slate-800/40 transition-colors"
                onClick={() => setExpanded(expanded === e.event_id ? null : e.event_id)}
              >
                <span className="text-[11px] text-slate-500 shrink-0 md:w-36 font-mono">{new Date(e.timestamp).toLocaleTimeString()}</span>
                <ActionBadge action={e.action} />
                <RiskBadge level={e.risk_level} />
                {e.injection_classification && <InjectionBadge classification={e.injection_classification} />}
                <span className="text-xs text-slate-400 truncate w-full md:w-auto md:flex-1 order-last md:order-none">{e.prompt}</span>
                {e.tool_name && <span className="text-[11px] text-slate-600 shrink-0">{e.tool_name}</span>}
              </button>
              {expanded === e.event_id && (
                <div className="px-4 pb-4 pt-1 text-xs text-slate-400 space-y-2 border-t border-slate-800">
                  <Row label="Event ID" value={e.event_id} mono />
                  <Row label="Session ID" value={e.session_id ?? "-"} mono />
                  <Row label="Risk score" value={`${e.risk_score.toFixed(1)} (${e.risk_level})`} />
                  <Row label="Injection score" value={e.injection_score !== null ? e.injection_score.toFixed(1) : "-"} />
                  <Row label="Detection types" value={e.detection_type || "none"} />
                  <Row label="Latency" value={`${e.latency_ms.toFixed(2)} ms`} />
                  <Row label="Reasoning" value={e.detection_reason ?? "-"} />
                  {e.tool_arguments && <Row label="Tool arguments" value={e.tool_arguments} mono />}
                  {e.response && <Row label="Response" value={e.response} mono />}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-3">
      <span className="text-slate-600 w-32 shrink-0">{label}</span>
      <span className={`flex-1 break-all ${mono ? "font-mono text-slate-300" : ""}`}>{value}</span>
    </div>
  );
}
