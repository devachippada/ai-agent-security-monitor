import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { EventOut, SessionSummary } from "../types";
import { ActionBadge, InjectionBadge, RiskScoreBar } from "../components/Badges";

export default function SessionReplayPage() {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [sessionId, setSessionId] = useState<string>("");
  const [events, setEvents] = useState<EventOut[]>([]);
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const timerRef = useRef<number | null>(null);

  useEffect(() => {
    api.listSessions().then((s) => {
      setSessions(s);
      if (s.length > 0) setSessionId(s[0].session_id);
    });
  }, []);

  useEffect(() => {
    if (!sessionId) return;
    api.getSessionEvents(sessionId).then((evts) => {
      setEvents(evts);
      setStep(0);
      setPlaying(false);
    });
  }, [sessionId]);

  useEffect(() => {
    if (playing && step < events.length - 1) {
      timerRef.current = window.setTimeout(() => setStep((s) => s + 1), 1600);
    } else if (playing) {
      setPlaying(false);
    }
    return () => {
      if (timerRef.current) window.clearTimeout(timerRef.current);
    };
  }, [playing, step, events.length]);

  const visible = events.slice(0, step + 1);

  return (
    <div className="p-6 space-y-4 max-w-4xl">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="font-semibold text-lg">Session Replay</h1>
          <p className="text-xs text-slate-500">Step through (or auto-play) a past session exactly as the gateway evaluated it, turn by turn.</p>
        </div>
        <select
          value={sessionId}
          onChange={(e) => setSessionId(e.target.value)}
          className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs"
        >
          {sessions.map((s) => (
            <option key={s.session_id} value={s.session_id}>
              {s.session_id} -- {new Date(s.last_event_at).toLocaleString()}
            </option>
          ))}
        </select>
      </div>

      {events.length === 0 ? (
        <div className="text-sm text-slate-500">No events in this session.</div>
      ) : (
        <>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setStep((s) => Math.max(0, s - 1))}
              disabled={step === 0}
              className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs disabled:opacity-30"
            >
              ← Prev
            </button>
            <button
              onClick={() => setPlaying((p) => !p)}
              className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-medium"
            >
              {playing ? "Pause" : "▶ Play"}
            </button>
            <button
              onClick={() => setStep((s) => Math.min(events.length - 1, s + 1))}
              disabled={step === events.length - 1}
              className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs disabled:opacity-30"
            >
              Next →
            </button>
            <span className="text-xs text-slate-500 ml-2">
              Step {step + 1} / {events.length}
            </span>
          </div>

          <div className="space-y-3">
            {visible.map((e, i) => (
              <div
                key={e.event_id}
                className={`bg-slate-900 border rounded-lg p-4 space-y-2 transition-colors ${
                  i === step ? "border-cyan-700" : "border-slate-800 opacity-60"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[11px] text-slate-500">{new Date(e.timestamp).toLocaleTimeString()}</span>
                  <div className="flex items-center gap-2">
                    <ActionBadge action={e.action} />
                    {e.injection_classification && <InjectionBadge classification={e.injection_classification} />}
                  </div>
                </div>
                <div className="text-sm font-mono text-slate-300">{e.prompt}</div>
                <RiskScoreBar score={e.risk_score} level={e.risk_level} />
                <div className="text-xs text-slate-500">{e.detection_reason}</div>
                {e.tool_name && <div className="text-[11px] text-slate-600">tool: {e.tool_name}</div>}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
