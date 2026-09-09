import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { EventOut } from "../types";
import { ActionBadge } from "../components/Badges";

interface Stage {
  stage: string;
  [key: string]: unknown;
}

const STAGE_LABELS: Record<string, string> = {
  agent_proposal: "1. FinAssist Agent Proposal",
  prompt_injection_detector: "2. Prompt-Injection Detector",
  sensitive_data_detector: "3. Sensitive-Data Detector",
  exfiltration_detector: "4. Data-Exfiltration Detector",
  policy_engine: "5. Tool Authorization & Policy Engine",
  behavioral_anomaly_detector: "6. Behavioral-Anomaly Detector",
  risk_scoring_engine: "7. Risk-Scoring Engine -> Decision",
};

export default function AgentTracePage() {
  const [events, setEvents] = useState<EventOut[]>([]);
  const [selected, setSelected] = useState<EventOut | null>(null);

  useEffect(() => {
    api.listEvents({ limit: 100 }).then((evts) => {
      setEvents(evts);
      if (evts.length > 0) setSelected(evts[0]);
    });
  }, []);

  const trace = selected?.trace ? (JSON.parse(selected.trace).stages as Stage[]) : null;

  return (
    <div className="flex flex-col md:flex-row h-full">
      <div className="w-full md:w-80 shrink-0 max-h-64 md:max-h-none border-b md:border-b-0 md:border-r border-slate-800 overflow-y-auto">
        <div className="px-4 py-4 border-b border-slate-800">
          <h1 className="font-semibold text-sm">Agent Trace</h1>
          <p className="text-xs text-slate-500 mt-1">Pick an event to see every gateway stage it passed through.</p>
        </div>
        {events.map((e) => (
          <button
            key={e.event_id}
            onClick={() => setSelected(e)}
            className={`w-full text-left px-4 py-2.5 border-b border-slate-900 text-xs hover:bg-slate-900/70 transition-colors ${
              selected?.event_id === e.event_id ? "bg-slate-900" : ""
            }`}
          >
            <div className="flex items-center gap-2 mb-1">
              <ActionBadge action={e.action} />
              <span className="text-slate-600">{new Date(e.timestamp).toLocaleTimeString()}</span>
            </div>
            <div className="text-slate-400 truncate">{e.prompt}</div>
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        {!selected || !trace ? (
          <div className="text-sm text-slate-500">Select an event to view its trace.</div>
        ) : (
          <div className="max-w-3xl space-y-4">
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
              <div className="text-xs text-slate-500 mb-1">Prompt</div>
              <div className="text-sm font-mono">{selected.prompt}</div>
            </div>

            <div className="relative pl-6 space-y-4 before:absolute before:left-[9px] before:top-2 before:bottom-2 before:w-px before:bg-slate-800">
              {trace.map((stage, i) => (
                <StageCard key={i} stage={stage} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function StageCard({ stage }: { stage: Stage }) {
  const label = STAGE_LABELS[stage.stage] ?? stage.stage;
  const flagged = detectStageFlag(stage);

  return (
    <div className="relative">
      <div
        className={`absolute -left-6 top-1.5 h-3 w-3 rounded-full border-2 ${
          flagged ? "bg-amber-400 border-amber-300" : "bg-slate-700 border-slate-600"
        }`}
      />
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div className="text-xs font-semibold text-slate-300 mb-2">{label}</div>
        <StageBody stage={stage} />
      </div>
    </div>
  );
}

function detectStageFlag(stage: Stage): boolean {
  if (stage.stage === "prompt_injection_detector") return stage.classification !== "SAFE";
  if (stage.stage === "sensitive_data_detector") return Array.isArray(stage.findings) && stage.findings.length > 0;
  if (stage.stage === "exfiltration_detector") return Array.isArray(stage.findings) && stage.findings.length > 0;
  if (stage.stage === "policy_engine")
    return stage.authorized_by_role === false || stage.requires_approval === true || stage.exceeded_call_budget === true;
  if (stage.stage === "behavioral_anomaly_detector") return stage.is_anomalous === true;
  if (stage.stage === "risk_scoring_engine") return stage.decision !== "ALLOWED";
  return false;
}

function StageBody({ stage }: { stage: Stage }) {
  switch (stage.stage) {
    case "agent_proposal":
      return (
        <div className="text-xs text-slate-400 space-y-1">
          <div>{String(stage.summary)}</div>
          {stage.proposed_tool ? <div className="font-mono text-slate-500">tool: {String(stage.proposed_tool)}</div> : null}
        </div>
      );
    case "prompt_injection_detector": {
      const signals = (stage.signals as { name: string; score: number; triggered: boolean; reason: string | null }[]) ?? [];
      return (
        <div className="space-y-2">
          <div className="text-xs text-slate-400">
            Score: <span className="font-semibold text-slate-200">{Number(stage.score).toFixed(1)}</span> -- {String(stage.classification)}
          </div>
          <div className="flex flex-wrap gap-1.5">
            {signals
              .filter((s) => s.triggered)
              .map((s) => (
                <span key={s.name} className="text-[11px] px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  {s.name.replace(/_/g, " ")} ({s.score.toFixed(2)})
                </span>
              ))}
            {signals.every((s) => !s.triggered) && <span className="text-[11px] text-slate-600">No signals triggered</span>}
          </div>
        </div>
      );
    }
    case "sensitive_data_detector":
    case "exfiltration_detector": {
      const findings = (stage.findings as string[]) ?? [];
      return findings.length > 0 ? (
        <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside">
          {findings.map((f, i) => (
            <li key={i}>{f}</li>
          ))}
        </ul>
      ) : (
        <div className="text-xs text-slate-600">No findings</div>
      );
    }
    case "policy_engine":
      return (
        <div className="text-xs text-slate-400 space-y-1">
          <div>Authorized by role: {String(stage.authorized_by_role)}</div>
          <div>Requires approval: {String(stage.requires_approval)}</div>
          <div>Exceeded call budget: {String(stage.exceeded_call_budget)}</div>
        </div>
      );
    case "behavioral_anomaly_detector":
      return stage.available ? (
        <div className="text-xs text-slate-400 space-y-1">
          <div>
            Anomaly score: <span className="font-semibold text-slate-200">{Number(stage.anomaly_score).toFixed(1)}</span> --{" "}
            {stage.is_anomalous ? "ANOMALOUS" : "normal"}
          </div>
          <div className="text-slate-500">{String(stage.explanation)}</div>
        </div>
      ) : (
        <div className="text-xs text-slate-600">Model not loaded (train it with backend/train_model.py)</div>
      );
    case "risk_scoring_engine": {
      const components = (stage.component_scores as Record<string, number>) ?? {};
      return (
        <div className="space-y-2">
          <div className="text-xs text-slate-400">
            Final score: <span className="font-semibold text-slate-200">{Number(stage.final_risk_score).toFixed(1)}</span> ({String(stage.risk_level)}) -&gt;{" "}
            <span className="font-semibold text-slate-200">{String(stage.decision)}</span>
          </div>
          <div className="grid grid-cols-2 gap-1.5">
            {Object.entries(components).map(([k, v]) => (
              <div key={k} className="text-[11px] flex justify-between bg-slate-950 rounded px-2 py-1">
                <span className="text-slate-500">{k.replace(/_/g, " ")}</span>
                <span className="text-slate-300 tabular-nums">{Number(v).toFixed(1)}</span>
              </div>
            ))}
          </div>
          <div className="text-xs text-slate-500 pt-1">{String(stage.reasoning_summary)}</div>
        </div>
      );
    }
    default:
      return <pre className="text-[11px] text-slate-500 overflow-x-auto">{JSON.stringify(stage, null, 2)}</pre>;
  }
}
