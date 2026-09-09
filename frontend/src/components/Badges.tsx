import type { ActionType, InjectionClass, RiskLevel } from "../types";

const RISK_STYLES: Record<RiskLevel, string> = {
  LOW: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  MEDIUM: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  HIGH: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  CRITICAL: "bg-red-500/15 text-red-400 border-red-500/30",
};

export function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${RISK_STYLES[level] ?? RISK_STYLES.LOW}`}>
      {level}
    </span>
  );
}

const ACTION_STYLES: Record<ActionType, string> = {
  ALLOWED: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  BLOCKED: "bg-red-500/15 text-red-400 border-red-500/30",
  APPROVAL_REQUIRED: "bg-amber-500/15 text-amber-400 border-amber-500/30",
};

export function ActionBadge({ action }: { action: ActionType }) {
  const label = action === "APPROVAL_REQUIRED" ? "APPROVAL REQUIRED" : action;
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${ACTION_STYLES[action] ?? ""}`}>
      {label}
    </span>
  );
}

const INJECTION_STYLES: Record<InjectionClass, string> = {
  SAFE: "bg-slate-500/15 text-slate-300 border-slate-500/30",
  SUSPICIOUS: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  MALICIOUS: "bg-red-500/15 text-red-400 border-red-500/30",
};

export function InjectionBadge({ classification }: { classification: InjectionClass }) {
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${INJECTION_STYLES[classification] ?? INJECTION_STYLES.SAFE}`}>
      {classification}
    </span>
  );
}

export function RiskScoreBar({ score, level }: { score: number; level: RiskLevel }) {
  const barColor =
    level === "CRITICAL" ? "bg-red-500" : level === "HIGH" ? "bg-orange-500" : level === "MEDIUM" ? "bg-amber-500" : "bg-emerald-500";
  return (
    <div className="flex items-center gap-2 w-full">
      <div className="h-2 flex-1 rounded-full bg-slate-800 overflow-hidden">
        <div className={`h-full ${barColor} transition-all`} style={{ width: `${Math.min(100, score)}%` }} />
      </div>
      <span className="text-xs tabular-nums text-slate-400 w-10 text-right">{score.toFixed(0)}</span>
    </div>
  );
}
