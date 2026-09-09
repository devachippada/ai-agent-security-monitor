import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { AttackScenario, ScenarioRunResult } from "../types";
import { ActionBadge, InjectionBadge, RiskScoreBar } from "../components/Badges";

export default function AttackSimulatorPage() {
  const [scenarios, setScenarios] = useState<AttackScenario[]>([]);
  const [results, setResults] = useState<Record<string, ScenarioRunResult>>({});
  const [runningId, setRunningId] = useState<string | null>(null);
  const [runningAll, setRunningAll] = useState(false);

  useEffect(() => {
    api.listScenarios().then(setScenarios);
  }, []);

  async function run(scenarioId: string) {
    setRunningId(scenarioId);
    try {
      const result = await api.runScenario(scenarioId);
      setResults((r) => ({ ...r, [scenarioId]: result }));
    } finally {
      setRunningId(null);
    }
  }

  async function runAll() {
    setRunningAll(true);
    try {
      const { results: all } = await api.runAllScenarios();
      const map: Record<string, ScenarioRunResult> = {};
      for (const r of all) map[r.scenario_id] = r;
      setResults(map);
    } finally {
      setRunningAll(false);
    }
  }

  return (
    <div className="p-6 space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-semibold text-lg">Attack Simulator</h1>
          <p className="text-xs text-slate-500 max-w-2xl">
            Each scenario below sends its prompt(s) through the exact same /api/chat → security gateway pipeline a real user hits. Nothing is
            special-cased for the demo: running a scenario twice reproduces the same detection result.
          </p>
        </div>
        <button
          onClick={runAll}
          disabled={runningAll}
          className="px-4 py-2 rounded-lg bg-red-600/80 hover:bg-red-600 disabled:opacity-40 text-sm font-medium transition-colors shrink-0"
        >
          {runningAll ? "Running all…" : "Run all scenarios"}
        </button>
      </div>

      <div className="space-y-4">
        {scenarios.map((s) => (
          <ScenarioCard key={s.scenario_id} scenario={s} result={results[s.scenario_id]} onRun={() => run(s.scenario_id)} running={runningId === s.scenario_id} />
        ))}
      </div>
    </div>
  );
}

function ScenarioCard({
  scenario,
  result,
  onRun,
  running,
}: {
  scenario: AttackScenario;
  result?: ScenarioRunResult;
  onRun: () => void;
  running: boolean;
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] uppercase tracking-wide px-2 py-0.5 rounded-full bg-slate-800 text-slate-400">{scenario.category}</span>
            <h3 className="font-semibold text-sm">{scenario.name}</h3>
          </div>
          <p className="text-xs text-slate-400 max-w-2xl">{scenario.description}</p>
          <p className="text-xs text-slate-600 mt-1 max-w-2xl italic">Expected: {scenario.expected_outcome}</p>
        </div>
        <button
          onClick={onRun}
          disabled={running}
          className="shrink-0 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-xs font-medium transition-colors"
        >
          {running ? "Running…" : "Run scenario"}
        </button>
      </div>

      {result && (
        <div className="mt-4 pt-4 border-t border-slate-800 space-y-3">
          {result.turns.map((t, i) => (
            <div key={i} className="bg-slate-950 border border-slate-800 rounded-lg p-3 space-y-2">
              <p className="text-xs text-slate-300 font-mono">"{t.prompt}"</p>
              <div className="flex items-center gap-2 flex-wrap">
                <ActionBadge action={t.action} />
                <InjectionBadge classification={t.injection_classification} />
                {t.tool_name && <span className="text-[11px] text-slate-500">tool: {t.tool_name}</span>}
              </div>
              <RiskScoreBar score={t.risk_score} level={t.risk_level} />
              <p className="text-xs text-slate-500">{t.reasoning_summary}</p>
            </div>
          ))}
          <div className={`text-xs font-medium ${result.any_blocked ? "text-emerald-400" : "text-amber-400"}`}>
            {result.any_blocked
              ? "✓ Malicious action(s) were blocked before execution."
              : result.any_approval_required
                ? "⚠ Held for human approval rather than blocked outright."
                : "This scenario's requests were allowed through -- inspect the reasoning above."}
          </div>
        </div>
      )}
    </div>
  );
}
