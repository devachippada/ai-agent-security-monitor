import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { ModelPerformance } from "../types";

export default function ModelPerformancePage() {
  const [perf, setPerf] = useState<ModelPerformance | null>(null);

  useEffect(() => {
    api.modelPerformance().then(setPerf);
  }, []);

  if (!perf) return <div className="p-6 text-sm text-slate-500">Loading model performance…</div>;

  const inj = perf.prompt_injection_detector;
  const anom = perf.behavioral_anomaly_detector;

  return (
    <div className="p-6 space-y-6 max-w-5xl">
      <div>
        <h1 className="font-semibold text-lg">Model Performance</h1>
        <p className="text-xs text-slate-500 max-w-2xl">
          Honest, recomputed-on-demand metrics for both detection models used by the gateway. Neither model is presented as more capable than it
          is: the injection detector is a transparent hybrid (rules + local corpus similarity), not a trained neural classifier.
        </p>
      </div>

      <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h2 className="font-semibold text-sm">Prompt-Injection Detector</h2>
        <p className="text-xs text-slate-500">{inj.type}</p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Stat label="Corpus accuracy" value={`${(inj.corpus_evaluation.accuracy * 100).toFixed(1)}%`} />
          <Stat label="Corpus examples" value={inj.corpus_evaluation.n_examples} />
          <Stat label="Benign / Malicious" value={`${inj.corpus_evaluation.n_benign} / ${inj.corpus_evaluation.n_malicious}`} />
          <Stat label="Live predictions logged" value={inj.live_predictions_logged.count} />
        </div>
        <p className="text-[11px] text-slate-600">
          This accuracy is measured against the local labeled corpus (135 rows). For an honest held-out generalization check (novel phrasings not
          in the corpus), see <code className="text-slate-400">backend/tests/test_prompt_injection.py::test_held_out_generalization_accuracy</code>{" "}
          (100% on 20 held-out examples at time of writing).
        </p>
      </section>

      <section className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold text-sm">Behavioral Anomaly Detector (Isolation Forest)</h2>
          <span className={`text-xs px-2 py-1 rounded-full ${anom.model_loaded ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400"}`}>
            {anom.model_loaded ? "Model loaded" : "No model trained"}
          </span>
        </div>
        <p className="text-xs text-slate-500">{anom.type}</p>

        {anom.training_metadata && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Stat label="Training samples" value={String(anom.training_metadata.n_training_samples ?? "-")} />
            <Stat label="Contamination" value={String(anom.training_metadata.contamination ?? "-")} />
            <Stat label="Trained at" value={new Date(String(anom.training_metadata.trained_at)).toLocaleString()} small />
            <Stat label="Model version" value={String(anom.training_metadata.version ?? "-")} />
          </div>
        )}

        {anom.offline_evaluation && (
          <>
            <h3 className="text-xs font-semibold text-slate-400 pt-2">
              Offline evaluation ({anom.offline_evaluation.n_normal_tested + anom.offline_evaluation.n_abnormal_tested} held-out synthetic
              sessions)
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <Stat label="Detection rate (recall)" value={`${(anom.offline_evaluation.detection_rate_recall * 100).toFixed(1)}%`} accent="good" />
              <Stat label="False positive rate" value={`${(anom.offline_evaluation.false_positive_rate * 100).toFixed(1)}%`} accent="warn" />
              <Stat label="Precision" value={`${(anom.offline_evaluation.precision * 100).toFixed(1)}%`} />
              <Stat label="Overall accuracy" value={`${(anom.offline_evaluation.accuracy * 100).toFixed(1)}%`} />
            </div>

            <h3 className="text-xs font-semibold text-slate-400 pt-2">Worked examples (from the project brief)</h3>
            <div className="grid md:grid-cols-2 gap-3">
              <ExampleCard
                label="Normal sequence"
                sequence={anom.offline_evaluation.worked_examples.normal_sequence}
                result={anom.offline_evaluation.worked_examples.normal_result}
              />
              <ExampleCard
                label="Abnormal sequence"
                sequence={anom.offline_evaluation.worked_examples.abnormal_sequence}
                result={anom.offline_evaluation.worked_examples.abnormal_result}
              />
            </div>
          </>
        )}
        {!anom.offline_evaluation && (
          <p className="text-xs text-amber-400">No offline evaluation report found -- run `python evaluate_model.py` in backend/.</p>
        )}
      </section>
    </div>
  );
}

function Stat({ label, value, accent, small }: { label: string; value: React.ReactNode; accent?: "good" | "warn"; small?: boolean }) {
  const color = accent === "good" ? "text-emerald-400" : accent === "warn" ? "text-amber-400" : "text-slate-100";
  return (
    <div className="bg-slate-950 border border-slate-800 rounded-lg p-3">
      <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-1">{label}</div>
      <div className={`font-semibold ${small ? "text-xs" : "text-lg"} ${color}`}>{value}</div>
    </div>
  );
}

function ExampleCard({ label, sequence, result }: { label: string; sequence: string; result: { anomaly_score: number; is_anomalous: boolean } }) {
  return (
    <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-2">
      <div className="text-xs font-semibold text-slate-400">{label}</div>
      <div className="text-[11px] text-slate-500 font-mono leading-relaxed">{sequence}</div>
      <div className="flex items-center gap-2">
        <span className={`text-xs px-2 py-0.5 rounded-full ${result.is_anomalous ? "bg-red-500/15 text-red-400" : "bg-emerald-500/15 text-emerald-400"}`}>
          {result.is_anomalous ? "ANOMALOUS" : "NORMAL"}
        </span>
        <span className="text-xs text-slate-500">score: {result.anomaly_score.toFixed(1)}</span>
      </div>
    </div>
  );
}
