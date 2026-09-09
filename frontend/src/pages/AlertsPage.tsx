import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { AlertOut } from "../types";
import { RiskBadge } from "../components/Badges";

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<AlertOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [showResolved, setShowResolved] = useState(false);

  async function load() {
    const data = await api.listAlerts(showResolved ? {} : { resolved: false });
    setAlerts(data);
    setLoading(false);
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showResolved]);

  async function resolve(alertId: string) {
    await api.resolveAlert(alertId);
    load();
  }

  return (
    <div className="p-6 space-y-4 max-w-4xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-semibold text-lg">Alerts</h1>
          <p className="text-xs text-slate-500">Raised automatically for any blocked, approval-required, or HIGH/CRITICAL-risk event.</p>
        </div>
        <label className="flex items-center gap-2 text-xs text-slate-400">
          <input type="checkbox" checked={showResolved} onChange={(e) => setShowResolved(e.target.checked)} />
          Show resolved
        </label>
      </div>

      {loading ? (
        <div className="text-sm text-slate-500">Loading…</div>
      ) : alerts.length === 0 ? (
        <div className="text-sm text-slate-500">No {showResolved ? "" : "unresolved "}alerts.</div>
      ) : (
        <div className="space-y-2">
          {alerts.map((a) => (
            <div key={a.alert_id} className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex items-start gap-3">
              <RiskBadge level={a.severity} />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium">{a.title}</div>
                <div className="text-xs text-slate-500 mt-1">{a.description}</div>
                <div className="text-[11px] text-slate-600 mt-1">{new Date(a.created_at).toLocaleString()}</div>
              </div>
              {!a.resolved && (
                <button
                  onClick={() => resolve(a.alert_id)}
                  className="shrink-0 text-xs px-3 py-1.5 rounded-lg border border-slate-700 hover:border-emerald-600 hover:text-emerald-400 transition-colors"
                >
                  Resolve
                </button>
              )}
              {a.resolved && <span className="text-[11px] text-emerald-500 shrink-0">Resolved</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
