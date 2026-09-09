import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../api/client";
import type { DashboardMetrics } from "../types";

const RISK_COLORS: Record<string, string> = {
  LOW: "#34d399",
  MEDIUM: "#fbbf24",
  HIGH: "#fb923c",
  CRITICAL: "#f87171",
};
const ACTION_COLORS: Record<string, string> = {
  ALLOWED: "#34d399",
  BLOCKED: "#f87171",
  APPROVAL_REQUIRED: "#fbbf24",
};
const INJ_COLORS: Record<string, string> = {
  SAFE: "#64748b",
  SUSPICIOUS: "#fbbf24",
  MALICIOUS: "#f87171",
};

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    const m = await api.dashboardMetrics();
    setMetrics(m);
    setLoading(false);
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading || !metrics) {
    return <div className="p-6 text-sm text-slate-500">Loading live metrics from the database…</div>;
  }

  const toChartData = (obj: Record<string, number>) => Object.entries(obj).map(([name, value]) => ({ name, value }));

  return (
    <div className="p-6 space-y-6 max-w-7xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-semibold text-lg">Security Dashboard</h1>
          <p className="text-xs text-slate-500">Live metrics computed directly from the SQLite events/alerts tables. Refreshes every 5s.</p>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total events" value={metrics.total_events} />
        <StatCard label="Total sessions" value={metrics.total_sessions} />
        <StatCard label="Blocked rate" value={`${metrics.blocked_rate_pct.toFixed(1)}%`} />
        <StatCard label="Unresolved alerts" value={metrics.unresolved_alerts} accent="amber" />
        <StatCard label="Avg risk score" value={metrics.avg_risk_score.toFixed(1)} />
        <StatCard label="Avg latency" value={`${metrics.avg_latency_ms.toFixed(1)} ms`} />
        <StatCard label="P50 / P95 latency" value={`${(metrics.p50_latency_ms ?? 0).toFixed(1)} / ${(metrics.p95_latency_ms ?? 0).toFixed(1)} ms`} />
        <StatCard label="Max latency" value={`${metrics.max_latency_ms.toFixed(1)} ms`} />
        <StatCard label="Model predictions logged" value={metrics.total_model_predictions} />
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        <ChartCard title="Actions taken">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={toChartData(metrics.action_breakdown)} dataKey="value" nameKey="name" innerRadius={45} outerRadius={75} paddingAngle={3}>
                {toChartData(metrics.action_breakdown).map((entry) => (
                  <Cell key={entry.name} fill={ACTION_COLORS[entry.name] ?? "#64748b"} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Risk level distribution">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie data={toChartData(metrics.risk_level_breakdown)} dataKey="value" nameKey="name" innerRadius={45} outerRadius={75} paddingAngle={3}>
                {toChartData(metrics.risk_level_breakdown).map((entry) => (
                  <Cell key={entry.name} fill={RISK_COLORS[entry.name] ?? "#64748b"} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Prompt-injection classification">
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={toChartData(metrics.injection_classification_breakdown)}
                dataKey="value"
                nameKey="name"
                innerRadius={45}
                outerRadius={75}
                paddingAngle={3}
              >
                {toChartData(metrics.injection_classification_breakdown).map((entry) => (
                  <Cell key={entry.name} fill={INJ_COLORS[entry.name] ?? "#64748b"} />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
            </PieChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <ChartCard title="Detection types triggered">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={toChartData(metrics.detection_type_counts)} layout="vertical" margin={{ left: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
              <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
              <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={11} width={150} />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="value" fill="#22d3ee" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard title="Tool usage">
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={toChartData(metrics.tool_usage_counts)} layout="vertical" margin={{ left: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
              <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
              <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={11} width={150} />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="value" fill="#818cf8" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      <ChartCard title="Events over the last 24 hours">
        {metrics.timeline_last_24h.length === 0 ? (
          <div className="text-xs text-slate-500 py-8 text-center">No events in the last 24 hours yet.</div>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={metrics.timeline_last_24h}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="bucket" stroke="#64748b" fontSize={10} />
              <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
              <Tooltip contentStyle={tooltipStyle} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Line type="monotone" dataKey="total" stroke="#22d3ee" name="Total events" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="blocked" stroke="#f87171" name="Blocked" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="approval_required" stroke="#fbbf24" name="Approval required" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </ChartCard>
    </div>
  );
}

const tooltipStyle = { backgroundColor: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, fontSize: 12 };

function StatCard({ label, value, accent }: { label: string; value: React.ReactNode; accent?: "amber" }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">{label}</div>
      <div className={`text-2xl font-semibold ${accent === "amber" && Number(value) > 0 ? "text-amber-400" : "text-slate-100"}`}>{value}</div>
    </div>
  );
}

function ChartCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <h3 className="text-xs font-semibold text-slate-400 mb-2">{title}</h3>
      {children}
    </div>
  );
}
