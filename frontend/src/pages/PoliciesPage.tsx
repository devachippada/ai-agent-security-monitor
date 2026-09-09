import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { PolicyOut } from "../types";
import { RiskBadge } from "../components/Badges";

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<PolicyOut[]>([]);
  const [loading, setLoading] = useState(true);

  async function load() {
    const data = await api.listPolicies();
    setPolicies(data);
    setLoading(false);
  }

  useEffect(() => {
    load();
  }, []);

  async function toggleApproval(p: PolicyOut) {
    const updated = await api.updatePolicy(p.policy_id, { requires_approval: !p.requires_approval });
    setPolicies((ps) => ps.map((x) => (x.policy_id === p.policy_id ? updated : x)));
  }

  async function toggleEnabled(p: PolicyOut) {
    const updated = await api.updatePolicy(p.policy_id, { enabled: !p.enabled });
    setPolicies((ps) => ps.map((x) => (x.policy_id === p.policy_id ? updated : x)));
  }

  async function updateMaxCalls(p: PolicyOut, value: string) {
    const n = value === "" ? null : parseInt(value, 10);
    const updated = await api.updatePolicy(p.policy_id, { max_calls_per_session: n ?? undefined });
    setPolicies((ps) => ps.map((x) => (x.policy_id === p.policy_id ? updated : x)));
  }

  return (
    <div className="p-6 space-y-4 max-w-5xl">
      <div>
        <h1 className="font-semibold text-lg">Policy Management</h1>
        <p className="text-xs text-slate-500">
          Declarative per-tool policy enforced by the Tool Authorization & Policy Engine, independent of the continuous risk score.
        </p>
      </div>

      {loading ? (
        <div className="text-sm text-slate-500">Loading…</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs border-separate border-spacing-y-2">
            <thead>
              <tr className="text-left text-slate-500">
                <th className="px-3 py-1">Tool</th>
                <th className="px-3 py-1">Risk level</th>
                <th className="px-3 py-1">Allowed roles</th>
                <th className="px-3 py-1">Requires approval</th>
                <th className="px-3 py-1">Max calls / session</th>
                <th className="px-3 py-1">Enabled</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.policy_id} className="bg-slate-900 border border-slate-800">
                  <td className="px-3 py-2.5 font-mono rounded-l-lg">{p.tool_name}</td>
                  <td className="px-3 py-2.5">
                    <RiskBadge level={p.risk_level} />
                  </td>
                  <td className="px-3 py-2.5 text-slate-400">{JSON.parse(p.allowed_roles).join(", ")}</td>
                  <td className="px-3 py-2.5">
                    <input type="checkbox" checked={p.requires_approval} onChange={() => toggleApproval(p)} />
                  </td>
                  <td className="px-3 py-2.5">
                    <input
                      type="number"
                      min={1}
                      defaultValue={p.max_calls_per_session ?? ""}
                      placeholder="unlimited"
                      onBlur={(e) => updateMaxCalls(p, e.target.value)}
                      className="w-24 bg-slate-950 border border-slate-700 rounded px-2 py-1"
                    />
                  </td>
                  <td className="px-3 py-2.5 rounded-r-lg">
                    <input type="checkbox" checked={p.enabled} onChange={() => toggleEnabled(p)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
