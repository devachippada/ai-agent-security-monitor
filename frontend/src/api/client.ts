import type {
  AlertOut,
  AttackScenario,
  ChatResponse,
  DashboardMetrics,
  EventOut,
  ModelPerformance,
  PolicyOut,
  ScenarioRunResult,
  SessionSummary,
  User,
} from "../types";

const BASE = "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = await resp.json();
      detail = body.detail ?? detail;
    } catch {
      // ignore
    }
    throw new Error(`${resp.status}: ${detail}`);
  }
  return resp.json() as Promise<T>;
}

export const api = {
  listUsers: () => request<User[]>("/users"),

  sendChat: (user_id: string, message: string, session_id?: string) =>
    request<ChatResponse>("/chat", {
      method: "POST",
      body: JSON.stringify({ user_id, message, session_id }),
    }),

  listEvents: (params: { limit?: number; session_id?: string } = {}) => {
    const qs = new URLSearchParams();
    if (params.limit) qs.set("limit", String(params.limit));
    if (params.session_id) qs.set("session_id", params.session_id);
    return request<EventOut[]>(`/events?${qs.toString()}`);
  },

  listAlerts: (params: { resolved?: boolean } = {}) => {
    const qs = new URLSearchParams();
    if (params.resolved !== undefined) qs.set("resolved", String(params.resolved));
    return request<AlertOut[]>(`/alerts?${qs.toString()}`);
  },
  resolveAlert: (alertId: string) => request<AlertOut>(`/alerts/${alertId}/resolve`, { method: "POST" }),

  dashboardMetrics: () => request<DashboardMetrics>("/dashboard/metrics"),

  listPolicies: () => request<PolicyOut[]>("/policies"),
  updatePolicy: (policyId: string, update: Partial<PolicyOut>) =>
    request<PolicyOut>(`/policies/${policyId}`, { method: "PATCH", body: JSON.stringify(update) }),

  listSessions: () => request<SessionSummary[]>("/sessions"),
  getSessionEvents: (sessionId: string) => request<EventOut[]>(`/sessions/${sessionId}/events`),
  getEvent: (eventId: string) => request<EventOut>(`/events/${eventId}`),
  modelPerformance: () => request<ModelPerformance>("/model-performance"),

  listScenarios: () => request<AttackScenario[]>("/attack-scenarios"),
  runScenario: (scenario_id: string, user_id?: string) =>
    request<ScenarioRunResult>("/attack-scenarios/run", {
      method: "POST",
      body: JSON.stringify({ scenario_id, user_id }),
    }),
  runAllScenarios: () =>
    request<{ results: ScenarioRunResult[] }>("/attack-scenarios/run-all", { method: "POST" }),
};
