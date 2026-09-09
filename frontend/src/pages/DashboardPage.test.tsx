import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import DashboardPage from "./DashboardPage";
import { api } from "../api/client";

vi.mock("../api/client", () => ({
  api: {
    dashboardMetrics: vi.fn(),
  },
}));

const mockedApi = vi.mocked(api);

beforeEach(() => {
  vi.clearAllMocks();
});

describe("DashboardPage", () => {
  it("renders real metrics returned by the API, not placeholder data", async () => {
    mockedApi.dashboardMetrics.mockResolvedValue({
      total_events: 42,
      total_sessions: 7,
      total_alerts: 5,
      unresolved_alerts: 3,
      total_model_predictions: 99,
      action_breakdown: { ALLOWED: 30, BLOCKED: 10, APPROVAL_REQUIRED: 2 },
      risk_level_breakdown: { LOW: 20, MEDIUM: 10, HIGH: 5, CRITICAL: 7 },
      injection_classification_breakdown: { SAFE: 30, SUSPICIOUS: 5, MALICIOUS: 7 },
      detection_type_counts: { prompt_injection: 7 },
      tool_usage_counts: { get_account_balance: 10 },
      alerts_by_severity: { CRITICAL: 3, HIGH: 2 },
      avg_risk_score: 24.5,
      avg_latency_ms: 3.2,
      max_latency_ms: 18.1,
      p50_latency_ms: 2.8,
      p95_latency_ms: 12.4,
      blocked_rate_pct: 23.8,
      timeline_last_24h: [],
    });

    render(<DashboardPage />);

    expect(await screen.findByText("42")).toBeInTheDocument(); // total events
    expect(screen.getByText("7")).toBeInTheDocument(); // total sessions
    expect(screen.getByText("23.8%")).toBeInTheDocument(); // blocked rate
    expect(screen.getByText("24.5")).toBeInTheDocument(); // avg risk score

    await waitFor(() => expect(mockedApi.dashboardMetrics).toHaveBeenCalledTimes(1));
  });

  it("shows a loading state before metrics arrive", () => {
    mockedApi.dashboardMetrics.mockReturnValue(new Promise(() => {}));
    render(<DashboardPage />);
    expect(screen.getByText(/Loading live metrics/)).toBeInTheDocument();
  });
});
