export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type ActionType = "ALLOWED" | "BLOCKED" | "APPROVAL_REQUIRED";
export type InjectionClass = "SAFE" | "SUSPICIOUS" | "MALICIOUS";

export interface User {
  user_id: string;
  customer_id: string;
  name: string;
  email: string;
  role: string;
}

export interface SignalScore {
  name: string;
  score: number;
  triggered: boolean;
  reason: string | null;
}

export interface SecurityEvaluation {
  risk_score: number;
  risk_level: RiskLevel;
  action: ActionType;
  blocked: boolean;
  injection_score: number;
  injection_classification: InjectionClass;
  injection_reasons: string[];
  injection_signals: SignalScore[];
  sensitive_data_findings: string[];
  exfiltration_findings: string[];
  policy_findings: string[];
  anomaly_score: number | null;
  anomaly_explanation: string | null;
  detection_types: string[];
  reasoning_summary: string;
}

export interface ChatResponse {
  event_id: string;
  session_id: string;
  reply: string;
  tool_name: string | null;
  tool_result: unknown;
  security: SecurityEvaluation;
  latency_ms: number;
}

export interface ChatTurn {
  id: string;
  role: "user" | "agent";
  text: string;
  security?: SecurityEvaluation;
  toolName?: string | null;
  toolResult?: unknown;
}

export interface EventOut {
  event_id: string;
  timestamp: string;
  session_id: string | null;
  user_id: string | null;
  agent_id: string | null;
  event_type: string | null;
  prompt: string | null;
  tool_name: string | null;
  tool_arguments: string | null;
  api_endpoint: string | null;
  response: string | null;
  risk_score: number;
  risk_level: RiskLevel;
  detection_reason: string | null;
  detection_type: string | null;
  action: ActionType;
  blocked: boolean;
  latency_ms: number;
  injection_classification: InjectionClass | null;
  injection_score: number | null;
  anomaly_score: number | null;
  trace: string | null;
}

export interface TraceStage {
  stage: string;
  [key: string]: unknown;
}

export interface SessionSummary {
  session_id: string;
  user_id: string | null;
  last_event_at: string;
  label: string | null;
}

export interface ModelPerformance {
  prompt_injection_detector: {
    type: string;
    corpus_evaluation: { n_examples: number; accuracy: number; n_benign: number; n_malicious: number };
    live_predictions_logged: { count: number; labels: Record<string, number> };
  };
  behavioral_anomaly_detector: {
    type: string;
    model_loaded: boolean;
    training_metadata: Record<string, unknown> | null;
    offline_evaluation: {
      evaluated_at: string;
      n_normal_tested: number;
      n_abnormal_tested: number;
      false_positive_rate: number;
      detection_rate_recall: number;
      precision: number;
      accuracy: number;
      confusion_matrix: { true_positives: number; false_positives: number; true_negatives: number; false_negatives: number };
      worked_examples: {
        normal_sequence: string;
        normal_result: { anomaly_score: number; is_anomalous: boolean };
        abnormal_sequence: string;
        abnormal_result: { anomaly_score: number; is_anomalous: boolean };
      };
    } | null;
    live_predictions_logged: { count: number; labels: Record<string, number> };
  };
}

export interface AlertOut {
  alert_id: string;
  event_id: string | null;
  severity: RiskLevel;
  title: string;
  description: string | null;
  created_at: string;
  resolved: boolean;
}

export interface PolicyOut {
  policy_id: string;
  tool_name: string;
  risk_level: RiskLevel;
  allowed_roles: string;
  requires_approval: boolean;
  max_calls_per_session: number | null;
  block_threshold: number;
  description: string | null;
  enabled: boolean;
}

export interface AttackScenario {
  scenario_id: string;
  name: string;
  category: string;
  description: string;
  expected_outcome: string;
  prompts: string[];
}

export interface ScenarioTurnResult {
  prompt: string;
  event_id: string;
  tool_name: string | null;
  reply: string;
  risk_score: number;
  risk_level: RiskLevel;
  action: ActionType;
  blocked: boolean;
  detection_types: string[];
  reasoning_summary: string;
  injection_classification: InjectionClass;
  injection_score: number;
}

export interface ScenarioRunResult {
  scenario_id: string;
  name: string;
  expected_outcome: string;
  session_id: string;
  turns: ScenarioTurnResult[];
  any_blocked: boolean;
  any_approval_required: boolean;
}

export interface DashboardMetrics {
  total_events: number;
  total_sessions: number;
  total_alerts: number;
  unresolved_alerts: number;
  total_model_predictions: number;
  action_breakdown: Record<string, number>;
  risk_level_breakdown: Record<string, number>;
  injection_classification_breakdown: Record<string, number>;
  detection_type_counts: Record<string, number>;
  tool_usage_counts: Record<string, number>;
  alerts_by_severity: Record<string, number>;
  avg_risk_score: number;
  avg_latency_ms: number;
  max_latency_ms: number;
  blocked_rate_pct: number;
  timeline_last_24h: { bucket: string; total: number; blocked: number; approval_required: number }[];
  p50_latency_ms?: number;
  p95_latency_ms?: number;
}
