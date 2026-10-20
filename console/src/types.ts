export type Action = 'ALLOW' | 'CONFIRM' | 'BLOCK';
export type Page = 'overview' | 'sources' | 'alignment' | 'policies' | 'trace' | 'robustness';
export type Json = Record<string, unknown>;
export type TraceSummary = {
  trace_id: string; session_id: string; started_at: string; last_event_at: string;
  event_count: number; goal: string; counts: Partial<Record<Action, number>>; call_count: number;
};
export type TraceNode = { id: string; kind: string; label: string; [key: string]: unknown };
export type TraceEdge = { source: string; target: string; kind: string; certainty: string };
export type TimelineItem = {
  event_id: number; ts: string; type: string; call_id: string | null;
  agent_id?: string | null; source_id: string | null; payload: Json;
};
export type Decision = {
  action: Action; rule_ids: string[]; reason: string; policy_version: string;
  degraded?: boolean; approval_id?: string | null; arguments_hash?: string;
};
export type Call = {
  call_id: string; tool: string; agent_id: string; parent_call_id?: string | null;
  arguments: Json; ts: string; decision: Decision | null;
};
export type Source = {
  source_id: string; type: string; uri: string; trust_level: string; content_hash: string;
  parent_source_id?: string | null; span?: Json | null; labels: string[];
  propagation?: { basis: string; field: string }[];
};
export type Incident = {
  trace_id: string; session_id: string; nodes: TraceNode[]; edges: TraceEdge[];
  timeline: TimelineItem[]; calls: Call[]; sources: Source[];
  impacts: { tool: string; target: string; call_id: string }[];
  mission: { goal?: string; goal_category?: string; allowed_actions?: string[]; version?: number };
  approvals: { approval_id: string; call_id: string; status: string; expires_at: string }[];
  hidden_model_events?: number; graph_error?: string;
};
export type PolicyRule = {
  id: string; priority: number; decision: Action; reason: string; when?: Json;
};
export type Arm = {
  arm: string; attacks: number; successes: number; utility: number; visible: number;
  clean: number; clean_utility: number; files: string[];
};
export type CveCase = {
  id: string; cve: { id: string; title: string; background: string; attack_chain: string[] };
  passed: boolean; calls: { tool: string; arguments: Json; decision: Action;
    reason: string; rule_ids: string[]; executed: boolean; ok: boolean }[];
  evidence: { injection_labels: string[]; dag: { nodes: number; edges: number; impacts: number } };
};
export type CorpusCase = {
  id: string; category: string; attack: boolean; goal: string; tool: string;
  result: { action: Action; rule_ids: string; latency: string } | null;
};
export type Bootstrap = {
  generated_at: string; readonly: boolean;
  database: { name: string; connected: boolean; message: string };
  traces: TraceSummary[];
  summary: {
    sessions: number; calls: number; events: number; sources: number;
    decisions: Partial<Record<Action, number>>; source_types: Record<string, number>;
    activity: { hour: string; total: number; decisions: number }[];
    rules: { id: string; count: number }[];
  };
  policy: { version: string; rules: PolicyRule[]; trusted_domains: string[]; error?: string };
  evaluations: { arms: Arm[]; cves: CveCase[]; cases: CorpusCase[]; scope: string; warnings: string[] };
};
