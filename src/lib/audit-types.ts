/** Type mirrors of the Python engine's report models (pydantic -> JSON). */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "high" | "medium" | "low";

export interface Remediation {
  steps: string[];
  before?: string | null;
  after?: string | null;
  verification?: string | null;
}

export interface Finding {
  id: string;
  rule_id: string;
  severity: Severity;
  category: string;
  title: string;
  file: string;
  line: number;
  end_line: number;
  evidence: string;
  description: string;
  impact: string;
  quick_fix: string;
  remediation?: Remediation | null;
  references: string[];
  cwe?: string | null;
  owasp: string[];
  confidence: Confidence;
  tool_source: string;
  fingerprint: string;
  auto_fixable: boolean;
  llm_detail?: string | null;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  risk_score: number;
  clean: boolean;
}

export interface ScanMetadata {
  started_at: string;
  duration_seconds: number;
  checks: string[];
  files_scanned: number;
  lines_scanned: number;
  languages: Record<string, number>;
  tool_version: string;
  llm_enriched: boolean;
  llm_note: string;
}

export interface AuditReport {
  tool: string;
  version: string;
  project_path: string;
  project_name: string;
  metadata: ScanMetadata;
  summary: ScanSummary;
  findings: Finding[];
}

export interface HistoryEntry {
  file: string;
  project_name: string;
  started_at: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  risk_score: number;
}

export interface EngineInfo {
  ok: boolean;
  version: string;
  checks: string[];
  rules_count: number;
  llm_available: boolean;
  demo_path: string;
  demo_available: boolean;
  python?: string;
  note?: string;
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_META: Record<
  Severity,
  { label: string; dot: string; text: string; bg: string; border: string; solid: string }
> = {
  critical: {
    label: "Critical",
    dot: "bg-red-500",
    text: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/60",
    solid: "bg-red-500",
  },
  high: {
    label: "High",
    dot: "bg-orange-500",
    text: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/60",
    solid: "bg-orange-500",
  },
  medium: {
    label: "Medium",
    dot: "bg-amber-400",
    text: "text-amber-300",
    bg: "bg-amber-400/10",
    border: "border-amber-400/60",
    solid: "bg-amber-400",
  },
  low: {
    label: "Low",
    dot: "bg-cyan-400",
    text: "text-cyan-300",
    bg: "bg-cyan-400/10",
    border: "border-cyan-400/60",
    solid: "bg-cyan-400",
  },
  info: {
    label: "Info",
    dot: "bg-zinc-400",
    text: "text-zinc-300",
    bg: "bg-zinc-400/10",
    border: "border-zinc-400/60",
    solid: "bg-zinc-400",
  },
};

export function riskLabel(score: number): { label: string; color: string } {
  if (score >= 60) return { label: "High risk", color: "text-red-400" };
  if (score >= 30) return { label: "Medium risk", color: "text-orange-400" };
  if (score >= 10) return { label: "Low risk", color: "text-amber-300" };
  return { label: "Minimal risk", color: "text-emerald-400" };
}
