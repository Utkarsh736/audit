"use client";

import { useMemo, useState } from "react";
import { Input } from "@/components/ui/input";
import { Finding, ScanSummary, SEVERITY_META, SEVERITY_ORDER, Severity } from "@/lib/audit-types";
import { FindingCard, FindingsEmptyState } from "./finding-card";
import { Search } from "lucide-react";

interface ResultsViewProps {
  report: {
    project_name: string;
    project_path: string;
    metadata: {
      started_at: string;
      duration_seconds: number;
      checks: string[];
      files_scanned: number;
      lines_scanned: number;
      languages: Record<string, number>;
      llm_note: string;
    };
    summary: ScanSummary;
    findings: Finding[];
  };
}

export function ResultsView({ report }: ResultsViewProps) {
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [query, setQuery] = useState("");

  const categories = useMemo(
    () => Array.from(new Set(report.findings.map((f) => f.category))).sort(),
    [report.findings]
  );

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: report.findings.length };
    for (const f of report.findings) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }, [report.findings]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return report.findings.filter((f) => {
      if (severityFilter !== "all" && f.severity !== severityFilter) return false;
      if (categoryFilter !== "all" && f.category !== categoryFilter) return false;
      if (
        q &&
        !`${f.title} ${f.file} ${f.id} ${f.category} ${f.evidence}`.toLowerCase().includes(q)
      )
        return false;
      return true;
    });
  }, [report.findings, severityFilter, categoryFilter, query]);

  const langEntries = Object.entries(report.metadata.languages || {}).slice(0, 6);

  return (
    <div className="space-y-4">
      {/* project header */}
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <div>
          <h2 className="text-lg font-semibold text-zinc-100">
            {report.project_name || "project"}
          </h2>
          <p className="font-mono text-xs text-zinc-500">{report.project_path}</p>
        </div>
        <p className="text-xs text-zinc-500">
          {report.metadata.files_scanned} files · {report.metadata.lines_scanned.toLocaleString()} lines ·{" "}
          {report.metadata.duration_seconds}s
          {langEntries.length > 0 && (
            <span className="ml-2 text-zinc-600">
              ({langEntries.map(([lang, n]) => `${lang}×${n}`).join(", ")})
            </span>
          )}
        </p>
      </div>
      {report.metadata.llm_note && (
        <p className="text-xs italic text-zinc-500">{report.metadata.llm_note}</p>
      )}

      {/* filters */}
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <FilterChip
            active={severityFilter === "all"}
            onClick={() => setSeverityFilter("all")}
            label={`All ${counts.all || 0}`}
          />
          {SEVERITY_ORDER.filter((sev) => counts[sev]).map((sev) => {
            const meta = SEVERITY_META[sev];
            return (
              <FilterChip
                key={sev}
                active={severityFilter === sev}
                onClick={() => setSeverityFilter(sev)}
                label={`${meta.label} ${counts[sev]}`}
                dot={meta.dot}
                activeClass={meta.text}
              />
            );
          })}
          {categories.length > 1 && (
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="ml-auto rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-xs text-zinc-300 outline-none focus:border-zinc-500"
              aria-label="Filter by category"
            >
              <option value="all">All categories</option>
              {categories.map((c) => (
                <option key={c} value={c} className="capitalize">
                  {c}
                </option>
              ))}
            </select>
          )}
        </div>
        <div className="relative max-w-sm">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search findings, files, evidence…"
            className="h-9 border-zinc-800 bg-zinc-900 pl-8 text-sm"
          />
        </div>
      </div>

      {/* findings list */}
      <div className="space-y-3">
        {filtered.length === 0 ? (
          <FindingsEmptyState filterActive={severityFilter !== "all" || categoryFilter !== "all" || !!query} />
        ) : (
          filtered.map((f, i) => <FindingCard key={f.id + f.fingerprint} finding={f} defaultOpen={i === 0} />)
        )}
      </div>
    </div>
  );
}

function FilterChip({
  active,
  onClick,
  label,
  dot,
  activeClass,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  dot?: string;
  activeClass?: string;
}) {
  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs transition-colors ${
        active
          ? `border-zinc-600 bg-zinc-800 ${activeClass || "text-zinc-100"}`
          : "border-zinc-800 bg-transparent text-zinc-500 hover:text-zinc-300"
      }`}
      aria-pressed={active}
    >
      {dot && <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />}
      {label}
    </button>
  );
}
