"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Finding, SEVERITY_META } from "@/lib/audit-types";
import {
  ChevronDown,
  ExternalLink,
  FileCode2,
  ShieldCheck,
  Sparkles,
  Terminal,
  Wrench,
} from "lucide-react";

export function FindingCard({ finding, defaultOpen = false }: { finding: Finding; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const meta = SEVERITY_META[finding.severity];
  const rem = finding.remediation;

  return (
    <div className={`overflow-hidden rounded-lg border-l-4 ${meta.border} border border-zinc-800 bg-zinc-900/60`}>
      <Collapsible open={open} onOpenChange={setOpen}>
        <CollapsibleTrigger asChild>
          <button className="flex w-full items-start gap-3 p-4 text-left hover:bg-zinc-900">
            <span className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${meta.dot}`} aria-hidden />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className={`border ${meta.border} ${meta.text} font-mono`}>
                  {finding.id}
                </Badge>
                <span className="font-medium text-zinc-100">{finding.title}</span>
                <Badge variant="outline" className="border-zinc-700 text-zinc-400 capitalize">
                  {finding.category}
                </Badge>
                {finding.auto_fixable && (
                  <Badge variant="outline" className="border-emerald-500/40 text-emerald-400">
                    auto-fixable
                  </Badge>
                )}
              </div>
              <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-zinc-500">
                <span className="font-mono">
                  {finding.file}:{finding.line}
                </span>
                {finding.cwe && <span>{finding.cwe}</span>}
                {finding.confidence !== "high" && (
                  <span className="text-amber-500/80">confidence: {finding.confidence}</span>
                )}
                <span>{finding.tool_source}</span>
              </div>
            </div>
            <ChevronDown
              className={`mt-1 h-4 w-4 shrink-0 text-zinc-500 transition-transform ${open ? "rotate-180" : ""}`}
            />
          </button>
        </CollapsibleTrigger>

        <CollapsibleContent>
          <div className="space-y-4 border-t border-zinc-800 p-4">
            {finding.evidence && (
              <div>
                <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-zinc-500">Evidence</p>
                <pre className="overflow-x-auto rounded-md border border-red-900/40 bg-red-950/30 p-3 font-mono text-xs text-zinc-200">
                  {finding.evidence}
                </pre>
              </div>
            )}

            {finding.description && (
              <div>
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-zinc-500">
                  Why this is a problem
                </p>
                <p className="text-sm leading-relaxed text-zinc-300">{finding.description}</p>
              </div>
            )}

            {finding.impact && (
              <div>
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-zinc-500">Impact</p>
                <p className="text-sm leading-relaxed text-zinc-300">{finding.impact}</p>
              </div>
            )}

            {finding.quick_fix && (
              <div className="flex items-start gap-2 rounded-md border border-emerald-800/50 bg-emerald-950/30 p-3">
                <Wrench className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
                <p className="text-sm text-emerald-200">{finding.quick_fix}</p>
              </div>
            )}

            {rem && rem.steps.length > 0 && (
              <div>
                <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-zinc-500">
                  Remediation steps
                </p>
                <ol className="space-y-2">
                  {rem.steps.map((step, i) => (
                    <li key={i} className="flex gap-2.5 text-sm text-zinc-300">
                      <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-zinc-800 text-xs font-mono text-zinc-400">
                        {i + 1}
                      </span>
                      <span className="leading-relaxed">{step}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}

            {(rem?.before || rem?.after) && (
              <div className="grid gap-3 md:grid-cols-2">
                {rem?.before && (
                  <div>
                    <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-red-400">Before</p>
                    <pre className="overflow-x-auto rounded-md border border-red-900/40 bg-zinc-950 p-3 font-mono text-xs text-zinc-300">
                      {rem.before}
                    </pre>
                  </div>
                )}
                {rem?.after && (
                  <div>
                    <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-emerald-400">After</p>
                    <pre className="overflow-x-auto rounded-md border border-emerald-900/40 bg-zinc-950 p-3 font-mono text-xs text-zinc-300">
                      {rem.after}
                    </pre>
                  </div>
                )}
              </div>
            )}

            {rem?.verification && (
              <div className="flex items-start gap-2 rounded-md border border-cyan-900/50 bg-cyan-950/20 p-3">
                <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" />
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wide text-cyan-400">Verify the fix</p>
                  <p className="mt-0.5 text-sm text-cyan-100/90">{rem.verification}</p>
                </div>
              </div>
            )}

            {finding.llm_detail && (
              <div className="rounded-md border border-fuchsia-900/40 bg-fuchsia-950/10 p-3">
                <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-fuchsia-300">
                  <Sparkles className="h-3.5 w-3.5" />
                  AI-generated guidance (review before applying)
                </p>
                <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed text-zinc-300">
                  {finding.llm_detail}
                </pre>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-zinc-800 pt-3">
              {finding.references.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {finding.references.slice(0, 3).map((ref) => (
                    <a
                      key={ref}
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 hover:underline"
                    >
                      <ExternalLink className="h-3 w-3" />
                      {ref.replace(/^https?:\/\//, "").slice(0, 48)}
                    </a>
                  ))}
                </div>
              ) : (
                <span />
              )}
              {finding.auto_fixable && (
                <code className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs text-zinc-400">
                  <Terminal className="h-3 w-3" />
                  audit fix --finding {finding.id} ./project
                </code>
              )}
            </div>
          </div>
        </CollapsibleContent>
      </Collapsible>
    </div>
  );
}

export function FindingCardSkeleton() {
  return (
    <div className="h-24 animate-pulse rounded-lg border border-zinc-800 bg-zinc-900/40" />
  );
}

export function FindingsEmptyState({ filterActive }: { filterActive: boolean }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-zinc-800 bg-zinc-900/40 py-16 text-center">
      <FileCode2 className="h-8 w-8 text-zinc-600" />
      <p className="text-sm text-zinc-400">
        {filterActive ? "No findings match the current filters." : "No findings at this severity."}
      </p>
    </div>
  );
}

export { Button };
