"use client";

import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { ScanSummary, SEVERITY_META, riskLabel } from "@/lib/audit-types";
import { ShieldAlert, ShieldCheck } from "lucide-react";

export function SummaryCards({ summary }: { summary: ScanSummary }) {
  const risk = riskLabel(summary.risk_score);
  const stats: { key: keyof ScanSummary; sev: keyof typeof SEVERITY_META }[] = [
    { key: "critical", sev: "critical" },
    { key: "high", sev: "high" },
    { key: "medium", sev: "medium" },
    { key: "low", sev: "low" },
    { key: "info", sev: "info" },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {stats.map(({ key, sev }) => {
          const meta = SEVERITY_META[sev as "critical"];
          const value = summary[key] as number;
          if (value === 0 && (key === "info" || key === "low")) return null;
          return (
            <Card key={key} className={`border ${meta.border} ${meta.bg}`}>
              <CardContent className="p-4">
                <div className="flex items-center gap-2">
                  <span className={`h-2 w-2 rounded-full ${meta.dot}`} />
                  <span className="text-xs uppercase tracking-wide text-zinc-400">{meta.label}</span>
                </div>
                <div className={`mt-1 text-2xl font-bold ${meta.text}`}>{value}</div>
              </CardContent>
            </Card>
          );
        })}
        <Card className="border-zinc-800 bg-zinc-900/60">
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              {summary.clean ? (
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
              ) : (
                <ShieldAlert className="h-4 w-4 text-red-400" />
              )}
              <span className="text-xs uppercase tracking-wide text-zinc-400">Risk score</span>
            </div>
            <div className={`mt-1 text-2xl font-bold ${risk.color}`}>{summary.risk_score}</div>
            <Progress
              value={summary.risk_score}
              className="mt-2 h-1.5 bg-zinc-800 [&>div]:bg-gradient-to-r [&>div]:from-amber-500 [&>div]:to-red-500"
            />
            <p className="mt-1 text-xs text-zinc-500">{risk.label}</p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
