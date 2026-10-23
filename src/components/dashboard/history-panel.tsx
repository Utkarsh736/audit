"use client";

import { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { HistoryEntry, riskLabel } from "@/lib/audit-types";
import { History, Loader2, RefreshCw, FolderOpen } from "lucide-react";

interface HistoryPanelProps {
  onOpenReport: (file: string) => void;
}

export function HistoryPanel({ onOpenReport }: HistoryPanelProps) {
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [opening, setOpening] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/history");
      const data = await res.json();
      setEntries(data.entries || []);
    } catch {
      setEntries([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const open = async (file: string) => {
    setOpening(file);
    try {
      await onOpenReport(file);
    } finally {
      setOpening(null);
    }
  };

  return (
    <Card className="border-zinc-800 bg-zinc-900/60">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-lg">
            <History className="h-4 w-4 text-emerald-400" />
            Scan history
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={load}
            disabled={loading}
            className="h-8 text-zinc-400 hover:text-zinc-100"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            <span className="sr-only">Refresh history</span>
          </Button>
        </div>
        <CardDescription>
          Past audits from the shared <span className="font-mono">~/.auditor/history</span> store — the
          same records your CLI writes, so terminal and dashboard stay in sync.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {entries === null ? (
          <div className="space-y-2">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-12 animate-pulse rounded-md bg-zinc-800/50" />
            ))}
          </div>
        ) : entries.length === 0 ? (
          <p className="py-8 text-center text-sm text-zinc-500">
            No scans yet. Run your first audit from the Scanner tab.
          </p>
        ) : (
          <div className="max-h-[28rem] space-y-2 overflow-y-auto pr-1">
            {entries.map((e) => {
              const risk = riskLabel(e.risk_score);
              return (
                <div
                  key={e.file}
                  className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 rounded-lg border border-zinc-800 bg-zinc-950/40 p-3"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-zinc-200">{e.project_name}</p>
                    <p className="text-xs text-zinc-500">
                      {e.started_at ? new Date(e.started_at).toLocaleString() : "—"}
                    </p>
                  </div>
                  <div className="flex items-center gap-3 text-xs">
                    <span className="flex items-center gap-1.5" title="critical">
                      <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                      <span className="text-zinc-400">{e.critical}</span>
                    </span>
                    <span className="flex items-center gap-1.5" title="high">
                      <span className="h-1.5 w-1.5 rounded-full bg-orange-500" />
                      <span className="text-zinc-400">{e.high}</span>
                    </span>
                    <span className="flex items-center gap-1.5" title="medium">
                      <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                      <span className="text-zinc-400">{e.medium}</span>
                    </span>
                    <span className={`font-semibold ${risk.color}`}>risk {e.risk_score}</span>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => open(e.file)}
                      disabled={opening === e.file}
                      className="h-7 border-zinc-700 px-2 text-xs hover:border-emerald-500/50 hover:text-emerald-300"
                    >
                      {opening === e.file ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <FolderOpen className="h-3 w-3" />
                      )}
                      Open
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
