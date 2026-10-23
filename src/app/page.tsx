"use client";

import { useCallback, useEffect, useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ScanForm } from "@/components/dashboard/scan-form";
import { SummaryCards } from "@/components/dashboard/summary-cards";
import { ResultsView } from "@/components/dashboard/results-view";
import { HistoryPanel } from "@/components/dashboard/history-panel";
import { AuditReport, EngineInfo } from "@/lib/audit-types";
import { Shield, ShieldAlert, ShieldCheck, Sparkles, Terminal, CircleAlert } from "lucide-react";

type Tab = "scanner" | "history";

export default function Home() {
  const [engine, setEngine] = useState<EngineInfo | null>(null);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("scanner");

  useEffect(() => {
    fetch("/api/engine")
      .then((r) => r.json())
      .then(setEngine)
      .catch(() => setEngine({ ok: false, version: "", checks: [], rules_count: 0, llm_available: false, demo_path: "", demo_available: false }));
  }, []);

  const runScan = useCallback(async (path: string, checks: string[], minSeverity: string) => {
    setScanning(true);
    setError(null);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path, checks, minSeverity }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Scan failed");
        setReport(null);
      } else {
        setReport(data.report);
        setTab("scanner");
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Network error");
    } finally {
      setScanning(false);
    }
  }, []);

  const openHistoryReport = useCallback(async (file: string) => {
    setError(null);
    try {
      const res = await fetch(`/api/history/${encodeURIComponent(file)}`);
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Could not load history entry");
        return;
      }
      setReport(data.report);
      setTab("scanner");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Network error");
    }
  }, []);

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100">
      {/* Header */}
      <header className="border-b border-zinc-800/80 bg-zinc-950/95 backdrop-blur">
        <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center gap-3 px-4 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-emerald-500/40 bg-emerald-500/10">
              <Shield className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-lg font-bold leading-tight">Auditor</h1>
              <p className="text-xs text-zinc-500">Agentic security auditor for code &amp; LLM apps</p>
            </div>
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-2 text-xs">
            {engine?.ok ? (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/10 px-2.5 py-1 text-emerald-400">
                <ShieldCheck className="h-3 w-3" />
                engine v{engine.version} · {engine.rules_count} rules
              </span>
            ) : engine ? (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-red-500/40 bg-red-500/10 px-2.5 py-1 text-red-400">
                <ShieldAlert className="h-3 w-3" />
                engine offline
              </span>
            ) : null}
            <span
              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 ${
                engine?.llm_available
                  ? "border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-300"
                  : "border-zinc-700 bg-zinc-900 text-zinc-400"
              }`}
              title={
                engine?.llm_available
                  ? "LLM enrichment active"
                  : "Set AUDITOR_LLM_API_KEY to enable AI-generated remediation guidance"
              }
            >
              <Sparkles className="h-3 w-3" />
              LLM {engine?.llm_available ? "on" : "off"}
            </span>
            <span className="hidden items-center gap-1.5 rounded-full border border-zinc-700 bg-zinc-900 px-2.5 py-1 text-zinc-400 sm:inline-flex">
              <Terminal className="h-3 w-3" />
              <code className="font-mono">audit scan ./project</code>
            </span>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6">
        <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)} className="space-y-6">
          <TabsList className="border border-zinc-800 bg-zinc-900">
            <TabsTrigger
              value="scanner"
              className="data-[state=active]:bg-zinc-800 data-[state=active]:text-emerald-300"
            >
              Scanner
            </TabsTrigger>
            <TabsTrigger
              value="history"
              className="data-[state=active]:bg-zinc-800 data-[state=active]:text-emerald-300"
            >
              History
            </TabsTrigger>
          </TabsList>

          <TabsContent value="scanner" className="space-y-6">
            <ScanForm engine={engine} scanning={scanning} onScan={runScan} />

            {error && (
              <Alert className="border-red-900/60 bg-red-950/30">
                <CircleAlert className="h-4 w-4 text-red-400" />
                <AlertTitle className="text-red-300">Scan failed</AlertTitle>
                <AlertDescription className="text-red-200/80">{error}</AlertDescription>
              </Alert>
            )}

            {scanning && (
              <div className="flex items-center justify-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900/40 py-10 text-sm text-zinc-400">
                <span className="h-2 w-2 animate-ping rounded-full bg-emerald-400" />
                Discovering files, running scanners, ranking findings…
              </div>
            )}

            {report && !scanning && (
              <div className="space-y-6">
                <SummaryCards summary={report.summary} />
                <ResultsView report={report} />
              </div>
            )}
          </TabsContent>

          <TabsContent value="history">
            <HistoryPanel onOpenReport={openHistoryReport} />
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-zinc-800/80 bg-zinc-950">
        <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center justify-between gap-2 px-4 py-4 text-xs text-zinc-600">
          <span>
            Deterministic scanners (regex + AST) · OWASP/CWE knowledge base · optional LLM enrichment
          </span>
          <span className="font-mono">
            pip install -e auditor-engine · audit scan · audit explain · audit fix
          </span>
        </div>
      </footer>
    </div>
  );
}
