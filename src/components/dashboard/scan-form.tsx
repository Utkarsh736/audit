"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Loader2, Play, FlaskConical, SlidersHorizontal } from "lucide-react";
import { EngineInfo } from "@/lib/audit-types";

const ALL_CHECKS = [
  { id: "secrets", label: "Secrets" },
  { id: "prompt-injection", label: "Prompt Injection" },
  { id: "data-handling", label: "Data Handling" },
  { id: "auth", label: "Auth" },
  { id: "insecure-output", label: "Insecure Output" },
  { id: "dangerous-code", label: "Dangerous Code" },
  { id: "configuration", label: "Configuration" },
];

interface ScanFormProps {
  engine: EngineInfo | null;
  scanning: boolean;
  onScan: (path: string, checks: string[], minSeverity: string) => void;
}

export function ScanForm({ engine, scanning, onScan }: ScanFormProps) {
  const [path, setPath] = useState("");
  const [checks, setChecks] = useState<string[]>(ALL_CHECKS.map((c) => c.id));
  const [minSeverity, setMinSeverity] = useState("info");
  const [showAdvanced, setShowAdvanced] = useState(false);

  const toggleCheck = (id: string) => {
    setChecks((prev) => (prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]));
  };

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (path.trim() && !scanning) onScan(path.trim(), checks, minSeverity);
  };

  const useDemo = () => {
    if (engine?.demo_available) setPath(engine.demo_path);
  };

  return (
    <Card className="border-zinc-800 bg-zinc-900/60">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Play className="h-4 w-4 text-emerald-400" />
          Run a security audit
        </CardTitle>
        <CardDescription>
          Point the auditor at a local project directory. Scanners are deterministic (regex + AST);
          findings are ranked and enriched with OWASP/CWE remediation guidance.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="project-path">Project path</Label>
            <div className="flex flex-col gap-2 sm:flex-row">
              <Input
                id="project-path"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder={engine?.demo_available ? "/home/you/projects/my-chatbot" : "Path to a project directory"}
                className="flex-1 font-mono text-sm"
                spellCheck={false}
              />
              <Button
                type="button"
                variant="outline"
                onClick={useDemo}
                disabled={!engine?.demo_available}
                className="shrink-0 border-zinc-700 hover:border-amber-500/50 hover:text-amber-300"
              >
                <FlaskConical className="mr-2 h-4 w-4" />
                Use demo app
              </Button>
            </div>
            {engine?.demo_available && (
              <p className="text-xs text-zinc-500">
                Demo target: <span className="font-mono text-zinc-400">{engine.demo_path}</span> — an
                intentionally vulnerable chatbot.
              </p>
            )}
          </div>

          <div>
            <button
              type="button"
              onClick={() => setShowAdvanced((s) => !s)}
              className="flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-200"
            >
              <SlidersHorizontal className="h-3.5 w-3.5" />
              {showAdvanced ? "Hide" : "Show"} advanced options
            </button>
            {showAdvanced && (
              <div className="mt-3 space-y-4 rounded-lg border border-zinc-800 bg-zinc-950/50 p-4">
                <div className="space-y-2">
                  <Label className="text-sm">Checks to run</Label>
                  <div className="flex flex-wrap gap-2">
                    {ALL_CHECKS.map((c) => {
                      const active = checks.includes(c.id);
                      return (
                        <button
                          key={c.id}
                          type="button"
                          onClick={() => toggleCheck(c.id)}
                          className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                            active
                              ? "border-emerald-500/60 bg-emerald-500/10 text-emerald-300"
                              : "border-zinc-700 bg-transparent text-zinc-500 hover:text-zinc-300"
                          }`}
                          aria-pressed={active}
                        >
                          {c.label}
                        </button>
                      );
                    })}
                  </div>
                </div>
                <div className="space-y-2">
                  <Label className="text-sm">Minimum severity</Label>
                  <div className="flex flex-wrap gap-2">
                    {["info", "low", "medium", "high", "critical"].map((sev) => (
                      <button
                        key={sev}
                        type="button"
                        onClick={() => setMinSeverity(sev)}
                        className={`rounded-full border px-3 py-1 text-xs capitalize transition-colors ${
                          minSeverity === sev
                            ? "border-zinc-500 bg-zinc-800 text-zinc-100"
                            : "border-zinc-700 bg-transparent text-zinc-500 hover:text-zinc-300"
                        }`}
                        aria-pressed={minSeverity === sev}
                      >
                        {sev}+
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs text-zinc-500">
              {engine ? (
                engine.ok ? (
                  <>
                    <Badge variant="outline" className="border-emerald-500/40 text-emerald-400">
                      engine v{engine.version}
                    </Badge>
                    <span>{engine.rules_count} rules</span>
                  </>
                ) : (
                  <Badge variant="outline" className="border-red-500/40 text-red-400">
                    engine offline
                  </Badge>
                )
              ) : (
                <span>checking engine…</span>
              )}
            </div>
            <Button
              type="submit"
              disabled={!path.trim() || scanning || checks.length === 0}
              className="bg-emerald-600 text-white hover:bg-emerald-500"
            >
              {scanning ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Scanning…
                </>
              ) : (
                <>
                  <Play className="mr-2 h-4 w-4" />
                  Scan project
                </>
              )}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
