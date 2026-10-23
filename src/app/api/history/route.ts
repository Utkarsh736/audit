import { NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { HISTORY_DIR } from "@/lib/engine";
import type { AuditReport, HistoryEntry } from "@/lib/audit-types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  if (!fs.existsSync(HISTORY_DIR)) {
    return NextResponse.json({ entries: [] });
  }
  const files = fs
    .readdirSync(HISTORY_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => {
      const full = path.join(HISTORY_DIR, f);
      return { full, f, mtime: fs.statSync(full).mtimeMs };
    })
    .sort((a, b) => b.mtime - a.mtime)
    .slice(0, 50);

  const entries: HistoryEntry[] = [];
  for (const { full, f } of files) {
    try {
      const report: AuditReport = JSON.parse(fs.readFileSync(full, "utf8"));
      entries.push({
        file: f,
        project_name: report.project_name || path.basename(report.project_path || "unknown"),
        started_at: report.metadata?.started_at || "",
        total: report.summary?.total ?? 0,
        critical: report.summary?.critical ?? 0,
        high: report.summary?.high ?? 0,
        medium: report.summary?.medium ?? 0,
        low: report.summary?.low ?? 0,
        info: report.summary?.info ?? 0,
        risk_score: report.summary?.risk_score ?? 0,
      });
    } catch {
      // skip corrupt entries
    }
  }
  return NextResponse.json({ entries });
}
