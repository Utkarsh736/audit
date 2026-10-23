import { NextResponse } from "next/server";
import fs from "fs";
import { DEMO_PROJECT, resolvePython, runAuditor } from "@/lib/engine";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const python = await resolvePython();
    const { stdout, code } = await runAuditor(["info", "--format", "json"]);
    if (code !== null && code <= 1 && stdout.trim()) {
      const info = JSON.parse(stdout);
      return NextResponse.json({
        ok: true,
        version: info.version,
        checks: info.checks,
        rules_count: info.rules_count,
        python,
        llm_available: !!(process.env.AUDITOR_LLM_API_KEY || process.env.GROQ_API_KEY),
        demo_path: DEMO_PROJECT,
        demo_available: fs.existsSync(DEMO_PROJECT),
      });
    }
    return NextResponse.json({ ok: false, note: "Engine did not respond correctly" });
  } catch {
    return NextResponse.json({ ok: false, note: "Python engine unreachable" }, { status: 200 });
  }
}
