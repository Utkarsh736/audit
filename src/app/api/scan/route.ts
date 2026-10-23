import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { isPathAllowed, runAuditor } from "@/lib/engine";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface ScanBody {
  path?: string;
  checks?: string[];
  minSeverity?: string;
}

export async function POST(req: NextRequest) {
  let body: ScanBody;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }
  if (!body.path || typeof body.path !== "string") {
    return NextResponse.json({ error: "Missing 'path' (project directory to scan)" }, { status: 400 });
  }

  let target: string;
  try {
    target = path.resolve(body.path);
  } catch {
    return NextResponse.json({ error: "Could not resolve path" }, { status: 400 });
  }
  if (!fs.existsSync(target)) {
    return NextResponse.json({ error: `Path does not exist: ${target}` }, { status: 404 });
  }
  const stat = fs.statSync(target);
  if (!stat.isDirectory() && !stat.isFile()) {
    return NextResponse.json({ error: "Path is neither a file nor a directory" }, { status: 400 });
  }
  if (!isPathAllowed(target)) {
    return NextResponse.json(
      { error: "Path is outside the allowed scan roots. Set AUDITOR_ALLOWED_ROOTS to expand." },
      { status: 403 }
    );
  }

  const validChecks = [
    "secrets",
    "prompt-injection",
    "data-handling",
    "auth",
    "insecure-output",
    "dangerous-code",
    "configuration",
  ];
  const checks = (body.checks || []).filter((c) => validChecks.includes(c));

  const args = ["scan", target, "--format", "json", "-q"];
  if (checks.length > 0 && checks.length < validChecks.length) {
    args.push("--checks", checks.join(","));
  }
  const minSeverity = body.minSeverity;
  if (
    minSeverity &&
    ["critical", "high", "medium", "low", "info"].includes(minSeverity) &&
    minSeverity !== "info"
  ) {
    args.push("--min-severity", minSeverity);
  }

  try {
    const { stdout, stderr, code } = await runAuditor(args);
    // exit code 1 means "findings exist" (CI semantics) - still a valid report
    try {
      const report = JSON.parse(stdout);
      return NextResponse.json({ report, stderrTail: stderr.split("\n").slice(-6).join("\n") });
    } catch {
      return NextResponse.json(
        {
          error: "Engine did not return a valid report",
          exitCode: code,
          stderrTail: stderr.slice(-1500),
        },
        { status: 500 }
      );
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown engine error";
    return NextResponse.json({ error: `Engine failed: ${message}` }, { status: 500 });
  }
}
