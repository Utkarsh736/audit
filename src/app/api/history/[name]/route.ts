import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { HISTORY_DIR } from "@/lib/engine";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(_req: NextRequest, { params }: { params: Promise<{ name: string }> }) {
  const { name } = await params;
  if (!/^[A-Za-z0-9_.\-]+\.json$/.test(name)) {
    return NextResponse.json({ error: "Invalid history file name" }, { status: 400 });
  }
  const file = path.join(HISTORY_DIR, name);
  if (!file.startsWith(HISTORY_DIR)) {
    return NextResponse.json({ error: "Path traversal rejected" }, { status: 403 });
  }
  if (!fs.existsSync(file)) {
    return NextResponse.json({ error: "History entry not found" }, { status: 404 });
  }
  try {
    const report = JSON.parse(fs.readFileSync(file, "utf8"));
    return NextResponse.json({ report });
  } catch {
    return NextResponse.json({ error: "Corrupt history entry" }, { status: 500 });
  }
}
