/**
 * Bridge between the Next.js dashboard and the Python auditor engine.
 *
 * The CLI/engine is the single source of truth: the dashboard is a thin UI
 * wrapper that spawns `python3 -m auditor ... --format json` - exactly the
 * same interface a GitHub Action or pre-commit hook would use.
 */
import { spawn } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";

export const ENGINE_DIR = path.join(process.cwd(), "auditor-engine");
export const DEMO_PROJECT = path.join(process.cwd(), "demo-apps", "vulnerable-chatbot");
export const HISTORY_DIR = path.join(os.homedir(), ".auditor", "history");

/** Allowed scan roots (path traversal protection for public deployments). */
export const ALLOWED_ROOTS = (process.env.AUDITOR_ALLOWED_ROOTS || os.homedir())
  .split(":")
  .map((r) => path.resolve(r.trim()))
  .filter(Boolean);

const PYTHON_CANDIDATES = [
  process.env.AUDITOR_PYTHON,
  "python3",
  "python",
].filter(Boolean) as string[];

let cachedPython: string | null = null;

async function probe(candidate: string): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const child = spawn(candidate, ["--version"], { stdio: "ignore" });
      const timer = setTimeout(() => child.kill("SIGKILL"), 4000);
      child.on("error", () => {
        clearTimeout(timer);
        resolve(false);
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        resolve(code === 0);
      });
    } catch {
      resolve(false);
    }
  });
}

export async function resolvePython(): Promise<string> {
  if (cachedPython) return cachedPython;
  for (const candidate of PYTHON_CANDIDATES) {
    if (await probe(candidate)) {
      cachedPython = candidate;
      return candidate;
    }
  }
  cachedPython = "python3";
  return cachedPython;
}

export interface PythonResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

/** Run the auditor engine with the given CLI arguments. */
export function runAuditor(args: string[], timeoutMs = 180_000): Promise<PythonResult> {
  return resolvePython().then(
    (bin) =>
      new Promise<PythonResult>((resolve, reject) => {
        const child = spawn(bin, ["-m", "auditor", ...args], {
          cwd: ENGINE_DIR,
          env: { ...process.env, PYTHONPATH: ENGINE_DIR },
        });
        let stdout = "";
        let stderr = "";
        let killed = false;
        const timer = setTimeout(() => {
          killed = true;
          child.kill("SIGKILL");
        }, timeoutMs);
        child.stdout.on("data", (d: Buffer) => {
          stdout += d.toString();
        });
        child.stderr.on("data", (d: Buffer) => {
          stderr += d.toString();
        });
        child.on("error", (err) => {
          clearTimeout(timer);
          reject(err);
        });
        child.on("close", (code) => {
          clearTimeout(timer);
          if (killed) {
            reject(new Error("Engine timed out"));
            return;
          }
          resolve({ stdout, stderr, code });
        });
      })
  );
}

export function isPathAllowed(absPath: string): boolean {
  return ALLOWED_ROOTS.some((root) => absPath === root || absPath.startsWith(root + path.sep));
}
