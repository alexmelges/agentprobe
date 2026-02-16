import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, extname } from "node:path";
import { ALL_PATTERNS, type PatternDef } from "./patterns.js";
import type { SkillAuditResult, SkillFinding, SkillSeverity } from "./types.js";

const TEXT_EXTENSIONS = new Set([
  ".md", ".txt", ".ts", ".js", ".mjs", ".cjs", ".py", ".rb", ".go",
  ".java", ".rs", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
  ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env",
  ".html", ".htm", ".css", ".xml", ".svg", ".sql", ".graphql", ".gql",
  ".dockerfile", ".makefile", ".cmake",
  "",  // files without extension (Makefile, Dockerfile, etc.)
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "__pycache__", ".venv",
  "venv", ".tox", ".mypy_cache", "target", ".next", ".nuxt",
]);

const MAX_FILE_SIZE = 1024 * 1024; // 1MB

const SEVERITY_RANK: Record<SkillSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function isBinary(buf: Buffer): boolean {
  // Check first 8KB for null bytes
  const sample = buf.subarray(0, 8192);
  for (let i = 0; i < sample.length; i++) {
    if (sample[i] === 0) return true;
  }
  return false;
}

function walkDir(dir: string): string[] {
  const files: string[] = [];
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith(".") && entry.name !== ".env") continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      files.push(...walkDir(fullPath));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}

function matchesExtension(filePath: string, extensions?: string[]): boolean {
  if (!extensions || extensions.length === 0) return true;
  const ext = extname(filePath).toLowerCase();
  return extensions.includes(ext);
}

function truncateMatch(text: string, maxLen = 80): string {
  const trimmed = text.trim().replace(/\n/g, "\\n");
  if (trimmed.length <= maxLen) return trimmed;
  return trimmed.slice(0, maxLen) + "...";
}

function scanFile(
  filePath: string,
  relPath: string,
  content: string,
  patterns: PatternDef[]
): SkillFinding[] {
  const findings: SkillFinding[] = [];
  const lines = content.split("\n");

  for (const pattern of patterns) {
    if (!matchesExtension(filePath, pattern.extensions)) continue;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const m = pattern.pattern.exec(line);
      if (m) {
        findings.push({
          id: pattern.id,
          category: pattern.category,
          severity: pattern.severity,
          name: pattern.name,
          description: pattern.name,
          file: relPath,
          line: i + 1,
          match: truncateMatch(m[0]),
          risk: pattern.risk,
        });
        // Only report first match per pattern per file to reduce noise
        break;
      }
    }
  }

  return findings;
}

export interface ScanOptions {
  severityFilter?: SkillSeverity;
}

export function auditSkill(
  dirPath: string,
  options: ScanOptions = {}
): SkillAuditResult {
  const start = Date.now();
  const minSeverity = SEVERITY_RANK[options.severityFilter ?? "low"] ?? 1;

  // Filter patterns by severity
  const patterns = ALL_PATTERNS.filter(
    (p) => SEVERITY_RANK[p.severity] >= minSeverity
  );

  const allFiles = walkDir(dirPath);
  let filesScanned = 0;
  let filesSkipped = 0;
  const findings: SkillFinding[] = [];

  for (const filePath of allFiles) {
    const ext = extname(filePath).toLowerCase();
    const baseName = filePath.split("/").pop() ?? "";

    // Skip by extension
    if (!TEXT_EXTENSIONS.has(ext) && !baseName.match(/^(Makefile|Dockerfile|Procfile|Gemfile|Rakefile|Vagrantfile)$/i)) {
      filesSkipped++;
      continue;
    }

    // Skip large files
    const stat = statSync(filePath);
    if (stat.size > MAX_FILE_SIZE) {
      filesSkipped++;
      continue;
    }

    // Skip binary files
    const buf = readFileSync(filePath);
    if (isBinary(buf)) {
      filesSkipped++;
      continue;
    }

    const content = buf.toString("utf-8");
    const relPath = relative(dirPath, filePath);
    const fileFindings = scanFile(filePath, relPath, content, patterns);
    findings.push(...fileFindings);
    filesScanned++;
  }

  return {
    path: dirPath,
    filesScanned,
    filesSkipped,
    findings,
    duration: Date.now() - start,
  };
}
