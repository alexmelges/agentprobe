import type { SkillAuditResult, SkillFinding, SkillSeverity } from "./types.js";

const SEVERITY_EMOJI: Record<SkillSeverity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
};

const SEVERITY_LABEL: Record<SkillSeverity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
};

const SEVERITY_ORDER: SkillSeverity[] = ["critical", "high", "medium", "low"];

function groupBySeverity(findings: SkillFinding[]): Record<SkillSeverity, SkillFinding[]> {
  const groups: Record<SkillSeverity, SkillFinding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: [],
  };
  for (const f of findings) {
    groups[f.severity].push(f);
  }
  return groups;
}

export function formatText(result: SkillAuditResult): string {
  const lines: string[] = [];
  lines.push(`🔍 AgentProbe Skill Audit: ${result.path}`);
  lines.push("");
  lines.push(`📁 Scanned: ${result.filesScanned} files (${result.filesSkipped} skipped)`);
  lines.push("");

  const groups = groupBySeverity(result.findings);

  for (const sev of SEVERITY_ORDER) {
    const items = groups[sev];
    if (items.length === 0) continue;

    lines.push(`${SEVERITY_EMOJI[sev]} ${SEVERITY_LABEL[sev]} (${items.length} finding${items.length !== 1 ? "s" : ""})`);
    for (const f of items) {
      lines.push(`  [${f.id}] ${f.name}`);
      lines.push(`    File: ${f.file}:${f.line}`);
      lines.push(`    Match: ${f.match}`);
      lines.push(`    Risk: ${f.risk}`);
      lines.push("");
    }
  }

  const counts = SEVERITY_ORDER.map(
    (s) => `${groups[s].length} ${SEVERITY_LABEL[s].toLowerCase()}`
  ).join(", ");

  const hasCriticalOrHigh = groups.critical.length > 0 || groups.high.length > 0;
  const verdict = hasCriticalOrHigh ? "FAIL" : result.findings.length > 0 ? "WARN" : "PASS";

  lines.push(`Summary: ${counts} — ${verdict}`);
  lines.push(`Duration: ${result.duration}ms`);

  return lines.join("\n");
}

export function formatJson(result: SkillAuditResult): string {
  return JSON.stringify(result, null, 2);
}

export function formatSarif(result: SkillAuditResult): string {
  const sarifSeverity: Record<SkillSeverity, string> = {
    critical: "error",
    high: "error",
    medium: "warning",
    low: "note",
  };

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "agentprobe-skill-audit",
            version: "0.5.0",
            rules: result.findings.map((f) => ({
              id: f.id,
              shortDescription: { text: f.name },
              fullDescription: { text: f.risk },
              defaultConfiguration: {
                level: sarifSeverity[f.severity],
              },
            })),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.id,
          level: sarifSeverity[f.severity],
          message: { text: `${f.name}: ${f.risk}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: { startLine: f.line },
              },
            },
          ],
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

export function formatMarkdown(result: SkillAuditResult): string {
  const lines: string[] = [];
  lines.push(`# AgentProbe Skill Audit: ${result.path}`);
  lines.push("");
  lines.push(`**Scanned:** ${result.filesScanned} files (${result.filesSkipped} skipped)`);
  lines.push("");

  const groups = groupBySeverity(result.findings);

  for (const sev of SEVERITY_ORDER) {
    const items = groups[sev];
    if (items.length === 0) continue;
    lines.push(`## ${SEVERITY_EMOJI[sev]} ${SEVERITY_LABEL[sev]} (${items.length})`);
    lines.push("");
    lines.push("| ID | Finding | File | Line | Risk |");
    lines.push("|---|---|---|---|---|");
    for (const f of items) {
      lines.push(`| ${f.id} | ${f.name} | ${f.file} | ${f.line} | ${f.risk} |`);
    }
    lines.push("");
  }

  const hasCriticalOrHigh = groups.critical.length > 0 || groups.high.length > 0;
  lines.push(`**Verdict:** ${hasCriticalOrHigh ? "❌ FAIL" : result.findings.length > 0 ? "⚠️ WARN" : "✅ PASS"}`);

  return lines.join("\n");
}

export type SkillReportFormat = "text" | "json" | "sarif" | "markdown";

export function formatSkillReport(result: SkillAuditResult, format: SkillReportFormat): string {
  switch (format) {
    case "text":
      return formatText(result);
    case "json":
      return formatJson(result);
    case "sarif":
      return formatSarif(result);
    case "markdown":
      return formatMarkdown(result);
    default:
      return formatText(result);
  }
}
