import chalk from "chalk";
import type { ProbeResult, AttackResult, SuiteResult, Severity } from "./attacks/types.js";

export type OutputFormat = "text" | "json" | "markdown" | "sarif";

const SEVERITY_COLORS: Record<Severity, (s: string) => string> = {
  critical: chalk.red.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.dim,
};

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: "✗ CRITICAL",
  high: "✗ HIGH",
  medium: "✗ MEDIUM",
  low: "✗ LOW",
};

function formatText(result: ProbeResult, options: { verbose?: boolean } = {}): string {
  const lines: string[] = [];

  lines.push(chalk.bold(`AgentProbe v0.1.0 — Adversarial Security Testing\n`));
  lines.push(`Target: ${result.target}`);
  lines.push(
    `Attacks: ${result.suites.length} suites, ${result.totalAttacks} patterns\n`
  );

  for (const suite of result.suites) {
    lines.push(chalk.bold.underline(`[${suite.suite}]`));

    for (const r of suite.results) {
      if (r.error) {
        lines.push(
          `  ${chalk.gray("⚠ ERROR")}  ${chalk.gray(r.attack.name)}    ${chalk.gray(r.error)}`
        );
      } else if (r.vulnerable) {
        const color = SEVERITY_COLORS[r.attack.severity];
        lines.push(
          `  ${color(SEVERITY_ICONS[r.attack.severity])}  ${r.attack.name}    ${chalk.dim(r.matchedDetectors.join(", "))}`
        );
        if (options.verbose) {
          lines.push(
            `    ${chalk.dim("Response:")} ${r.response.slice(0, 200).replace(/\n/g, "\\n")}`
          );
        }
      } else {
        lines.push(`  ${chalk.green("✓ PASS")}   ${chalk.dim(r.attack.name)}`);
      }
    }

    lines.push("");
  }

  // Summary
  const critCount = countBySeverity(result, "critical");
  const highCount = countBySeverity(result, "high");
  const medCount = countBySeverity(result, "medium");
  const lowCount = countBySeverity(result, "low");
  const errCount = result.suites
    .flatMap((s) => s.results)
    .filter((r) => r.error).length;

  lines.push(chalk.bold("Summary:"));
  lines.push(
    `  ${result.totalAttacks} attacks | ${chalk.green(String(result.totalPassed) + " passed")} | ${critCount ? chalk.red.bold(critCount + " critical") : "0 critical"} | ${highCount ? chalk.red(highCount + " high") : "0 high"} | ${medCount ? chalk.yellow(medCount + " medium") : "0 medium"} | ${lowCount ? chalk.dim(lowCount + " low") : "0 low"}${errCount ? chalk.gray(` | ${errCount} errors`) : ""}`
  );
  lines.push(`  Duration: ${(result.duration / 1000).toFixed(1)}s`);

  if (result.totalFailed > 0) {
    lines.push(
      `\n${chalk.red.bold(`Exit code: 1 (${critCount + highCount} critical/high findings)`)}`
    );
  } else {
    lines.push(`\n${chalk.green.bold("Exit code: 0 (no vulnerabilities found)")}`);
  }

  return lines.join("\n");
}

function formatJson(result: ProbeResult): string {
  return JSON.stringify(
    {
      version: "0.1.0",
      target: result.target,
      duration: result.duration,
      summary: {
        total: result.totalAttacks,
        passed: result.totalPassed,
        failed: result.totalFailed,
        critical: countBySeverity(result, "critical"),
        high: countBySeverity(result, "high"),
        medium: countBySeverity(result, "medium"),
        low: countBySeverity(result, "low"),
      },
      suites: result.suites.map((s) => ({
        name: s.suite,
        total: s.total,
        passed: s.passed,
        failed: s.failed,
        results: s.results.map((r) => ({
          id: r.attack.id,
          name: r.attack.name,
          severity: r.attack.severity,
          vulnerable: r.vulnerable,
          matchedDetectors: r.matchedDetectors,
          duration: r.duration,
          ...(r.error ? { error: r.error } : {}),
        })),
      })),
    },
    null,
    2
  );
}

function formatMarkdown(result: ProbeResult): string {
  const lines: string[] = [];

  lines.push("# AgentProbe Report\n");
  lines.push(`**Target:** ${result.target}`);
  lines.push(`**Duration:** ${(result.duration / 1000).toFixed(1)}s`);
  lines.push(
    `**Summary:** ${result.totalAttacks} attacks | ${result.totalPassed} passed | ${result.totalFailed} failed\n`
  );

  const crit = countBySeverity(result, "critical");
  const high = countBySeverity(result, "high");
  if (crit > 0) lines.push(`> ⛔ **${crit} CRITICAL vulnerabilities found**\n`);
  if (high > 0) lines.push(`> ⚠️ **${high} HIGH vulnerabilities found**\n`);

  for (const suite of result.suites) {
    lines.push(`## ${suite.suite}\n`);
    lines.push("| Status | Severity | Attack | Detectors |");
    lines.push("|--------|----------|--------|-----------|");

    for (const r of suite.results) {
      if (r.error) {
        lines.push(`| ⚠️ | - | ${r.attack.name} | Error: ${r.error} |`);
      } else if (r.vulnerable) {
        const icon = r.attack.severity === "critical" ? "⛔" : r.attack.severity === "high" ? "🔴" : r.attack.severity === "medium" ? "🟡" : "⚪";
        lines.push(
          `| ${icon} FAIL | ${r.attack.severity} | ${r.attack.name} | ${r.matchedDetectors.join(", ")} |`
        );
      } else {
        lines.push(`| ✅ PASS | ${r.attack.severity} | ${r.attack.name} | - |`);
      }
    }

    lines.push("");
  }

  return lines.join("\n");
}

const SARIF_LEVEL: Record<Severity, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

function formatSarif(result: ProbeResult): string {
  const allAttacks = result.suites.flatMap((s) => s.results);

  // Build rules from all unique attack patterns
  const rulesMap = new Map<string, AttackResult["attack"]>();
  for (const r of allAttacks) {
    if (!rulesMap.has(r.attack.id)) {
      rulesMap.set(r.attack.id, r.attack);
    }
  }

  const rules = Array.from(rulesMap.values()).map((a) => ({
    id: a.id,
    name: a.name,
    shortDescription: { text: a.description },
    fullDescription: { text: `[${a.suite}] ${a.description}` },
    defaultConfiguration: { level: SARIF_LEVEL[a.severity] },
    properties: {
      suite: a.suite,
      severity: a.severity,
    },
  }));

  // Build results — only vulnerable findings
  const results = allAttacks
    .filter((r) => r.vulnerable)
    .map((r) => ({
      ruleId: r.attack.id,
      level: SARIF_LEVEL[r.attack.severity],
      message: {
        text: `${r.attack.description}. Matched detectors: ${r.matchedDetectors.join(", ")}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: result.target },
          },
        },
      ],
      properties: {
        suite: r.attack.suite,
        duration: r.duration,
        detectors: r.matchedDetectors,
      },
    }));

  const sarif = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0" as const,
    runs: [
      {
        tool: {
          driver: {
            name: "agentprobe",
            version: "0.1.0",
            informationUri: "https://github.com/alexmelges/agentprobe",
            rules,
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            properties: {
              totalAttacks: result.totalAttacks,
              totalPassed: result.totalPassed,
              totalFailed: result.totalFailed,
              duration: result.duration,
            },
          },
        ],
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

function countBySeverity(result: ProbeResult, severity: Severity): number {
  return result.suites
    .flatMap((s) => s.results)
    .filter((r) => r.vulnerable && r.attack.severity === severity).length;
}

export function report(
  result: ProbeResult,
  format: OutputFormat = "text",
  options: { verbose?: boolean } = {}
): string {
  switch (format) {
    case "json":
      return formatJson(result);
    case "markdown":
      return formatMarkdown(result);
    case "sarif":
      return formatSarif(result);
    case "text":
    default:
      return formatText(result, options);
  }
}
