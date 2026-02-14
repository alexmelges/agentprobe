import type { Adapter } from "./adapters/types.js";
import type { AttackPattern, AttackResult, SuiteResult, ProbeResult, SuiteName } from "./attacks/types.js";
import type { BoundariesConfig } from "./config.js";
import { resolveDetector } from "./detectors.js";
import { getAttacks } from "./attacks/registry.js";

export interface RunOptions {
  verbose?: boolean;
  timeout?: number;
  severityFilter?: string;
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

async function runAttack(
  adapter: Adapter,
  attack: AttackPattern,
  boundaries?: BoundariesConfig,
  timeout = 30000
): Promise<AttackResult> {
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const res = await adapter.send({ input: attack.input });
    clearTimeout(timer);

    const response = res.content;
    const matchedDetectors: string[] = [];

    for (const detectorStr of attack.detectors) {
      const { name, fn } = resolveDetector(detectorStr);
      if (fn(response, boundaries)) {
        matchedDetectors.push(name);
      }
    }

    // Also check tool_calls for unauthorized-tool-call detectors
    if (res.tool_calls && res.tool_calls.length > 0) {
      for (const tc of res.tool_calls) {
        for (const detectorStr of attack.detectors) {
          if (detectorStr.startsWith("unauthorized-tool-call:")) {
            const toolPattern = detectorStr.slice("unauthorized-tool-call:".length);
            if (tc.name.toLowerCase().includes(toolPattern.toLowerCase())) {
              if (!matchedDetectors.includes(detectorStr)) {
                matchedDetectors.push(detectorStr);
              }
            }
          }
        }
      }
    }

    return {
      attack,
      vulnerable: matchedDetectors.length > 0,
      response,
      duration: Date.now() - start,
      matchedDetectors,
    };
  } catch (err) {
    return {
      attack,
      vulnerable: false,
      response: "",
      duration: Date.now() - start,
      matchedDetectors: [],
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function runProbe(
  adapter: Adapter,
  suites: SuiteName[],
  boundaries?: BoundariesConfig,
  options: RunOptions = {}
): Promise<ProbeResult> {
  const start = Date.now();
  const suiteResults: SuiteResult[] = [];
  const minSeverity = SEVERITY_RANK[options.severityFilter ?? "low"] ?? 1;

  for (const suiteName of suites) {
    let attacks = getAttacks(suiteName);

    // Filter by severity
    attacks = attacks.filter(
      (a) => (SEVERITY_RANK[a.severity] ?? 0) >= minSeverity
    );

    const results: AttackResult[] = [];

    for (const attack of attacks) {
      if (options.verbose) {
        process.stderr.write(`  Testing ${attack.id}: ${attack.name}...`);
      }

      const result = await runAttack(
        adapter,
        attack,
        boundaries,
        options.timeout
      );
      results.push(result);

      if (options.verbose) {
        process.stderr.write(
          result.vulnerable ? " VULNERABLE\n" : result.error ? ` ERROR: ${result.error}\n` : " PASS\n"
        );
      }
    }

    suiteResults.push({
      suite: suiteName,
      results,
      total: results.length,
      passed: results.filter((r) => !r.vulnerable && !r.error).length,
      failed: results.filter((r) => r.vulnerable).length,
    });
  }

  const allResults = suiteResults.flatMap((s) => s.results);

  return {
    suites: suiteResults,
    totalAttacks: allResults.length,
    totalPassed: allResults.filter((r) => !r.vulnerable && !r.error).length,
    totalFailed: allResults.filter((r) => r.vulnerable).length,
    duration: Date.now() - start,
    target: adapter.name,
  };
}
