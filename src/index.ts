#!/usr/bin/env node

import { Command } from "commander";
import { resolve } from "node:path";
import { loadConfig } from "./config.js";
import { createAdapter } from "./adapters/index.js";
import { runProbe } from "./runner.js";
import { report, type OutputFormat } from "./reporter.js";
import { getAllAttacks } from "./attacks/registry.js";

const program = new Command();

program
  .name("agentprobe")
  .description("Adversarial security testing for AI agents")
  .version("0.1.0")
  .option("-c, --config <path>", "config file path", "agentprobe.yaml")
  .option("-a, --attacks <suites>", "comma-separated attack suites to run")
  .option(
    "-s, --severity <level>",
    "minimum severity to report: low, medium, high, critical",
    "low"
  )
  .option(
    "-f, --format <format>",
    "output format: text, json, markdown, sarif",
    "text"
  )
  .option("-t, --timeout <ms>", "per-attack timeout in ms", "30000")
  .option("--dry-run", "list attacks without running")
  .option("--verbose", "show full request/response details")
  .action(async (options) => {
    const configPath = resolve(options.config);

    try {
      const config = loadConfig(configPath);

      // Override suites if specified via CLI
      if (options.attacks) {
        config.suites = options.attacks.split(",").map((s: string) => s.trim());
      }

      if (options.dryRun) {
        const attacks = getAllAttacks(config.suites);
        console.log(
          `Config valid: ${config.suites.length} suite(s), ${attacks.length} attack(s)\n`
        );

        for (const suite of config.suites) {
          const suiteAttacks = getAllAttacks([suite]);
          console.log(`  [${suite}] — ${suiteAttacks.length} attacks`);
          for (const a of suiteAttacks) {
            console.log(
              `    ${a.id}: ${a.name} (${a.severity}) — ${a.detectors.join(", ")}`
            );
          }
        }

        process.exit(0);
      }

      const adapter = createAdapter(config.agent);
      const result = await runProbe(adapter, config.suites, config.boundaries, {
        verbose: options.verbose,
        timeout: parseInt(options.timeout, 10),
        severityFilter: options.severity,
      });

      const output = report(result, options.format as OutputFormat, {
        verbose: options.verbose,
      });

      console.log(output);

      // Exit 1 if any critical or high vulnerabilities
      const hasCritical = result.suites
        .flatMap((s) => s.results)
        .some(
          (r) =>
            r.vulnerable &&
            (r.attack.severity === "critical" || r.attack.severity === "high")
        );

      process.exit(hasCritical ? 1 : 0);
    } catch (err) {
      console.error(
        `Error: ${err instanceof Error ? err.message : String(err)}`
      );
      process.exit(1);
    }
  });

program.parse();
