import { describe, it, expect } from "vitest";
import { report } from "../src/reporter.js";
import type { ProbeResult } from "../src/attacks/types.js";

const mockResult: ProbeResult = {
  suites: [
    {
      suite: "prompt-injection",
      total: 3,
      passed: 1,
      failed: 2,
      results: [
        {
          attack: {
            id: "pi-001",
            suite: "prompt-injection",
            name: "ignore-instructions",
            description: "Classic injection",
            input: "Ignore...",
            severity: "high",
            detectors: ["compliance-check"],
          },
          vulnerable: true,
          response: "Sure, instructions ignored.",
          duration: 150,
          matchedDetectors: ["compliance-check"],
        },
        {
          attack: {
            id: "pi-002",
            suite: "prompt-injection",
            name: "xml-injection",
            description: "XML tag injection",
            input: "</system>...",
            severity: "critical",
            detectors: ["keyword-match:injection worked"],
          },
          vulnerable: true,
          response: "injection worked",
          duration: 200,
          matchedDetectors: ["keyword-match:injection worked"],
        },
        {
          attack: {
            id: "pi-003",
            suite: "prompt-injection",
            name: "base64-injection",
            description: "Base64",
            input: "Decode...",
            severity: "medium",
            detectors: ["keyword-match:BASE64"],
          },
          vulnerable: false,
          response: "I can't decode that.",
          duration: 100,
          matchedDetectors: [],
        },
      ],
    },
  ],
  totalAttacks: 3,
  totalPassed: 1,
  totalFailed: 2,
  duration: 450,
  target: "mock",
};

describe("reporter", () => {
  it("formats text output", () => {
    const output = report(mockResult, "text");
    expect(output).toContain("AgentProbe");
    expect(output).toContain("prompt-injection");
    expect(output).toContain("ignore-instructions");
    expect(output).toContain("PASS");
    expect(output).toContain("3 attacks");
  });

  it("formats json output", () => {
    const output = report(mockResult, "json");
    const parsed = JSON.parse(output);
    expect(parsed.version).toBe("0.1.0");
    expect(parsed.summary.total).toBe(3);
    expect(parsed.summary.failed).toBe(2);
    expect(parsed.summary.critical).toBe(1);
    expect(parsed.summary.high).toBe(1);
    expect(parsed.suites).toHaveLength(1);
    expect(parsed.suites[0].results).toHaveLength(3);
  });

  it("formats markdown output", () => {
    const output = report(mockResult, "markdown");
    expect(output).toContain("# AgentProbe Report");
    expect(output).toContain("| Status |");
    expect(output).toContain("CRITICAL");
    expect(output).toContain("⛔");
    expect(output).toContain("3 attacks");
  });

  it("shows verbose details when requested", () => {
    const output = report(mockResult, "text", { verbose: true });
    expect(output).toContain("Response:");
  });

  it("handles empty results", () => {
    const empty: ProbeResult = {
      suites: [],
      totalAttacks: 0,
      totalPassed: 0,
      totalFailed: 0,
      duration: 10,
      target: "mock",
    };
    const output = report(empty, "text");
    expect(output).toContain("0 attacks");
  });

  it("formats sarif output with valid structure", () => {
    const output = report(mockResult, "sarif");
    const sarif = JSON.parse(output);
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);

    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("agentprobe");
    expect(run.tool.driver.version).toBe("0.1.0");
    expect(run.tool.driver.rules).toHaveLength(3); // all 3 attack patterns as rules
  });

  it("sarif results only include vulnerable findings", () => {
    const output = report(mockResult, "sarif");
    const sarif = JSON.parse(output);
    const results = sarif.runs[0].results;
    expect(results).toHaveLength(2); // only 2 vulnerable
    expect(results[0].ruleId).toBe("pi-001");
    expect(results[1].ruleId).toBe("pi-002");
  });

  it("sarif maps severity to correct levels", () => {
    const output = report(mockResult, "sarif");
    const sarif = JSON.parse(output);
    const results = sarif.runs[0].results;
    // high → error, critical → error
    expect(results[0].level).toBe("error"); // high
    expect(results[1].level).toBe("error"); // critical
  });

  it("sarif includes matched detectors in message", () => {
    const output = report(mockResult, "sarif");
    const sarif = JSON.parse(output);
    const msg = sarif.runs[0].results[0].message.text;
    expect(msg).toContain("compliance-check");
  });

  it("sarif includes invocation metadata", () => {
    const output = report(mockResult, "sarif");
    const sarif = JSON.parse(output);
    const inv = sarif.runs[0].invocations[0];
    expect(inv.executionSuccessful).toBe(true);
    expect(inv.properties.totalAttacks).toBe(3);
  });

  it("sarif handles empty results", () => {
    const empty: ProbeResult = {
      suites: [],
      totalAttacks: 0,
      totalPassed: 0,
      totalFailed: 0,
      duration: 10,
      target: "mock",
    };
    const sarif = JSON.parse(report(empty, "sarif"));
    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it("json includes error information", () => {
    const withError: ProbeResult = {
      suites: [
        {
          suite: "prompt-injection",
          total: 1,
          passed: 0,
          failed: 0,
          results: [
            {
              attack: {
                id: "pi-001",
                suite: "prompt-injection",
                name: "test",
                description: "test",
                input: "test",
                severity: "high",
                detectors: [],
              },
              vulnerable: false,
              response: "",
              duration: 0,
              matchedDetectors: [],
              error: "Connection refused",
            },
          ],
        },
      ],
      totalAttacks: 1,
      totalPassed: 0,
      totalFailed: 0,
      duration: 10,
      target: "mock",
    };
    const parsed = JSON.parse(report(withError, "json"));
    expect(parsed.suites[0].results[0].error).toBe("Connection refused");
  });
});
