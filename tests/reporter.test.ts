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
