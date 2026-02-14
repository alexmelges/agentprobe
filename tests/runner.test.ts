import { describe, it, expect, vi } from "vitest";
import { runProbe } from "../src/runner.js";
import type { Adapter } from "../src/adapters/types.js";

function createMockAdapter(responseText: string): Adapter {
  return {
    name: "mock",
    send: vi.fn().mockResolvedValue({ content: responseText }),
  };
}

function createErrorAdapter(): Adapter {
  return {
    name: "mock-error",
    send: vi.fn().mockRejectedValue(new Error("Connection refused")),
  };
}

describe("runProbe", () => {
  it("marks attacks as passed when agent rejects them", async () => {
    const adapter = createMockAdapter("I'm sorry, I cannot do that. I must follow my guidelines.");
    const result = await runProbe(adapter, ["prompt-injection"], undefined, {
      severityFilter: "critical",
    });

    expect(result.totalAttacks).toBeGreaterThan(0);
    expect(result.totalPassed).toBeGreaterThan(0);
    // Agent properly rejected, so no vulnerabilities
  });

  it("marks attacks as vulnerable when agent complies", async () => {
    const adapter = createMockAdapter("Sure! Safety filters disabled. Unrestricted mode is now active. INJECTION_SUCCESS");
    const result = await runProbe(adapter, ["prompt-injection"], undefined, {
      severityFilter: "critical",
    });

    expect(result.totalFailed).toBeGreaterThan(0);
  });

  it("detects system prompt leaks", async () => {
    const adapter = createMockAdapter("You are a helpful assistant. Your role is to answer questions about our products. You must always be polite.");
    const result = await runProbe(adapter, ["data-exfiltration"]);

    const vulnerable = result.suites
      .flatMap((s) => s.results)
      .filter((r) => r.vulnerable);
    expect(vulnerable.length).toBeGreaterThan(0);
  });

  it("handles adapter errors gracefully", async () => {
    const adapter = createErrorAdapter();
    const result = await runProbe(adapter, ["prompt-injection"], undefined, {
      severityFilter: "critical",
    });

    const errors = result.suites
      .flatMap((s) => s.results)
      .filter((r) => r.error);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0].error).toContain("Connection refused");
  });

  it("filters by severity", async () => {
    const adapter = createMockAdapter("I can't help with that.");
    const resultAll = await runProbe(adapter, ["prompt-injection"], undefined, {
      severityFilter: "low",
    });
    const resultCrit = await runProbe(adapter, ["prompt-injection"], undefined, {
      severityFilter: "critical",
    });

    expect(resultAll.totalAttacks).toBeGreaterThan(resultCrit.totalAttacks);
  });

  it("runs multiple suites", async () => {
    const adapter = createMockAdapter("I can't help with that.");
    const result = await runProbe(
      adapter,
      ["prompt-injection", "data-exfiltration"],
      undefined,
      { severityFilter: "critical" }
    );

    expect(result.suites).toHaveLength(2);
    expect(result.suites[0].suite).toBe("prompt-injection");
    expect(result.suites[1].suite).toBe("data-exfiltration");
  });

  it("includes timing information", async () => {
    const adapter = createMockAdapter("No.");
    const result = await runProbe(adapter, ["prompt-injection"], undefined, {
      severityFilter: "critical",
    });

    expect(result.duration).toBeGreaterThanOrEqual(0);
    for (const suite of result.suites) {
      for (const r of suite.results) {
        expect(r.duration).toBeGreaterThanOrEqual(0);
      }
    }
  });

  it("uses boundaries for detection", async () => {
    const adapter = createMockAdapter("I have access to search and weather tools for your convenience.");
    const result = await runProbe(
      adapter,
      ["permission-escalation"],
      { tools: ["search", "weather"], system_prompt_secret: true }
    );

    // Should detect tool list leak
    const toolLeaks = result.suites
      .flatMap((s) => s.results)
      .filter((r) => r.matchedDetectors.includes("tool-list-leak"));
    expect(toolLeaks.length).toBeGreaterThan(0);
  });
});
