import { describe, it, expect } from "vitest";
import { getAttacks, getAllAttacks } from "../../src/attacks/registry.js";

describe("attack registry", () => {
  it("returns prompt injection attacks", () => {
    const attacks = getAttacks("prompt-injection");
    expect(attacks.length).toBeGreaterThanOrEqual(50);
    expect(attacks[0].suite).toBe("prompt-injection");
  });

  it("returns data exfiltration attacks", () => {
    const attacks = getAttacks("data-exfiltration");
    expect(attacks.length).toBeGreaterThanOrEqual(20);
    expect(attacks[0].suite).toBe("data-exfiltration");
  });

  it("returns permission escalation attacks", () => {
    const attacks = getAttacks("permission-escalation");
    expect(attacks.length).toBeGreaterThanOrEqual(10);
    expect(attacks[0].suite).toBe("permission-escalation");
  });

  it("returns output manipulation attacks", () => {
    const attacks = getAttacks("output-manipulation");
    expect(attacks.length).toBeGreaterThanOrEqual(10);
    expect(attacks[0].suite).toBe("output-manipulation");
  });

  it("returns empty for jailbreak (future)", () => {
    const attacks = getAttacks("jailbreak");
    expect(attacks).toEqual([]);
  });

  it("combines all suites", () => {
    const all = getAllAttacks([
      "prompt-injection",
      "data-exfiltration",
      "permission-escalation",
      "output-manipulation",
    ]);
    expect(all.length).toBeGreaterThanOrEqual(90);
  });

  it("each attack has required fields", () => {
    const all = getAllAttacks([
      "prompt-injection",
      "data-exfiltration",
      "permission-escalation",
      "output-manipulation",
    ]);
    for (const a of all) {
      expect(a.id).toBeTruthy();
      expect(a.suite).toBeTruthy();
      expect(a.name).toBeTruthy();
      expect(a.input).toBeTruthy();
      expect(a.severity).toMatch(/^(critical|high|medium|low)$/);
      expect(a.detectors.length).toBeGreaterThan(0);
    }
  });

  it("all attack IDs are unique", () => {
    const all = getAllAttacks([
      "prompt-injection",
      "data-exfiltration",
      "permission-escalation",
      "output-manipulation",
    ]);
    const ids = all.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
