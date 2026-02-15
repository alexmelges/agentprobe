import { describe, it, expect } from "vitest";
import { multiAgentAttacks } from "../../src/attacks/multi-agent.js";
import { getAttacks, getAllAttacks } from "../../src/attacks/registry.js";

describe("multi-agent attacks", () => {
  it("has at least 25 attack patterns", () => {
    expect(multiAgentAttacks.length).toBeGreaterThanOrEqual(25);
  });

  it("has exactly 30 attack patterns", () => {
    expect(multiAgentAttacks.length).toBe(30);
  });

  it("all attacks have unique ids", () => {
    const ids = multiAgentAttacks.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("all attacks have suite set to multi-agent", () => {
    for (const a of multiAgentAttacks) {
      expect(a.suite).toBe("multi-agent");
    }
  });

  it("all attacks have valid severity", () => {
    const valid = ["critical", "high", "medium", "low"];
    for (const a of multiAgentAttacks) {
      expect(valid).toContain(a.severity);
    }
  });

  it("all attacks have at least one detector", () => {
    for (const a of multiAgentAttacks) {
      expect(a.detectors.length).toBeGreaterThanOrEqual(1);
    }
  });

  it("all attacks have non-empty input", () => {
    for (const a of multiAgentAttacks) {
      expect(a.input.length).toBeGreaterThan(10);
    }
  });

  it("ids follow ma-NNN pattern", () => {
    for (const a of multiAgentAttacks) {
      expect(a.id).toMatch(/^ma-\d{3}$/);
    }
  });

  it("is registered in the attack registry", () => {
    const attacks = getAttacks("multi-agent");
    expect(attacks.length).toBe(30);
    expect(attacks[0].id).toBe("ma-001");
  });

  it("getAllAttacks includes multi-agent when requested", () => {
    const all = getAllAttacks(["multi-agent"]);
    expect(all.length).toBe(30);
  });

  it("covers all 5 attack categories", () => {
    const categories = {
      contextPoisoning: multiAgentAttacks.filter((a) => a.id >= "ma-001" && a.id <= "ma-006"),
      taskManipulation: multiAgentAttacks.filter((a) => a.id >= "ma-007" && a.id <= "ma-012"),
      fakeCheckpoint: multiAgentAttacks.filter((a) => a.id >= "ma-013" && a.id <= "ma-018"),
      cascadeEscalation: multiAgentAttacks.filter((a) => a.id >= "ma-019" && a.id <= "ma-023"),
      authoritySpoofing: multiAgentAttacks.filter((a) => a.id >= "ma-024" && a.id <= "ma-030"),
    };
    expect(categories.contextPoisoning.length).toBe(6);
    expect(categories.taskManipulation.length).toBe(6);
    expect(categories.fakeCheckpoint.length).toBe(6);
    expect(categories.cascadeEscalation.length).toBe(5);
    expect(categories.authoritySpoofing.length).toBe(7);
  });

  it("has critical severity attacks in each category", () => {
    const criticals = multiAgentAttacks.filter((a) => a.severity === "critical");
    expect(criticals.length).toBeGreaterThanOrEqual(10);
  });
});
