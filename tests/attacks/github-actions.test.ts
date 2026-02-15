import { describe, it, expect } from "vitest";
import { githubActionsAttacks } from "../../src/attacks/github-actions.js";
import { getAttacks, getAllAttacks } from "../../src/attacks/registry.js";

describe("github-actions attacks", () => {
  it("has exactly 30 attack patterns", () => {
    expect(githubActionsAttacks.length).toBe(30);
  });

  it("all attacks have unique ids", () => {
    const ids = githubActionsAttacks.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("all attacks have suite set to github-actions", () => {
    for (const a of githubActionsAttacks) {
      expect(a.suite).toBe("github-actions");
    }
  });

  it("all attacks have valid severity", () => {
    const valid = ["critical", "high", "medium", "low"];
    for (const a of githubActionsAttacks) {
      expect(valid).toContain(a.severity);
    }
  });

  it("all attacks have at least one detector", () => {
    for (const a of githubActionsAttacks) {
      expect(a.detectors.length).toBeGreaterThanOrEqual(1);
    }
  });

  it("all attacks have non-empty input", () => {
    for (const a of githubActionsAttacks) {
      expect(a.input.length).toBeGreaterThan(10);
    }
  });

  it("ids follow ga-NNN pattern", () => {
    for (const a of githubActionsAttacks) {
      expect(a.id).toMatch(/^ga-\d{3}$/);
    }
  });

  it("is registered in the attack registry", () => {
    const attacks = getAttacks("github-actions");
    expect(attacks.length).toBe(30);
    expect(attacks[0].id).toBe("ga-001");
  });

  it("getAllAttacks includes github-actions when requested", () => {
    const all = getAllAttacks(["github-actions"]);
    expect(all.length).toBe(30);
  });

  it("covers all 6 attack categories", () => {
    const categories = {
      issueTitleBody: githubActionsAttacks.filter((a) => a.id >= "ga-001" && a.id <= "ga-008"),
      prDescription: githubActionsAttacks.filter((a) => a.id >= "ga-009" && a.id <= "ga-014"),
      commentPoisoning: githubActionsAttacks.filter((a) => a.id >= "ga-015" && a.id <= "ga-019"),
      commitMessage: githubActionsAttacks.filter((a) => a.id >= "ga-020" && a.id <= "ga-023"),
      codeContent: githubActionsAttacks.filter((a) => a.id >= "ga-024" && a.id <= "ga-027"),
      metadata: githubActionsAttacks.filter((a) => a.id >= "ga-028" && a.id <= "ga-030"),
    };
    expect(categories.issueTitleBody.length).toBe(8);
    expect(categories.prDescription.length).toBe(6);
    expect(categories.commentPoisoning.length).toBe(5);
    expect(categories.commitMessage.length).toBe(4);
    expect(categories.codeContent.length).toBe(4);
    expect(categories.metadata.length).toBe(3);
  });

  it("has critical severity attacks", () => {
    const criticals = githubActionsAttacks.filter((a) => a.severity === "critical");
    expect(criticals.length).toBeGreaterThanOrEqual(8);
  });

  it("uses github-specific detectors", () => {
    const allDetectors = githubActionsAttacks.flatMap((a) => a.detectors);
    expect(allDetectors).toContain("github-label-manipulation");
    expect(allDetectors).toContain("github-merge-manipulation");
    expect(allDetectors).toContain("github-permission-change");
    expect(allDetectors).toContain("github-workflow-trigger");
  });
});
