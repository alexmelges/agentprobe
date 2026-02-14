import { describe, it, expect } from "vitest";
import { validateConfig } from "../src/config.js";

describe("validateConfig", () => {
  it("validates a minimal http config", () => {
    const config = validateConfig({
      agent: { type: "http", endpoint: "http://localhost:3000/api" },
      suites: ["prompt-injection"],
    });
    expect(config.agent.type).toBe("http");
    expect(config.suites).toEqual(["prompt-injection"]);
  });

  it("validates an openai config", () => {
    const config = validateConfig({
      agent: { type: "openai", model: "gpt-4o-mini" },
      suites: ["data-exfiltration"],
    });
    expect(config.agent.type).toBe("openai");
  });

  it("validates an anthropic config", () => {
    const config = validateConfig({
      agent: { type: "anthropic", model: "claude-sonnet-4-5-20250929" },
      suites: ["permission-escalation"],
    });
    expect(config.agent.type).toBe("anthropic");
  });

  it("validates config with all suites", () => {
    const config = validateConfig({
      agent: { type: "http", endpoint: "http://localhost:3000" },
      suites: ["prompt-injection", "data-exfiltration", "permission-escalation", "output-manipulation"],
    });
    expect(config.suites).toHaveLength(4);
  });

  it("validates config with boundaries", () => {
    const config = validateConfig({
      agent: { type: "http", endpoint: "http://localhost:3000" },
      suites: ["prompt-injection"],
      boundaries: {
        system_prompt_secret: true,
        tools: ["search", "weather"],
        sensitive_topics: ["medical"],
      },
    });
    expect(config.boundaries?.system_prompt_secret).toBe(true);
    expect(config.boundaries?.tools).toEqual(["search", "weather"]);
  });

  it("throws on missing agent", () => {
    expect(() => validateConfig({ suites: ["prompt-injection"] })).toThrow("agent");
  });

  it("throws on missing agent type", () => {
    expect(() =>
      validateConfig({ agent: {}, suites: ["prompt-injection"] })
    ).toThrow("agent.type");
  });

  it("throws on invalid agent type", () => {
    expect(() =>
      validateConfig({ agent: { type: "invalid" }, suites: ["prompt-injection"] })
    ).toThrow("Invalid agent.type");
  });

  it("throws on missing endpoint for http type", () => {
    expect(() =>
      validateConfig({ agent: { type: "http" }, suites: ["prompt-injection"] })
    ).toThrow("endpoint");
  });

  it("throws on empty suites", () => {
    expect(() =>
      validateConfig({ agent: { type: "http", endpoint: "http://localhost" }, suites: [] })
    ).toThrow("at least one suite");
  });

  it("throws on invalid suite name", () => {
    expect(() =>
      validateConfig({
        agent: { type: "http", endpoint: "http://localhost" },
        suites: ["fake-suite"],
      })
    ).toThrow("Invalid suite");
  });

  it("throws on non-object config", () => {
    expect(() => validateConfig(null)).toThrow("YAML object");
    expect(() => validateConfig("string")).toThrow("YAML object");
  });

  it("sets default method to POST", () => {
    const config = validateConfig({
      agent: { type: "http", endpoint: "http://localhost:3000" },
      suites: ["prompt-injection"],
    });
    expect(config.agent.method).toBe("POST");
  });
});
