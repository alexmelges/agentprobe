import { readFileSync, existsSync } from "node:fs";
import { parse } from "yaml";
import type { SuiteName } from "./attacks/types.js";

export interface AgentConfig {
  type: "http" | "openai" | "anthropic" | "custom";
  endpoint?: string;
  method?: string;
  headers?: Record<string, string>;
  request?: {
    template: string;
  };
  response?: {
    path: string;
  };
  model?: string;
  system?: string;
  api_key?: string;
}

export interface BoundariesConfig {
  system_prompt_secret?: boolean;
  tools?: string[];
  sensitive_topics?: string[];
}

export interface ProbeConfig {
  agent: AgentConfig;
  suites: SuiteName[];
  boundaries?: BoundariesConfig;
}

function substituteEnvVars(value: string): string {
  return value.replace(/\$\{(\w+)\}/g, (_, name) => {
    return process.env[name] ?? "";
  });
}

function substituteEnvVarsDeep(obj: unknown): unknown {
  if (typeof obj === "string") {
    return substituteEnvVars(obj);
  }
  if (Array.isArray(obj)) {
    return obj.map(substituteEnvVarsDeep);
  }
  if (obj !== null && typeof obj === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = substituteEnvVarsDeep(value);
    }
    return result;
  }
  return obj;
}

const VALID_TYPES = ["http", "openai", "anthropic", "custom"];
const VALID_SUITES: SuiteName[] = [
  "prompt-injection",
  "data-exfiltration",
  "permission-escalation",
  "output-manipulation",
  "jailbreak",
];

export function validateConfig(raw: unknown): ProbeConfig {
  if (!raw || typeof raw !== "object") {
    throw new Error("Config must be a YAML object");
  }

  const config = raw as Record<string, unknown>;

  // Validate agent section
  if (!config.agent || typeof config.agent !== "object") {
    throw new Error("Config must have an 'agent' section");
  }

  const agent = config.agent as Record<string, unknown>;

  if (!agent.type || typeof agent.type !== "string") {
    throw new Error("agent.type is required (http | openai | anthropic | custom)");
  }
  if (!VALID_TYPES.includes(agent.type)) {
    throw new Error(
      `Invalid agent.type "${agent.type}". Must be one of: ${VALID_TYPES.join(", ")}`
    );
  }

  if (agent.type === "http") {
    if (!agent.endpoint || typeof agent.endpoint !== "string") {
      throw new Error("agent.endpoint is required for HTTP agents");
    }
  }

  // Validate suites
  if (!Array.isArray(config.suites) || config.suites.length === 0) {
    throw new Error("Config must have at least one suite");
  }

  for (const suite of config.suites) {
    if (!VALID_SUITES.includes(suite as SuiteName)) {
      throw new Error(
        `Invalid suite "${suite}". Must be one of: ${VALID_SUITES.join(", ")}`
      );
    }
  }

  // Build validated config
  const result: ProbeConfig = {
    agent: {
      type: agent.type as AgentConfig["type"],
      endpoint: agent.endpoint as string | undefined,
      method: (agent.method as string) ?? "POST",
      headers: agent.headers as Record<string, string> | undefined,
      request: agent.request as { template: string } | undefined,
      response: agent.response as { path: string } | undefined,
      model: agent.model as string | undefined,
      system: agent.system as string | undefined,
      api_key: agent.api_key as string | undefined,
    },
    suites: config.suites as SuiteName[],
  };

  if (config.boundaries && typeof config.boundaries === "object") {
    const b = config.boundaries as Record<string, unknown>;
    result.boundaries = {
      system_prompt_secret: b.system_prompt_secret as boolean | undefined,
      tools: b.tools as string[] | undefined,
      sensitive_topics: b.sensitive_topics as string[] | undefined,
    };
  }

  return result;
}

export function loadConfig(configPath: string): ProbeConfig {
  if (!existsSync(configPath)) {
    throw new Error(`Config file not found: ${configPath}`);
  }

  const raw = readFileSync(configPath, "utf-8");
  const parsed = parse(raw);
  const substituted = substituteEnvVarsDeep(parsed);

  return validateConfig(substituted);
}
