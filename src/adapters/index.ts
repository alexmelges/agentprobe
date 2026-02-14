import type { Adapter } from "./types.js";
import type { AgentConfig } from "../config.js";
import { createHttpAdapter } from "./http.js";
import { createOpenAIAdapter } from "./openai.js";
import { createAnthropicAdapter } from "./anthropic.js";

export function createAdapter(config: AgentConfig): Adapter {
  switch (config.type) {
    case "http":
      return createHttpAdapter(config);
    case "openai":
      return createOpenAIAdapter(config);
    case "anthropic":
      return createAnthropicAdapter(config);
    case "custom":
      throw new Error(
        "Custom adapters are not yet supported. Use http, openai, or anthropic."
      );
    default:
      throw new Error(`Unknown agent type: ${config.type}`);
  }
}

export type { Adapter, AdapterRequest, AdapterResponse, ToolCallInfo } from "./types.js";
