import type { Adapter, AdapterRequest, AdapterResponse, ToolCallInfo } from "./types.js";
import type { AgentConfig } from "../config.js";

export function createAnthropicAdapter(config: AgentConfig): Adapter {
  const model = config.model ?? "claude-sonnet-4-5-20250929";

  return {
    name: "anthropic",
    async send(request: AdapterRequest): Promise<AdapterResponse> {
      let Anthropic;
      try {
        Anthropic = (await import("@anthropic-ai/sdk")).default;
      } catch {
        throw new Error(
          'Anthropic SDK not installed. Run: npm install @anthropic-ai/sdk'
        );
      }

      const client = new Anthropic({
        apiKey: config.api_key || process.env.ANTHROPIC_API_KEY,
      });

      const message = await client.messages.create({
        model,
        max_tokens: 1000,
        ...(config.system ? { system: config.system } : {}),
        messages: [{ role: "user", content: request.input }],
        temperature: 0,
      });

      let content = "";
      const toolCalls: ToolCallInfo[] = [];

      for (const block of message.content) {
        if (block.type === "text") {
          content += (block as any).text;
        } else if (block.type === "tool_use") {
          toolCalls.push({
            name: (block as any).name,
            arguments: (block as any).input as Record<string, unknown>,
          });
        }
      }

      return {
        content,
        tool_calls: toolCalls.length > 0 ? toolCalls : undefined,
        raw: message,
      };
    },
  };
}
