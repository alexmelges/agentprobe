import type { Adapter, AdapterRequest, AdapterResponse, ToolCallInfo } from "./types.js";
import type { AgentConfig } from "../config.js";

export function createOpenAIAdapter(config: AgentConfig): Adapter {
  const model = config.model ?? "gpt-4o-mini";

  return {
    name: "openai",
    async send(request: AdapterRequest): Promise<AdapterResponse> {
      let OpenAI;
      try {
        OpenAI = (await import("openai")).default;
      } catch {
        throw new Error(
          'OpenAI SDK not installed. Run: npm install openai'
        );
      }

      const client = new OpenAI({
        apiKey: config.api_key || process.env.OPENAI_API_KEY,
      });

      const messages: any[] = [];
      if (config.system) {
        messages.push({ role: "system", content: config.system });
      }
      messages.push({ role: "user", content: request.input });

      const completion = await client.chat.completions.create({
        model,
        messages,
        temperature: 0,
        max_tokens: 1000,
      });

      const choice = completion.choices[0];
      const content = choice.message.content ?? "";
      const toolCalls: ToolCallInfo[] = (choice.message.tool_calls ?? []).map(
        (tc: any) => ({
          name: tc.function.name,
          arguments: JSON.parse(tc.function.arguments),
        })
      );

      return {
        content,
        tool_calls: toolCalls.length > 0 ? toolCalls : undefined,
        raw: completion,
      };
    },
  };
}
