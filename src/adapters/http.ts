import type { Adapter, AdapterRequest, AdapterResponse } from "./types.js";
import type { AgentConfig } from "../config.js";

function extractByPath(obj: unknown, path: string): unknown {
  const parts = path.replace(/\[(\d+)\]/g, ".$1").split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

export function createHttpAdapter(config: AgentConfig): Adapter {
  const endpoint = config.endpoint!;
  const method = config.method ?? "POST";
  const headers = config.headers ?? {};
  const requestTemplate = config.request?.template ?? '{"message": "{{input}}"}';
  const responsePath = config.response?.path ?? "choices[0].message.content";

  return {
    name: "http",
    async send(request: AdapterRequest): Promise<AdapterResponse> {
      const body = requestTemplate.replace(/\{\{input\}\}/g, JSON.stringify(request.input).slice(1, -1));

      const res = await fetch(endpoint, {
        method,
        headers: {
          "Content-Type": "application/json",
          ...headers,
        },
        body,
      });

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }

      const json = await res.json();
      const content = extractByPath(json, responsePath);

      return {
        content: typeof content === "string" ? content : JSON.stringify(content),
        raw: json,
      };
    },
  };
}
