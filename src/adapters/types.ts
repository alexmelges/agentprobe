export interface AdapterRequest {
  input: string;
}

export interface AdapterResponse {
  content: string;
  tool_calls?: ToolCallInfo[];
  raw?: unknown;
}

export interface ToolCallInfo {
  name: string;
  arguments: Record<string, unknown>;
}

export interface Adapter {
  name: string;
  send(request: AdapterRequest): Promise<AdapterResponse>;
}
