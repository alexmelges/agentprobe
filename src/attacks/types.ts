export type SuiteName =
  | "prompt-injection"
  | "data-exfiltration"
  | "permission-escalation"
  | "output-manipulation"
  | "jailbreak";

export type Severity = "critical" | "high" | "medium" | "low";

export const ALL_SUITES: SuiteName[] = [
  "prompt-injection",
  "data-exfiltration",
  "permission-escalation",
  "output-manipulation",
];

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export interface AttackPattern {
  id: string;
  suite: SuiteName;
  name: string;
  description: string;
  input: string;
  severity: Severity;
  detectors: string[];
}

export interface AttackResult {
  attack: AttackPattern;
  vulnerable: boolean;
  response: string;
  duration: number;
  matchedDetectors: string[];
  error?: string;
}

export interface SuiteResult {
  suite: SuiteName;
  results: AttackResult[];
  total: number;
  passed: number;
  failed: number;
}

export interface ProbeResult {
  suites: SuiteResult[];
  totalAttacks: number;
  totalPassed: number;
  totalFailed: number;
  duration: number;
  target: string;
}
