export type SkillSeverity = "critical" | "high" | "medium" | "low";

export type SkillCategory =
  | "credential-access"
  | "data-exfiltration"
  | "instruction-injection"
  | "permission-escalation"
  | "persistence"
  | "obfuscation";

export interface SkillFinding {
  id: string;
  category: SkillCategory;
  severity: SkillSeverity;
  name: string;
  description: string;
  file: string;
  line: number;
  match: string;
  risk: string;
}

export interface SkillAuditResult {
  path: string;
  filesScanned: number;
  filesSkipped: number;
  findings: SkillFinding[];
  duration: number;
}
