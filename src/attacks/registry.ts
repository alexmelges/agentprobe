import type { AttackPattern, SuiteName } from "./types.js";
import { promptInjectionAttacks } from "./prompt-injection.js";
import { dataExfiltrationAttacks } from "./data-exfiltration.js";
import { permissionEscalationAttacks } from "./permission-escalation.js";
import { outputManipulationAttacks } from "./output-manipulation.js";
import { multiAgentAttacks } from "./multi-agent.js";
import { githubActionsAttacks } from "./github-actions.js";

const registry: Record<SuiteName, AttackPattern[]> = {
  "prompt-injection": promptInjectionAttacks,
  "data-exfiltration": dataExfiltrationAttacks,
  "permission-escalation": permissionEscalationAttacks,
  "output-manipulation": outputManipulationAttacks,
  "multi-agent": multiAgentAttacks,
  "github-actions": githubActionsAttacks,
  jailbreak: [], // future
};

export function getAttacks(suite: SuiteName): AttackPattern[] {
  return registry[suite] ?? [];
}

export function getAllAttacks(suites: SuiteName[]): AttackPattern[] {
  return suites.flatMap((s) => getAttacks(s));
}
