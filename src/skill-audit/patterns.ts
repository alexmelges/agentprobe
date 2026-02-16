import type { SkillCategory, SkillSeverity } from "./types.js";

export interface PatternDef {
  id: string;
  category: SkillCategory;
  severity: SkillSeverity;
  name: string;
  pattern: RegExp;
  risk: string;
  /** Only match in these file extensions (empty = all) */
  extensions?: string[];
}

// ─── CREDENTIAL ACCESS (critical) ───────────────────────────────────

const credentialPatterns: PatternDef[] = [
  {
    id: "CRED-001",
    category: "credential-access",
    severity: "critical",
    name: "Hardcoded OpenAI API key",
    pattern: /sk-[a-zA-Z0-9]{20,}/,
    risk: "OpenAI API key exposed in plain text",
  },
  {
    id: "CRED-002",
    category: "credential-access",
    severity: "critical",
    name: "Hardcoded Anthropic API key",
    pattern: /sk-ant-[a-zA-Z0-9]{20,}/,
    risk: "Anthropic API key exposed in plain text",
  },
  {
    id: "CRED-003",
    category: "credential-access",
    severity: "critical",
    name: "Hardcoded GitHub token",
    pattern: /gh[ps]_[a-zA-Z0-9]{36}/,
    risk: "GitHub token exposed in plain text",
  },
  {
    id: "CRED-004",
    category: "credential-access",
    severity: "critical",
    name: "Hardcoded AWS key",
    pattern: /AKIA[A-Z0-9]{16}/,
    risk: "AWS access key exposed in plain text",
  },
  {
    id: "CRED-005",
    category: "credential-access",
    severity: "critical",
    name: "Hardcoded Slack token",
    pattern: /xox[bprs]-[a-zA-Z0-9-]+/,
    risk: "Slack token exposed in plain text",
  },
  {
    id: "CRED-006",
    category: "credential-access",
    severity: "critical",
    name: "Private key material",
    pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY/,
    risk: "Private key embedded in file",
  },
  {
    id: "CRED-007",
    category: "credential-access",
    severity: "high",
    name: "Password in assignment",
    pattern: /(?:password|passwd|pwd|secret|token|api_key|apikey|api[-_]?secret)\s*[:=]\s*["'][^"']{8,}["']/i,
    risk: "Credential appears to be hardcoded",
  },
  {
    id: "CRED-008",
    category: "credential-access",
    severity: "high",
    name: "Sensitive file reference",
    pattern: /(?:~\/\.ssh\/|~\/\.aws\/|~\/\.credentials|~\/\.env|~\/\.netrc|\.env\.local|\.env\.production)/,
    risk: "References sensitive credential file path",
  },
  {
    id: "CRED-009",
    category: "credential-access",
    severity: "high",
    name: "Environment variable harvesting",
    pattern: /process\.env\[|os\.environ\[|ENV\[|System\.getenv\(/,
    risk: "Reads environment variables (potential credential harvesting)",
    extensions: [".ts", ".js", ".py", ".rb", ".java"],
  },
  {
    id: "CRED-010",
    category: "credential-access",
    severity: "high",
    name: "Keychain/secret store access",
    pattern: /security\s+find-(?:generic|internet)-password|keytar|keyring|SecretService|Credential(?:Manager|Store)/i,
    risk: "Accesses system keychain or secret store",
  },
  {
    id: "CRED-011",
    category: "credential-access",
    severity: "critical",
    name: "JWT token",
    pattern: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\./,
    risk: "JWT token exposed in plain text",
  },
  {
    id: "CRED-012",
    category: "credential-access",
    severity: "critical",
    name: "Hardcoded Google API key",
    pattern: /AIza[a-zA-Z0-9_-]{35}/,
    risk: "Google API key exposed in plain text",
  },
];

// ─── DATA EXFILTRATION (critical) ───────────────────────────────────

const dataExfiltrationPatterns: PatternDef[] = [
  {
    id: "EXFIL-001",
    category: "data-exfiltration",
    severity: "critical",
    name: "Outbound HTTP to suspicious domain",
    pattern: /(?:https?:\/\/|curl\s+|wget\s+|fetch\(|axios\.|requests?\.).*(?:webhook\.site|requestbin|ngrok\.io|pipedream\.net|burpcollaborator|evil\.com|attacker\.com|exfil\.|leak\.)/i,
    risk: "Data may be exfiltrated to external server",
  },
  {
    id: "EXFIL-002",
    category: "data-exfiltration",
    severity: "high",
    name: "Base64 encoding before network call",
    pattern: /(?:btoa|Buffer\.from|base64\.b64encode|encode\('base64'\)).*(?:fetch|curl|wget|http|request)/is,
    risk: "Data encoded before transmission (exfiltration pattern)",
  },
  {
    id: "EXFIL-003",
    category: "data-exfiltration",
    severity: "critical",
    name: "Reads sensitive system file",
    pattern: /(?:readFile|open|cat|less|head|tail)\s*\(?.*(?:\/etc\/passwd|\/etc\/shadow|\.ssh\/id_|\.bash_history|\.zsh_history|chrome.*(?:Login Data|Cookies)|firefox.*(?:logins|cookies))/i,
    risk: "Attempts to read sensitive system or browser files",
  },
  {
    id: "EXFIL-004",
    category: "data-exfiltration",
    severity: "high",
    name: "DNS exfiltration pattern",
    pattern: /(?:dns|dig|nslookup|resolve)\s.*\$|(?:\.burpcollaborator\.net|\.oastify\.com|\.interact\.sh)/i,
    risk: "Potential DNS-based data exfiltration",
  },
  {
    id: "EXFIL-005",
    category: "data-exfiltration",
    severity: "high",
    name: "Clipboard access",
    pattern: /(?:pbcopy|pbpaste|xclip|xsel|clipboard|navigator\.clipboard|pyperclip)/i,
    risk: "Accesses system clipboard (may read/exfiltrate copied data)",
  },
  {
    id: "EXFIL-006",
    category: "data-exfiltration",
    severity: "high",
    name: "Image-based exfiltration",
    pattern: /!\[.*?\]\(https?:\/\/.*?\?.*(?:data|token|key|secret|prompt)=/i,
    risk: "Markdown image tag may exfiltrate data via URL parameters",
  },
];

// ─── INSTRUCTION INJECTION (high) ───────────────────────────────────

const instructionInjectionPatterns: PatternDef[] = [
  {
    id: "INJECT-001",
    category: "instruction-injection",
    severity: "high",
    name: "Hidden instruction in HTML comment",
    pattern: /<!--\s*(?:ignore|forget|disregard|override|new instructions|system prompt|you are now)/i,
    risk: "Hidden prompt injection in HTML/Markdown comment",
  },
  {
    id: "INJECT-002",
    category: "instruction-injection",
    severity: "high",
    name: "Prompt injection in tool description",
    pattern: /(?:description|help|usage)\s*[:=].*(?:ignore previous|forget your|disregard|override instructions|you are now|new role)/i,
    risk: "Prompt injection embedded in tool metadata",
  },
  {
    id: "INJECT-003",
    category: "instruction-injection",
    severity: "medium",
    name: "Zero-width character obfuscation",
    pattern: /[\u200B\u200C\u200D\u2060\uFEFF]{2,}/,
    risk: "Zero-width characters may hide instructions from human review",
  },
  {
    id: "INJECT-004",
    category: "instruction-injection",
    severity: "medium",
    name: "Base64-encoded instruction block",
    pattern: /(?:atob|decode|base64)\s*\(\s*["'](?:[A-Za-z0-9+/]{20,}={0,2})["']\s*\)/,
    risk: "Base64-encoded content may hide malicious instructions",
  },
  {
    id: "INJECT-005",
    category: "instruction-injection",
    severity: "high",
    name: "System prompt override attempt",
    pattern: /(?:system\s*prompt|system\s*message|system_prompt)\s*[:=].*(?:you are|your role|ignore|override|always|never)/i,
    risk: "Attempts to override agent system prompt",
  },
  {
    id: "INJECT-006",
    category: "instruction-injection",
    severity: "high",
    name: "Role hijacking in text content",
    pattern: /\[(?:SYSTEM|ADMIN|ROOT|ASSISTANT)\].*(?:ignore|forget|disregard|new instructions|override)/i,
    risk: "Fake role tag with injection payload",
  },
];

// ─── PERMISSION ESCALATION (high) ───────────────────────────────────

const permissionEscalationPatterns: PatternDef[] = [
  {
    id: "PERM-001",
    category: "permission-escalation",
    severity: "high",
    name: "Shell command execution",
    pattern: /(?:child_process|exec|execSync|spawn|spawnSync|system|popen|subprocess\.(?:run|call|Popen))\s*\(/,
    risk: "Executes arbitrary shell commands",
    extensions: [".ts", ".js", ".py", ".rb"],
  },
  {
    id: "PERM-002",
    category: "permission-escalation",
    severity: "critical",
    name: "Shell execution in script",
    pattern: /(?:eval|exec)\s+.*\$|`.*\$\(|sh\s+-c\s+/,
    risk: "Dynamic shell command execution",
    extensions: [".sh", ".bash", ".zsh"],
  },
  {
    id: "PERM-003",
    category: "permission-escalation",
    severity: "high",
    name: "File write outside workspace",
    pattern: /(?:writeFile|write|open\(|>)\s*["']?(?:\/(?:etc|usr|tmp|var)|~\/\.|\.\.\/\.\.\/)/,
    risk: "Writes files outside expected workspace directory",
  },
  {
    id: "PERM-004",
    category: "permission-escalation",
    severity: "high",
    name: "Network listener creation",
    pattern: /(?:createServer|\.listen\(|\.bind\(|socket\.socket|ServerSocket|net\.Listen)/,
    risk: "Creates network listener (potential backdoor)",
    extensions: [".ts", ".js", ".py", ".go", ".java"],
  },
  {
    id: "PERM-005",
    category: "permission-escalation",
    severity: "critical",
    name: "Sudo/admin elevation",
    pattern: /(?:sudo\s|runas\s|doas\s|pkexec\s|gsudo\s)/,
    risk: "Attempts privilege elevation via sudo or equivalent",
  },
  {
    id: "PERM-006",
    category: "permission-escalation",
    severity: "high",
    name: "Process spawning",
    pattern: /(?:fork\(|os\.fork|Process\.start|Runtime\.exec|ProcessBuilder)/,
    risk: "Spawns new processes",
    extensions: [".ts", ".js", ".py", ".java", ".go"],
  },
];

// ─── PERSISTENCE (medium) ───────────────────────────────────────────

const persistencePatterns: PatternDef[] = [
  {
    id: "PERSIST-001",
    category: "persistence",
    severity: "medium",
    name: "Cron job creation",
    pattern: /(?:crontab|cron\.d|systemctl\s+enable|launchctl\s+load|schtasks\s+\/create)/i,
    risk: "Creates scheduled task for persistence",
  },
  {
    id: "PERSIST-002",
    category: "persistence",
    severity: "high",
    name: "Startup script modification",
    pattern: /(?:\.bashrc|\.zshrc|\.profile|\.bash_profile|\.login|autostart|rc\.local|init\.d)/,
    risk: "Modifies startup scripts for persistence",
  },
  {
    id: "PERSIST-003",
    category: "persistence",
    severity: "medium",
    name: "Runtime package installation",
    pattern: /(?:npm\s+install|pip\s+install|gem\s+install|cargo\s+install|brew\s+install)\s/,
    risk: "Installs packages at runtime (supply chain risk)",
  },
  {
    id: "PERSIST-004",
    category: "persistence",
    severity: "medium",
    name: "Browser extension installation",
    pattern: /(?:chrome\.runtime|browser\.runtime|extensions\/|\.crx|\.xpi)/i,
    risk: "Interacts with browser extensions",
  },
  {
    id: "PERSIST-005",
    category: "persistence",
    severity: "high",
    name: "SSH authorized_keys modification",
    pattern: /(?:authorized_keys|\.ssh\/.*>>|ssh-keygen|ssh-copy-id)/,
    risk: "Modifies SSH authorized keys (persistent remote access)",
  },
];

// ─── OBFUSCATION (medium) ───────────────────────────────────────────

const obfuscationPatterns: PatternDef[] = [
  {
    id: "OBFUSC-001",
    category: "obfuscation",
    severity: "medium",
    name: "Dynamic code evaluation",
    pattern: /(?:eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["']|setInterval\s*\(\s*["'])/,
    risk: "Dynamic code evaluation can hide malicious behavior",
    extensions: [".ts", ".js", ".py"],
  },
  {
    id: "OBFUSC-002",
    category: "obfuscation",
    severity: "medium",
    name: "Hex-encoded string",
    pattern: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){4,}/i,
    risk: "Hex-encoded string may hide malicious content",
  },
  {
    id: "OBFUSC-003",
    category: "obfuscation",
    severity: "medium",
    name: "String concatenation obfuscation",
    pattern: /["'][a-z]{1,3}["']\s*\+\s*["'][a-z]{1,3}["']\s*\+\s*["'][a-z]{1,3}["']\s*\+\s*["'][a-z]{1,3}["']/i,
    risk: "Excessive string concatenation may hide keywords",
  },
  {
    id: "OBFUSC-004",
    category: "obfuscation",
    severity: "low",
    name: "Minified code block",
    pattern: /^[^\n]{500,}$/m,
    risk: "Very long single line suggests minified/obfuscated code",
  },
  {
    id: "OBFUSC-005",
    category: "obfuscation",
    severity: "medium",
    name: "Unicode escape obfuscation",
    pattern: /\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){3,}/i,
    risk: "Unicode escapes may hide malicious content",
  },
];

export const ALL_PATTERNS: PatternDef[] = [
  ...credentialPatterns,
  ...dataExfiltrationPatterns,
  ...instructionInjectionPatterns,
  ...permissionEscalationPatterns,
  ...persistencePatterns,
  ...obfuscationPatterns,
];
