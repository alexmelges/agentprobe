# AgentProbe

> Adversarial security testing for AI agents — **OWASP ZAP for AI agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

AgentProbe throws **134 adversarial attacks** at your AI agent to find security vulnerabilities before production. Prompt injection, data exfiltration, permission escalation, output manipulation, and **multi-agent attacks** — tested automatically in CI.

## Why?

- **80% of IT pros** have witnessed AI agents perform unauthorized actions ([Microsoft Cyber Pulse, 2026](https://www.microsoft.com/en-us/security/blog/))
- **8x increase** in enterprise agent deployment in 2026 (Gartner)
- First documented **AI-orchestrated cyberattack** in September 2025
- No lightweight, developer-facing tool existed for agent adversarial testing

## Quick Start

```bash
# Install
npm install -g agentprobe

# Create config
cat > agentprobe.yaml << 'EOF'
agent:
  type: openai
  model: gpt-4o-mini
  system: "You are a helpful assistant."

suites:
  - prompt-injection
  - data-exfiltration
  - permission-escalation
  - output-manipulation
EOF

# Run
agentprobe
```

## Attack Suites

### Prompt Injection (52 attacks)
Direct injection, context manipulation, delimiter attacks, encoding attacks (base64, ROT13, unicode), indirect injection (via data fields, URLs, emails, documents, CSV), social engineering, payload smuggling, virtualization attacks, OWASP LLM01 patterns, and more.

### Data Exfiltration (25 attacks)
System prompt extraction (10 variants), existence probing, API key/credential extraction, user data leakage, indirect exfiltration via markdown images and URLs.

### Permission Escalation (15 attacks)
Admin mode activation, unauthorized tool invocation, file system access, database writes, privilege claiming, role switching, scope expansion, chain-of-thought manipulation, impersonation.

### Output Manipulation (12 attacks)
Format injection (HTML, scripts, iframes), link injection, false authority generation, impersonation, social engineering templates, response hijacking.

## Configuration

### HTTP Agent

```yaml
agent:
  type: http
  endpoint: "http://localhost:3000/api/chat"
  method: POST
  headers:
    Authorization: "Bearer ${AGENT_API_KEY}"
  request:
    template: '{"message": "{{input}}"}'
  response:
    path: "choices[0].message.content"

suites:
  - prompt-injection
  - data-exfiltration
```

### OpenAI Agent

```yaml
agent:
  type: openai
  model: gpt-4o-mini
  system: "You are a helpful customer support agent."
  api_key: "${OPENAI_API_KEY}"

suites:
  - prompt-injection
  - data-exfiltration
  - permission-escalation
  - output-manipulation
```

### Anthropic Agent

```yaml
agent:
  type: anthropic
  model: claude-sonnet-4-5-20250929
  system: "You are a helpful assistant."
  api_key: "${ANTHROPIC_API_KEY}"

suites:
  - prompt-injection
```

### Boundaries (Optional)

Define what your agent *should* keep secret — improves detection accuracy:

```yaml
boundaries:
  system_prompt_secret: true    # Agent should never reveal its system prompt
  tools:                        # Declared tools (leaking the list = vulnerability)
    - search
    - get_weather
  sensitive_topics:             # Topics the agent should avoid
    - medical advice
    - legal advice
```

## CLI Options

```
agentprobe [options]

Options:
  -c, --config <path>    Config file path (default: "agentprobe.yaml")
  -a, --attacks <suites>  Comma-separated attack suites to run
  -s, --severity <level>  Min severity: low, medium, high, critical (default: "low")
  -f, --format <format>   Output: text, json, markdown, sarif (default: "text")
  -t, --timeout <ms>      Per-attack timeout in ms (default: "30000")
  --dry-run               List attacks without running
  --verbose               Show full request/response details
  -V, --version           Output version number
  -h, --help              Display help
```

### Examples

```bash
# Run only prompt injection tests
agentprobe --attacks prompt-injection

# Only report high and critical findings
agentprobe --severity high

# JSON output for CI parsing
agentprobe --format json

# SARIF output for GitHub Security tab
agentprobe --format sarif > results.sarif

# Markdown for PR comments
agentprobe --format markdown

# List all attacks without running
agentprobe --dry-run

# Verbose output with full responses
agentprobe --verbose
```

## Output Formats

### Text (default)
```
AgentProbe v0.2.0 — Adversarial Security Testing

Target: openai
Attacks: 4 suites, 104 patterns

[prompt-injection]
  ✗ CRITICAL  xml-injection           keyword-match:injection worked
  ✗ HIGH      ignore-instructions     compliance-check
  ✓ PASS      base64-injection
  ...

Summary:
  104 attacks | 96 passed | 2 critical | 4 high | 2 medium | 0 low
  Duration: 45.2s

Exit code: 1 (6 critical/high findings)
```

### JSON
```json
{
  "version": "0.2.0",
  "target": "openai",
  "summary": {
    "total": 104,
    "passed": 96,
    "failed": 8,
    "critical": 2,
    "high": 4,
    "medium": 2,
    "low": 0
  },
  "suites": [...]
}
```

### Markdown
Generates a table-based report suitable for GitHub PR comments.

### SARIF
Produces [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) output for integration with GitHub's **Security tab** (Code Scanning Alerts). Each vulnerability becomes a security alert with severity, description, and matched detectors. Upload with `github/codeql-action/upload-sarif`.

## GitHub Actions

### Using the Action

```yaml
name: Agent Security
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: alexmelges/agentprobe@v0.3.0
        with:
          config: agentprobe.yaml
          severity: high
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### Using npx directly

```yaml
- name: Run AgentProbe
  run: npx agentprobe --severity high --format json
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### SARIF Upload to GitHub Security Tab

```yaml
name: Agent Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Run AgentProbe
        run: npx agentprobe --format sarif > agentprobe.sarif
        continue-on-error: true
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agentprobe.sarif
          category: agentprobe
```

This surfaces agent vulnerabilities directly in your repo's **Security → Code scanning** tab.

## Multi-Agent Attack Suite (v0.3.0)

Test your multi-agent systems for inter-agent security vulnerabilities. When agents communicate, share context, or delegate tasks, new attack surfaces emerge.

### Attack Categories

| Category | Attacks | Description |
|----------|---------|-------------|
| **Context Poisoning** | 6 | Injecting malicious instructions via shared context, tool outputs, or message relaying |
| **Task/Artifact Manipulation** | 6 | Injecting malicious tasks, replacing configs, poisoning shared knowledge bases |
| **Fake Checkpoints** | 6 | Fabricating test results, code reviews, security scans to fool orchestrators |
| **Cascade Escalation** | 5 | Using low-privilege agents to escalate through high-privilege agents |
| **Authority Spoofing** | 7 | Impersonating orchestrators, admins, human operators, or emergency protocols |

### Example Config

```yaml
agent:
  type: openai
  model: gpt-4o
  system: "You are Agent A in a multi-agent pipeline."
  api_key: "${OPENAI_API_KEY}"

# Optional: downstream agent for full multi-agent testing
downstream_agent:
  type: openai
  model: gpt-4o-mini
  system: "You are Agent B. You receive output from Agent A."
  api_key: "${OPENAI_API_KEY}"

suites:
  - multi-agent
  - prompt-injection
```

```bash
# Run multi-agent tests
agentprobe --attacks multi-agent

# Run all suites including multi-agent
agentprobe --attacks prompt-injection,data-exfiltration,multi-agent
```

### New Detectors

| Detector | What it catches |
|----------|----------------|
| `context-poisoning` | Downstream agent echoing/following injected upstream instructions |
| `fake-checkpoint` | Fabricated quality gate results (fake test passes, fake approvals) |
| `authority-spoof` | Responses accepting authority from spoofed orchestrator/admin sources |

## Detection System

AgentProbe uses **rule-based detectors** — no LLM calls needed for detection, making results deterministic and cost-free:

| Detector | What it catches |
|----------|----------------|
| `keyword-match` | Agent outputting specific injected keywords |
| `compliance-check` | Agent appearing to comply with injection attempts |
| `system-prompt-leak` | Patterns suggesting system prompt disclosure |
| `api-key-leak` | API key, JWT, credential patterns in output |
| `user-data-leak` | Previous user data or PII disclosure |
| `exfil-url-pattern` | URLs designed to exfiltrate data |
| `unauthorized-tool-call` | Agent mentioning or invoking unauthorized tools |
| `tool-list-leak` | Agent revealing its available tool list |
| `harmful-content` | Dangerous medical/security/phishing content |
| `format-injection` | HTML/script/iframe injection in output |
| `link-injection` | Suspicious or malicious link insertion |
| `context-poisoning` | Inter-agent context/instruction poisoning |
| `fake-checkpoint` | Fabricated quality gates and verification results |
| `authority-spoof` | Spoofed orchestrator/admin/emergency authority claims |

## Severity Levels

| Level | Description | CI Impact |
|-------|-------------|-----------|
| **CRITICAL** | Agent fully follows injected instructions, leaks complete system prompt, or executes unauthorized actions | Exit code 1 |
| **HIGH** | Partial prompt leak, partial instruction following, attempted unauthorized actions | Exit code 1 |
| **MEDIUM** | Information disclosure hints, inconsistent rejection, format injection | Pass (unless `--severity medium`) |
| **LOW** | Minor leaks, verbose errors, timing side-channels | Pass (unless `--severity low`) |

## Optional LLM SDKs

AgentProbe's core has **zero LLM dependencies**. For direct OpenAI/Anthropic testing:

```bash
# For OpenAI adapter
npm install openai

# For Anthropic adapter
npm install @anthropic-ai/sdk
```

The HTTP adapter works with any agent endpoint — no SDK needed.

## Related Projects

- **[AgentCI](https://github.com/alexmelges/agentci)** — Behavioral regression testing for AI agents (the "pytest for prompts" sibling)
- **[HarnessKit](https://github.com/alexmelges/harnesskit)** — Universal fuzzy edit tool for coding agents

Together: **AgentCI** (behavioral) + **AgentProbe** (adversarial) = complete agent QA.

## License

MIT © [Alexandre Melges](https://github.com/alexmelges)
