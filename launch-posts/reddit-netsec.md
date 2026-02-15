# AgentProbe — adversarial security testing for LLM-based agents

Open-sourced a CLI tool for pre-deploy security testing of AI agents. Think of it as a Nuclei-style scanner but for prompt injection, data exfil, privilege escalation, and multi-agent attack surfaces.

**The problem:** Most AI security tools are runtime guardrails (Lakera, Rebuff, NeMo Guardrails). They're your WAF. But nobody was doing the pentest — testing agents *before* deployment to find what the guardrails miss.

**134 attack patterns across 5 categories:**
- Prompt injection (52 patterns) — jailbreaks, role hijacking, instruction override
- Data exfiltration (25) — PII extraction, context leaking, training data extraction
- Permission escalation (15) — tool abuse, scope creep, auth bypass
- Output manipulation (12) — format injection, encoding tricks
- Multi-agent attacks (30) — delegation abuse, trust chain exploitation, cross-agent injection

**Key design decisions:**
- Detection is rule-based, not LLM-based (deterministic, no false positive drift)
- SARIF 2.1.0 output → integrates with GitHub Advanced Security
- Designed for CI pipelines, not just manual runs

```bash
npx @alexmelges/agentprobe --demo
```

GitHub: https://github.com/alexmelges/agentprobe
MIT licensed.

Interested in community-contributed attack templates (Nuclei model). PRs welcome.
