# AgentProbe — Pentest your AI agents before attackers do

I built a CLI tool that runs 134 adversarial attack patterns against your AI agents — prompt injection, data exfiltration, permission escalation, output manipulation, and multi-agent attacks.

**Why?** Tools like Lakera and Rebuff are runtime WAFs. AgentProbe is your pre-deploy pentest. You run it in CI, find vulnerabilities before shipping, and get results in SARIF format that shows up in GitHub's Security tab.

**What it does:**
- 134 attack patterns across 5 categories
- Works with OpenAI, Anthropic, or any HTTP endpoint
- SARIF output → GitHub Security tab integration
- Rule-based detection (no LLM cost for analysis)
- Only tool I've found that tests multi-agent attack surfaces

**Quick start:**
```bash
npx @alexmelges/agentprobe --demo    # see it in action
npx @alexmelges/agentprobe init      # generates config
npx @alexmelges/agentprobe           # run the scan
```

**GitHub Action:**
```yaml
- uses: alexmelges/agentprobe@main
  with:
    config: agentprobe.yaml
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

Open source (MIT): https://github.com/alexmelges/agentprobe
npm: https://www.npmjs.com/package/@alexmelges/agentprobe

Would love feedback — especially on attack patterns you'd want to see added.
