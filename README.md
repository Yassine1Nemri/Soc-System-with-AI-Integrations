# HomeSOC-AI

A home Security Operations Center built on one Ubuntu host. It detects attacks I run against my own lab, triages the alerts with a local AI model, and **measures where the AI is wrong**.

![Architecture](soc_diagram_updated.png)

## Highlights

- **Wazuh extended to see what it ignores by default:** file integrity monitoring on cron and SSH paths, auditd rules (curl/wget execution, history and log changes), and UFW logging.
- **Custom detection rules** for the gaps I found, including a port-scan rule (`configs/local_rules.xml`).
- **AI triage pipeline:** a Python forwarder sends only level 7+ alerts to a local LLM (Ollama, `qwen3:4b`). It rate-limits per rule and agent, redacts IPs, usernames and hostnames, and retries on failure.
- **The model never decides facts.** File path, hash, rule ID and MITRE technique come from the alert and a lookup table. The AI writes only the summary and next steps, and code can raise a score that is too low.
- **One-screen Grafana dashboard:** alerts over time, MITRE techniques, top rules, file integrity events, device inventory, AI risk score and analysis.
- **NetAlertX** watches the network for new and unknown devices.
- **Least privilege:** Grafana reads the Indexer through a read-only account (a write returns 403).

## Screenshots

| | |
|---|---|
| ![AI summary](screenshots/06-ai-summary.png) | ![AI dashboard](screenshots/05-ai-dashboard.png) |
| AI risk score, latest analysis and file integrity events | AI triage panels |
| ![SOC dashboard](screenshots/04-dashboard.png) | ![Wazuh](screenshots/07-wazuh-dashboard.png) |
| Grafana SOC overview | Wazuh threat hunting view |

![Agents](screenshots/01-agents-active.png)

## Finding: a detection gap and an AI failure from the same attack

**Attack 2, cron persistence (T1053.003).** I dropped a file in `/etc/cron.d/`.

- **Detection:** file integrity monitoring caught it, but as the generic rule 554 (level 5) with no MITRE tag. The forwarder only sends level 7+, so the AI would never have seen it. Verdict: **partly detected**.
- **AI:** when I replayed the alert manually, the model labelled it `T1059: Command and Control` (wrong: T1059 is Execution), scored it 10/100 and reported high confidence. It invented a MITRE technique because the alert had none, and it garbled the hash in its summary.

![Before: AI invents a MITRE technique](screenshots/ai-failure-before.png)

**Fix:** the forwarder now takes MITRE from a lookup table, applies a risk floor per technique, strips hashes from the model's text, and records validation flags.

![After: facts from code, prose from the AI](screenshots/ai-triage-output.png)

Full output: [`ai-eval/example-cron-persistence.json`](ai-eval/example-cron-persistence.json)

## Architecture

```mermaid
flowchart TD
    LAN["Home Wi-Fi + VM network"] --> N["NetAlertX (host, Docker)"]
    U["Ubuntu target VM<br/>Wazuh agent + auditd + UFW"] --> M["Wazuh server VM"]
    M --> F["Forwarder<br/>filter, cooldown, redact, validate"]
    F --> AI["Local LLM<br/>Ollama qwen3:4b"]
    AI --> G["Grafana (host, Docker)"]
    M --> G
    N --> G
```

| Component | Where it runs | Job |
|---|---|---|
| Wazuh server 4.14.8 | VM | Collects events, raises alerts, maps to MITRE ATT&CK |
| Wazuh agent | Ubuntu target VM | File integrity, auditd, UFW and port monitoring |
| NetAlertX | Docker on host | Device inventory, new-device flag |
| Grafana | Docker on host | Dashboard (OpenSearch + Infinity data sources) |
| Forwarder | Host (Python) | Filter, cooldown, redaction, AI call, validation |
| Ollama (`qwen3:4b`) | Host | Summary, risk score and recommended actions |

**Cost: $0.** Everything is free or open source.

## Attack campaign

All attacks run only against my own VMs.

| # | Attack | MITRE | Status |
|---|---|---|---|
| 1 | New user added to sudo group | T1136.001 | not yet written up |
| 2 | Cron job persistence | T1053.003 | **Partly detected** (generic level 5 rule, no MITRE tag), see above |
| 3 | SSH key planted, then used to log in | T1098.004, T1021.004 | not yet written up |
| 4 | History and log clearing | T1070.003, T1070.002 | not yet written up |
| 5 | Nmap port scan | T1046 | see [`attacks/05-nmap-scan.md`](attacks/05-nmap-scan.md) |
| 6 | Hidden listening port | T1571 | not yet written up |
| 7 | Download-and-run from host | T1105 | not yet written up |
| 8 | Rogue device joins network | T1200 | not yet written up |

Records live in [`attacks/`](attacks/). I fill in this table only with attacks I have written up.

## AI evaluation

Method: take 20 real alerts, write my own triage note for each **before** reading the AI output, then label the AI result correct, partly correct, wrong, or confidently wrong. Results will be in `reports/ai-evaluation.md`. Not completed yet, so no accuracy number is claimed here.

One documented case so far: the cron persistence failure above, labelled **confidently wrong**.

## Limitations

- Single-node Wazuh Indexer with no redundancy. It went red twice after interrupted restarts.
- Small lab: one monitored target, so results do not generalise.
- A 4B-parameter local model. It follows schemas loosely, which is why facts come from code.
- TLS verification to the Indexer is relaxed inside the lab network.

## Security decisions

- Attacks run only against VMs I own.
- Grafana uses a read-only Indexer account, never admin.
- Alert text is untrusted input: the prompt forbids following instructions found inside an alert.
- IPs, usernames and hostnames are masked before any alert reaches the model.
- No passwords, API keys or tokens are committed; secrets come from environment variables.

## Repository layout
    attacks/       one record per attack
    ai-eval/       AI outputs and evaluation data
    configs/       Wazuh rules, agent config, compose files, Grafana export (no secrets)
    docs/          IP plan and problems log
    forwarder/     Python AI triage forwarder
    reports/       incident reports
    screenshots/   dashboards and evidence

## Problems I solved

See [`docs/problems-log.md`](docs/problems-log.md): Indexer bound to localhost, corrupt shards, interrupted password tool, Grafana data source errors, and more. Each entry has problem, what I tried, fix, lesson.

## Roadmap

- [x] Wazuh server and agent
- [x] Extra monitoring: file integrity, auditd, UFW, custom rules
- [x] NetAlertX
- [x] Grafana dashboard with read-only Indexer user
- [x] AI forwarder: filter, cooldown, redaction, retry, validation
- [ ] Attack records 1 to 8
- [ ] Custom rule for cron persistence (T1053.003)
- [ ] AI evaluation on 20 alerts
- [ ] Forwarder as a systemd service
- [ ] Demo video

## Disclaimer

Learning project. Do not run these techniques against systems you do not own or have permission to test.

## Author

Yassine Nemri | [LinkedIn](https://www.linkedin.com/in/YOUR-HANDLE) | [GitHub](https://github.com/Yassine1Nemri)
