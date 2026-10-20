# 🛡️ HomeSOC-AI

**A home SOC built on one Ubuntu host: Wazuh + NetAlertX + Grafana, with a local AI analyst in the loop, and a measured look at where that AI is wrong.**

I attacked my own lab with techniques mapped to MITRE ATT&CK, extended Wazuh to see what it ignores by default, and sent the high-severity alerts through a Python forwarder to a local LLM (Ollama, `qwen3:4b`) for triage. Everything shows up on one Grafana dashboard.

![Architecture](soc_diagram_updated.png)

## Table of contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Repository contents](#repository-contents)
- [Build journey](#build-journey)
- [Key finding: a detection gap and an AI failure from one attack](#key-finding-a-detection-gap-and-an-ai-failure-from-one-attack)
- [Attack campaign](#attack-campaign)
- [AI evaluation](#ai-evaluation)
- [Engineering notes](#engineering-notes)
- [Design decisions](#design-decisions)
- [Limitations](#limitations)
- [Roadmap](#roadmap)

## What it does

A change happens on the monitored Ubuntu target (a cron file, an SSH key, a port scan). The Wazuh agent and auditd report it, the Wazuh manager raises an alert, and the forwarder picks up level 7+ alerts, masks private data and asks the local model for a summary and next steps. Grafana pulls alerts, device inventory and AI results into one screen.

- 🔍 **Detection beyond the defaults:** file integrity monitoring on cron and SSH paths, auditd rules for `curl`/`wget` execution, history changes and log changes, and UFW logging for port scans.
- ✍️ **Custom Wazuh rules** for the gaps I found, including a port-scan rule (`configs/local_rules.xml`).
- 🤖 **AI triage with guardrails:** level filter, per-rule cooldown, redaction of IPs, usernames and hostnames, retries, and output validation.
- 🧱 **The model never decides facts.** File path, hash, rule ID and MITRE technique come from the alert and a lookup table. The AI writes only the summary and next steps.
- 📡 **Network inventory** with NetAlertX, flagging new and unknown devices.
- 📊 **One dashboard** over two independent data sources (Wazuh Indexer and the NetAlertX API) plus the AI results.
- 🔐 **Least privilege:** Grafana uses a read-only Indexer account (a write returns 403), and the Indexer stays bound to localhost, reached over an SSH tunnel.

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

| Machine | Address | Role |
|---|---|---|
| Ubuntu host | 172.16.220.1 (VM network) | NetAlertX, Grafana, forwarder, Ollama |
| Wazuh VM | 172.16.220.136 | Wazuh manager, Indexer (OpenSearch 2.19), dashboard, v4.14.8 |
| Ubuntu target VM | 172.16.220.137 | Monitored attack target |

## Tech stack

| Layer | Technology |
|---|---|
| SIEM | Wazuh 4.14.8 (manager, Indexer, dashboard, Filebeat) |
| Extra telemetry | auditd, Wazuh syscheck (realtime), UFW logging |
| Network discovery | NetAlertX (Docker, host networking) |
| AI | Ollama with `qwen3:4b`, Python forwarder |
| Visualisation | Grafana with the OpenSearch and Infinity data sources |
| Infrastructure | VMware, Ubuntu, Docker, SSH tunnel to the Indexer |

**Cost: $0.** Everything is free or open source, and the AI runs locally.

## Repository contents

```
.
├── README.md
├── soc_diagram_updated.png
├── attack_report.py        # pulls rule IDs, levels, MITRE tags and alert counts for a time window
├── attacks/                # one record per attack
├── ai-eval/                # AI outputs and evaluation data
├── configs/                # agent config, audit rules, local_rules.xml, compose files, Grafana export
├── docs/                   # IP plan and problems log
├── forwarder/              # AI triage forwarder
├── reports/                # incident reports
└── screenshots/            # dashboards and evidence
```

## Build journey

### 1. Lab network and health baseline

Wazuh runs on its own VM next to a monitored Ubuntu target. The Wazuh dashboard opens from the host, and the target shows **Active** on the Agents page. The Indexer listens only on `127.0.0.1:9200`, so the host reaches it through an SSH tunnel rather than a config change that would expose it.

![Agents page: the Ubuntu target is Active](screenshots/01-agents-active.png)

*The Wazuh Endpoints page: connection status, operating system and group of each enrolled agent.*

### 2. Making attacks visible

Out of the box Wazuh sees little of what an attacker does on Linux. I added:

- **File integrity monitoring** (`realtime="yes"`) on `/etc/cron.d`, `/etc/crontab`, `/var/spool/cron` and `/home/*/.ssh`.
- **auditd rules** for `curl` and `wget` execution, shell history changes and changes under `/var/log`, read by Wazuh from `/var/log/audit/audit.log`.
- **UFW logging**, so a port scan leaves a log line.
- **Custom rules** on top: `100210` and `100211` for the auditd events and `100221` for "UFW: possible port scan".

Each item was tested with one harmless change and confirmed in the dashboard. The configs are in [`configs/`](configs/) with secrets removed.

![Wazuh Threat Hunting overview](screenshots/07-wazuh-dashboard.png)

*Wazuh Threat Hunting dashboard: total alerts, authentication metrics, alert level evolution, top agents and MITRE ATT&CK breakdown.*

### 3. Network discovery with NetAlertX

NetAlertX runs in Docker with host networking so it can scan both the home Wi-Fi and the VM network, and flags any device it has not seen. I generated an API token and tested the `/devices` endpoint with `curl`, which is how Grafana reads it. The config is saved as [`configs/netalertx-compose.yml`](configs/netalertx-compose.yml).

<!-- Blur family devices, MACs and names in this screenshot, then remove this comment to publish it:
![NetAlertX device inventory](screenshots/03-netalertx-devices.png)
*Inventory of every device on the networks, with online status, IP and MAC.*
-->

### 4. Grafana: one screen

Grafana runs in Docker on the host with two data sources: **OpenSearch** (index pattern `wazuh-alerts-4.x-*`, time field `timestamp`) through a **read-only** account (`grafana_ro` with role `grafana_read`; a count query works and a write returns 403), and **Infinity** for the NetAlertX API (Bearer token).

Panels: alerts over time, top 10 rules fired, alerts by MITRE technique, agent status, critical alerts (level 10+), file integrity events coloured by event type, and the NetAlertX device inventory.

![Grafana SOC overview](screenshots/04-dashboard.png)

*Alerts over time, top triggered rules, alerts by MITRE technique and device counts.*

### 5. The AI forwarder

[`forwarder/forwarder.py`](forwarder/forwarder.py) sits between Wazuh and the model:

- **Filter:** only alerts at level 7 or higher are sent.
- **Cooldown:** one AI call per rule per agent every 5 minutes, so a noisy rule cannot flood the model.
- **Redaction:** internal IPs, usernames and hostnames are masked before anything reaches the model.
- **Retry:** a failed AI call does not lose the alert.
- **Swappable provider:** the model call lives in one function.
- **Prompt:** the model is told to act as a cautious analyst, to treat alert text as untrusted data, never to follow instructions found inside an alert, and to return strict JSON.

The first prompt version failed, and I kept that case in [`ai-eval/v1-prompt-failure.jsonl`](ai-eval/v1-prompt-failure.jsonl) as evidence of what changed.

### 6. AI results on the dashboard

The AI output is stored and shown in Grafana as a **risk score gauge**, a **Latest AI analysis** table (alert, summary, recommended action, confidence) and a **risk-over-time** chart, next to the critical-alert count and file integrity events.

![AI summary: risk score, latest analysis and file integrity events](screenshots/06-ai-summary.png)

*The risk score ranks alerts for triage. The analysis table shows what the model says about the latest alert.*

![AI triage panels](screenshots/05-ai-dashboard.png)

*The same AI panels in a taller layout with risk over time.*

## Key finding: a detection gap and an AI failure from one attack

**Attack 2, cron persistence (T1053.003).** I created a file in `/etc/cron.d/`.

**1. Detection: partly detected.** File integrity monitoring saw it, but only as the generic rule **554 ("File added to the system"), level 5, with no MITRE tag**. The forwarder only sends level 7+, so this alert would never have reached the AI.

**2. The AI, replayed manually:** the model labelled the file `T1059: Command and Control`. That is wrong twice: T1059 is *Command and Scripting Interpreter* (Execution), and the right technique is T1053.003. It scored the alert **10/100 (Low)**, reported **high confidence**, and garbled the SHA-256 hash in its summary. The alert had no MITRE field, so the model invented one. I label this case **confidently wrong**.

![Before: the AI invents a MITRE technique](screenshots/ai-failure-before.png)

*The failing output: wrong technique, low score, high confidence.*

**3. The fix is in the design, not a better prompt.** MITRE technique and tactic come from a path-to-technique lookup table, each technique has a risk floor so code can raise a score that is too low, and the hash is stripped from the model's free text. The model writes only the summary and the next steps.

![After: facts from code, prose from the AI](screenshots/ai-triage-output.png)

*The same alert after the fix: path, hash and rule ID from the alert, T1053.003 (Persistence) from the lookup table, severity High, evidence list, three recommended actions and validation flags.*

Full output: [`ai-eval/example-cron-persistence.json`](ai-eval/example-cron-persistence.json)

## Attack campaign

All attacks run only against my own lab VMs, one at a time. Each record in [`attacks/`](attacks/) uses the same template: commands, alerts (rule ID, level, description), MITRE tag shown by Wazuh, number of alerts (noise), detected yes/partly/no, and what I would tune.

| # | Attack | MITRE | What catches it | Result |
|---|---|---|---|---|
| 1 | New user added to sudo group | T1136.001 | ⬜ fill in | ⬜ |
| 2 | Cron job persistence | T1053.003 | FIM, generic rule 554 (level 5, no MITRE tag) | **Partly detected** |
| 3 | SSH key planted, then used to log in | T1098.004, T1021.004 | FIM on `/home/*/.ssh` | ⬜ |
| 4 | History cleared and log truncated | T1070.003, T1070.002 | auditd rules | ⬜ |
| 5 | Nmap scan from the host | T1046 | Custom rule 100221 (UFW port scan) | see [`attacks/05-nmap-scan.md`](attacks/05-nmap-scan.md) |
| 6 | Hidden listening port | T1571 | Wazuh netstat monitoring (rule 533) | ⬜ |
| 7 | Download-and-run from the host | T1105 | auditd `curl`/`wget` rules | ⬜ |
| 8 | Rogue device joins the network | T1200 | NetAlertX new-device flag | ⬜ |

**Detected X of 8:** ⬜

## AI evaluation

**Method:** take 20 real alerts covering all 8 attacks plus a few noisy ones. Write my own triage note for each (what happened, severity, next step) *before* reading the AI output. Then label each AI result **correct**, **partly correct**, **wrong** or **confidently wrong**. Results go in `reports/ai-evaluation.md`.

| Label | Count |
|---|---|
| Correct | ⬜ |
| Partly correct | ⬜ |
| Wrong | ⬜ |
| Confidently wrong | ⬜ |
| **Total** | ⬜ |

Documented failure so far: the cron persistence case above (confidently wrong).

## Engineering notes

Every failure is in [`docs/problems-log.md`](docs/problems-log.md) with problem, what I tried, fix and lesson. The ones that taught me the most:

| Problem | Cause | Fix |
|---|---|---|
| Host could not reach the Indexer on 9200 | Indexer bound to `127.0.0.1` by default | SSH tunnel, no config change on the VM |
| Cluster went **red**, 5 unassigned shards | Interrupted restarts left corrupt translogs | Deleted regenerable `wazuh-monitoring-*` and `wazuh-statistics-*` indices and one corrupt alerts index. Lesson: a single node has no redundancy, so snapshot first |
| `securityadmin.sh` hung | It waits for a yellow cluster and the cluster was red | Repaired the cluster first |
| Indexer failed to start after a config edit | `AccessDeniedException`: files edited as root | `chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer` |
| `wazuh-passwords-tool.sh` left in a bad state | I interrupted it with Ctrl+C and used a placeholder password | Let tools finish and never paste placeholders |
| Grafana OpenSearch data source: connect error, then 403, then 401 | Role missing `cluster:monitor/main`, then a mistyped password | Added the permission and reset the password |
| Grafana version detection `JSON.parse` error, empty panels | Plugin could not detect the version, wrong time field `@timestamp` | **Get Version and Save**, time field `timestamp` |
| Infinity filters failed (`Invalid token: '='`, `No parameter 'devName'`) | Filters need `==` and the column **title**, not the raw field name | Rewrote the filters |
| "Unknown devices" count never changed | Most home phones and TVs are unnamed, so a rogue device would go unnoticed | Baseline approach: clear the New flag on accepted devices and alert on `New == 1` |

## Design decisions

- **Local LLM instead of a cloud API.** Alert data stays on the machine, the cost is $0, and I can measure the model without rate limits. The trade-off is a weaker 4B model, which is why facts come from code and the model only writes prose.
- **Facts from code, prose from the model.** After the cron failure I stopped trusting the model with file paths, hashes or MITRE IDs. Validation flags record every time code corrects the model.
- **Level filter and cooldown.** Level 7+ only, one call per rule per agent per 5 minutes. A chatty rule produced 388 alerts in one dashboard window, and AI calls are the scarce resource.
- **Read-only Grafana account and SSH tunnel.** A dashboard should never be able to write to the SIEM, and the Indexer should not listen on the network.
- **Alert text treated as untrusted input.** Log lines can contain attacker-controlled text, so the prompt forbids following instructions found inside an alert, and IPs, usernames and hostnames are masked before the model sees them.

## Limitations

- Single-node Wazuh Indexer with no redundancy. It went red twice after interrupted restarts.
- Small lab with one monitored target, so results do not generalise.
- A 4B-parameter model follows schemas loosely and cannot be treated as a verdict.
- TLS verification to the Indexer is relaxed inside the lab network.
- The AI accuracy sample is small, and I wrote the reference triage notes myself.


## Disclaimer

Learning project. Do not run these techniques against systems you do not own or have permission to test.

## Author

**Yassine Nemri** · [GitHub](https://github.com/Yassine1Nemri) · [LinkedIn](https://www.linkedin.com/in/YOUR-HANDLE)
