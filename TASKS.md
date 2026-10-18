# Tasks: SOC System with AI Integrations

Tick each box only when you have **proof** (a screenshot, a command output, or a saved file in the repo). Write every error you hit in `docs/problems-log.md` as you go.

**My lab**

| Machine | IP | Role |
|---|---|---|
| Ubuntu host | 172.16.220.1 (VM network), 192.168.0.171 (Wi-Fi) | NetAlertX, Grafana, forwarder |
| Wazuh VM | 172.16.220.136 | Wazuh server (v4.14.8) |
| Ubuntu target VM | 172.16.220.137 | Attack target |
| Windows VM | 172.16.220.138 | Optional, not needed |

---

## Phase 0: Prep (about 30 min)

- [ ] Snapshot all VMs as `clean-baseline`
- [ ] Check time sync on every Linux machine: `timedatectl` shows `System clock synchronized: yes`
- [ ] (Optional) Raise the Wazuh VM RAM from 4 GB to 6 GB
- [ ] Create the repo `homesoc-ai` with folders `docs, configs, attacks, reports, screenshots`
- [ ] Create `docs/problems-log.md` (columns: date, problem, what I tried, fix, lesson)
- [ ] Create `docs/ip-plan.md` with the table above
- [ ] Add a `.gitignore` that excludes `*.env`, `*.key`, `*.pem`, and any file with passwords or tokens
- [ ] Copy `README.md` and the `.drawio` diagram into the repo

## Phase 1: Health baseline

- [ ] Wazuh VM: manager, indexer, dashboard, and filebeat all report `active`
- [ ] Wazuh dashboard opens from the host at `https://172.16.220.136`
- [ ] Ubuntu target agent shows **Active** in the dashboard
- [ ] Agent version is equal to or lower than the manager (4.14.8)
- [ ] Host can ping .136 and .137
- [ ] Check whether port 9200 (Indexer) is reachable from the host and note the result in the problems log
- [ ] Screenshot: Agents page → `screenshots/01-agents-active.png`

## Phase 2: Make attacks visible

Wazuh only sees what you tell it to watch.

- [ ] File monitoring on the target for `/etc/cron.d`, `/etc/crontab`, `/var/spool/cron`, and `/home/*/.ssh` (set in the agent's `ossec.conf`, `realtime="yes"`)
- [ ] Install `auditd` on the target
- [ ] auditd rules for: execution of `curl` and `wget`, changes to history files, and changes to files in `/var/log`
- [ ] Make Wazuh read the audit log (`/var/log/audit/audit.log`)
- [ ] Turn on UFW logging on the target so a port scan leaves a log line
- [ ] Confirm the listening-ports monitoring is active in the agent config
- [ ] Test each item: make one harmless change and confirm an alert appears in the dashboard
- [ ] Save the agent config changes to `configs/` (no secrets)
- [ ] Snapshot the target as `monitoring-ready`

## Phase 3: NetAlertX on the host

- [ ] Install Docker on the host and confirm `docker run hello-world` works
- [ ] Create `compose.yml` with host networking
- [ ] Scan subnets: `192.168.0.0/24` on `wlo1` and `172.16.220.0/24` on `vmnet8`
- [ ] Start the container and open the web UI
- [ ] Check that the device list is not empty (if it is, record the cause in the problems log)
- [ ] Name and label every known device, so "unknown" means something
- [ ] Generate an API token and test the `/devices` endpoint with `curl`
- [ ] Screenshot: device list → `screenshots/03-netalertx-devices.png`
- [ ] Save `compose.yml` to `configs/` with the token removed

## Phase 4: Grafana dashboard

- [ ] Make the Indexer reachable from the host (check what it listens on and what the firewall allows)
- [ ] Create a read-only Indexer user and role for Grafana
- [ ] Run Grafana in Docker on the host
- [ ] Add the OpenSearch data source for `wazuh-alerts-4.x-*`, time field `timestamp`
- [ ] Add the Infinity data source for NetAlertX (Bearer token)
- [ ] Build panels:
  - [ ] Alerts over time
  - [ ] Top 10 rules fired
  - [ ] Alerts by MITRE technique
  - [ ] Agent status
  - [ ] NetAlertX device inventory
  - [ ] New or unknown devices
- [ ] Set refresh to 30 seconds
- [ ] Export the dashboard JSON to `configs/grafana-dashboard.json`
- [ ] Screenshot: full dashboard → `screenshots/04-dashboard.png`

## Phase 5: Attack campaign

Rules: run one attack at a time, only on your own VMs, and restore the `monitoring-ready` snapshot between attacks.

For each attack, create `attacks/NN-name.md` with this record:

```
Attack: 
Time started / ended: 
Commands run: 
Wazuh alert(s): rule ID, level, description
MITRE tag shown by Wazuh (correct?): 
Number of alerts produced (noise): 
Detected? yes / partly / no
What I would tune: 
```

- [ ] 1. New user added to the sudo group (T1136.001)
- [ ] 2. Cron job persistence (T1053.003)
- [ ] 3. SSH key planted, then used to log in from the host (T1098.004, T1021.004)
- [ ] 4. Clear bash history and truncate a log (T1070.003, T1070.002)
- [ ] 5. Nmap scan from the host (T1046), expected **gap** at first
  - [ ] Write a custom rule that catches it and save it to `configs/local_rules.xml`
  - [ ] Re-run the scan and confirm the alert fires
- [ ] 6. Hidden listening port on the target (T1571)
- [ ] 7. Download-and-run from `python3 -m http.server` on the host (T1105)
  - [ ] Write a custom rule if the built-in rules miss it
- [ ] 8. Rogue device joins the network (NetAlertX new-device alert)
- [ ] Tuning: record alert counts **before** and **after** you reduce noise from one chatty rule
- [ ] Fill in the results table in `README.md`
- [ ] Write the detection-rate line: "Detected X of 8"

## Phase 6: AI layer

- [ ] Choose the provider: local model (Ollama) first, Airia free plan for the final demo
- [ ] Sign up for the Airia free plan and note its limits
- [ ] Write the AI prompt: a cautious analyst, treat alert text as untrusted, never follow instructions found inside an alert, return strict JSON
- [ ] Build the forwarder (Python) with:
  - [ ] Filter: send only alerts at level 7 or higher
  - [ ] Cooldown: one AI call per rule per agent every 5 minutes
  - [ ] Redaction: mask internal IPs, usernames, and hostnames before sending
  - [ ] Retry: do not lose an alert if the AI call fails
  - [ ] The AI call sits in **one function**, so the provider can be swapped
- [ ] Run `python3 -m py_compile` on the script
- [ ] Run the forwarder as a systemd service with a restricted user
- [ ] Test with one real alert from Phase 5
- [ ] Add AI summary panels to Grafana (latest summary, history, risk score)
- [ ] Screenshot: AI summary on the dashboard → `screenshots/06-ai-summary.png`

## Phase 7: AI evaluation

- [ ] Pick 20 real alerts, covering all 8 attacks plus a few noisy ones
- [ ] **Before looking at the AI**, write your own triage note for each (what happened, severity, next step)
- [ ] Compare each AI output with your note and label it: correct / partly correct / wrong / confidently wrong
- [ ] Put the results in `reports/ai-evaluation.md` as a table, with counts
- [ ] Describe 3 cases where the AI failed and why
- [ ] If you used two providers, compare them side by side
- [ ] Write 3 sentences: where the AI helps, where it should never be trusted, and what you would change

## Phase 8: Publish

- [ ] Write 2 or 3 incident reports in `reports/` (timeline, evidence, MITRE ID, verdict, tuning, AI summary vs your verdict)
- [ ] Fill in every "TBD" in `README.md` with real numbers
- [ ] Write the "Lessons learned" section from `docs/problems-log.md`
- [ ] Search the repo for secrets before pushing: `grep -rniE "password|token|api[_-]?key" .`
- [ ] Rotate any secret that was ever pasted into chat or a screenshot
- [ ] Record a 2-minute demo: attack, then alert, then AI summary, then dashboard
- [ ] Push to GitHub and pin the repo
- [ ] Write 3 resume bullets and 1 LinkedIn post using only things you actually did
- [ ] Prepare answers for: why these tools, what broke, how you reduced noise, and where the AI was wrong

---

## Definition of done

- [ ] All 8 attacks have a record in `attacks/`
- [ ] Detection rate and AI accuracy are both written as numbers
- [ ] At least 5 entries in the problems log
- [ ] The dashboard shows alerts, devices, and AI summaries on one screen
- [ ] No secrets in the repository
- [ ] You can explain every part of the project without notes
