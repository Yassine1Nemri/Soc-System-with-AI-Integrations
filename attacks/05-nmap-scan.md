Attack: Nmap scan from the host
Time started / ended: 2026-10-19 21:40 to 2026-10-19 21:55 (local time)
Commands run: TODO (paste the exact commands you ran)

Wazuh alert(s): rule ID, level, description

| Rule ID | Level | Description | MITRE | Count |
|---|---|---|---|---|
| 100210 | 8 | Audit: curl/wget executed (tool_transfer) | T1105 (Ingress Tool Transfer) | 1 |
| 5402 | 3 | Successful sudo to ROOT executed. | T1548.003 (Sudo and Sudo Caching) | 1 |
| 5501 | 3 | PAM: Login session opened. | T1078 (Valid Accounts) | 1 |
| 5502 | 3 | PAM: Login session closed. | -  | 1 |

MITRE tag shown by Wazuh (correct?): T1078, T1105, T1548.003. TODO: compare with the expected technique ID
Number of alerts produced (noise): 4 across 4 rule(s)
Detected? TODO yes / partly / no
What I would tune: TODO

