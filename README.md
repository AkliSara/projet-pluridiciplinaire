# projet-pluridiciplinaire
## Incident 1 — SSH Brute Force Attack
**Date:** 2026-05-23 03:01 UTC+1 | **Severity:** CRITICAL | **MITRE ATT&CK:** T1110 — Brute Force / Credential Access

---

### Alert Triage

| Field | Value |
|---|---|
| Rule ID | 5763 |
| Rule Level | 10 |
| MITRE Technique | T1110 — Credential Access |
| Agent Name | `vm-vulnerable` |
| Agent IP | `100.108.27.54` |
| Source IP (Attacker) | `100.117.116.16` |
| Targeted User | `rawane` |
| Timestamp | `2026-05-23T02:01:01.671Z` |

---

### Log Analysis
The first indicator was a high-frequency stream of PAM authentication failures logged by `sshd`, all originating from the same source IP within a very short time window — a pattern characteristic of automated credential stuffing or dictionary attacks.
Wazuh correlated these repeated failures and escalated to rule **5763** (level 10), mapping the behavior to **MITRE T1110 — Brute Force**. The consistent targeting of a single username (`rawane`) across all attempts confirms a focused credential attack rather than a random spray.


---

### Analyst Notes

- Single source IP with no lateral variation → likely automated tool (Hydra/Medusa pattern)
- All attempts target the same account → attacker had prior knowledge of valid usernames (possible prior reconnaissance)
- Short time window between attempts → no throttling or lockout policy enforced on the target
- Successful login eventually occurred → password policy was weak or account had no brute-force protection

The first indicator was a high-frequency stream of PAM authentication failures logged by `sshd`, all originating from the same source IP within a very short time window — a pattern characteristic of automated credential stuffing or dictionary attacks.
### Response Actions Taken

| Step | Action | Tool |
|---|---|---|
| 1 | Alert received and reviewed | Wazuh SIEM |
| 2 | SOC team notified with full alert context | Shuffle → Discord |
| 3 | Source IP `100.117.116.16` added to firewall blocklist | Shuffle → OPNsense REST API |
| 4 | Block rule persisted across restarts | OPNsense HTTPS config save |

---
### Evidence
| Screenshot | Description |
|---|---|
| Wazuh alert received in Discord via Shuffle |
<img width="976" height="585" alt="image" src="https://github.com/user-attachments/assets/4637bbb9-a264-4c9f-9212-b005e19297d9" />

| `opnsense_blocklist.png` | Attacker IP added to OPNsense blocklist |
<img width="1709" height="558" alt="image" src="https://github.com/user-attachments/assets/8fd722dc-9ad0-4c8d-8d67-5cd0cbc5323b" />

| `wazuh_alert.png` | Wazuh SIEM alert detail — T1110 Credential Access |
<img width="1606" height="317" alt="image" src="https://github.com/user-attachments/assets/298f727b-882c-4106-bfa4-57d557d4752e" />



