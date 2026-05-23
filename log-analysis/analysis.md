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

---

### Response Actions Taken

| Step | Action | Tool |
|---|---|---|
| 1 | Alert received and reviewed | Wazuh SIEM |
| 2 | SOC team notified with full alert context | Shuffle → Discord |
| 3 | Source IP `100.117.116.16` added to firewall blocklist | Shuffle → OPNsense REST API |
| 4 | Block rule persisted across restarts | OPNsense HTTPS config save |

---

### Evidence

| File | Description |
|---|---|
| Real-time Discord notification triggered by Shuffle SOAR |
<img width="976" height="585" alt="image" src="https://github.com/user-attachments/assets/1c421c62-6e73-4b52-a720-a4b4004a227e" />

| OPNsense `blocklist_suricata` showing blocked IP |
<img width="1709" height="558" alt="image" src="https://github.com/user-attachments/assets/07530e44-2914-4f9d-b03b-53704ed94ed7" />

| Wazuh alert detail — T1110, rule 5763, agent `vm-vulnerable` |
<img width="1606" height="317" alt="image" src="https://github.com/user-attachments/assets/ef5d8293-5c8d-4b29-8322-0cf300c16e03" />

## Incident 2 — Persistence & Privilege Escalation
**Date:** 2026-05-23 03:18–03:30 UTC+1 | **Severity:** CRITICAL | **MITRE ATT&CK:** T1548.003 — Sudo/Sudoers Abuse · T1136.001 — Create Local Account

---

### Alert Triage

#### Alert 1 — Privilege Escalation
| Field | Value |
|---|---|
| Rule ID | 100004 |
| Rule Level | 10 |
| MITRE Technique | T1548.003 — Privilege Escalation / Defense Evasion |
| Description | Privilege Escalation: Successful sudo to ROOT executed |
| Agent Name | `vm-vulnerable` |
| Agent IP | `100.108.27.54` |
| Timestamp | `2026-05-23T02:18:53.127Z` |

#### Alert 2 — Backdoor Account Creation
| Field | Value |
|---|---|
| Rule ID | 100005 |
| Rule Level | 10 |
| MITRE Technique | T1136.001 — Persistence |
| Description | Persistence: New user account created on system |
| Agent Name | `vm-vulnerable` |
| Agent IP | `100.108.27.54` |
| Decoder | `useradd` |
| Timestamp | `2026-05-23T02:30:26.082Z` |

---

### Log Analysis

**Step 1 — Privilege Escalation via sudo (T1548.003)**

Approximately 17 minutes after the brute-force access was established, Wazuh raised a level-10 alert for a successful `sudo` escalation to root on `vm-vulnerable`. This confirms the attacker moved from the compromised `rawane` account to full root privileges by abusing a permissive `sudoers` configuration — no password required.

This technique falls under both **Privilege Escalation** and **Defense Evasion** since abusing legitimate system binaries helps avoid detection compared to deploying an external exploit.

**Step 2 — Backdoor Account Creation (T1136.001)**

12 minutes later, Wazuh's `useradd` decoder caught the following log:
2026-05-23T03:30:25.923871+01:00 vm-vulnerable useradd[252406]:
new group: name=backdoor, GID=1002
A new group named `backdoor` with GID 1002 was created — a direct indicator of an attacker establishing a persistence mechanism to survive a potential password reset or session termination on the original account.

---

### Analyst Notes

- The 17-minute gap between initial access (03:01) and privilege escalation (03:18) suggests a deliberate, manual post-exploitation phase — not an automated script
- `sudo` abuse with no password prompt means the `sudoers` file was misconfigured (likely `NOPASSWD` entry for `rawane`)
- The group name `backdoor` is explicit and unsophisticated — attacker made no attempt to blend in with legitimate system accounts
- No attacker IP was captured in the persistence alert — by this stage the attacker was operating locally as root, not over the network
- Timeline correlation: T1110 (03:01) → T1548.003 (03:18) → T1136.001 (03:30) — clean kill chain progression

---

### Response Actions Taken

| Step | Action | Tool |
|---|---|---|
| 1 | Privilege escalation alert reviewed | Wazuh SIEM |
| 2 | Backdoor account creation alert reviewed | Wazuh SIEM |
| 3 | SOC team notified via Discord (Spidey Bot) | Shuffle → Discord |
| 4 | Recommended actions: disable `rawane` & `backdoor` accounts, audit `sudoers`, full reinstall | Manual escalation |

**Note:** The Discord notification for the persistence alert shows an empty `Attacker IP` field. This is expected — by this stage the attacker was executing commands locally as root. The source IP is correlated from the earlier brute-force alert (`100.117.116.16`).

---

### Evidence

| File | Description |
|---|---|
| Wazuh alert — T1548.003, sudo to ROOT, rule 100004 |
<img width="1910" height="475" alt="image" src="https://github.com/user-attachments/assets/6fc8623e-e58f-40a7-be28-a21ee2d3b2c3" />

| Wazuh alert — T1136.001, backdoor group creation, rule 100005 |
<img width="1910" height="475" alt="image" src="https://github.com/user-attachments/assets/5917d0d6-9e75-4b50-b6be-87d9edcb3103" />

| Discord notification — new user account created on `vm-vulnerable` |
<img width="1555" height="346" alt="image" src="https://github.com/user-attachments/assets/162299ef-7e17-4925-a772-6e68ebb8b63e" />


