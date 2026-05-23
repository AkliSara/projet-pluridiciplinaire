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

## Incident 3 — Web Probing / Active Reconnaissance
**Date:** 2026-05-23 03:45–03:48 UTC+1 | **Severity:** MEDIUM → HIGH | **MITRE ATT&CK:** T1595.002 — Active Scanning / Vulnerability Scanning · T1055 · T1083 · T1190

---

### Alert Triage

#### Alert 1 — HTTP Flood / Directory Probing
| Field | Value |
|---|---|
| Rule ID | 31151 |
| Rule Level | 10 |
| MITRE Technique | T1595.002 — Reconnaissance |
| Description | Multiple web server 400 error codes from same source IP |
| Agent Name | `vm-vulnerable` |
| Agent IP | `100.108.27.54` |
| Source IP | `100.117.116.16` |
| Protocol | GET |
| Probed URL (sample) | `/100_108_27_54.jks` |
| Log Source | `/var/log/apache2/access.log` |
| Timestamp | `2026-05-23T02:45:29.367Z` |

#### Alert 2 — Common Web Attack (Path Traversal)
| Field | Value |
|---|---|
| Rule ID | 31104 |
| Rule Level | 6 |
| MITRE Techniques | T1055 · T1083 · T1190 — Defense Evasion, Discovery, Initial Access |
| Description | Common web attack |
| Agent Name | `vm-vulnerable` |
| Agent IP | `100.108.27.54` |
| Source IP | `100.117.116.16` |
| Protocol | GET |
| Probed URL | `/../../../../../../../../../../../etc/passwd` |
| Rule Groups | `web, accesslog, attack` |
| Rule Fired Times | **79** |
| Log Source | `/var/log/apache2/access.log` |
| Timestamp | `2026-05-23T02:48:23.640Z` |

---

### Log Analysis

**Step 1 — Automated Directory & File Enumeration (Rule 31151)**

Wazuh ingested Apache access logs and correlated a high volume of HTTP `404` responses all originating from `100.117.116.16` within the same timestamp window. The probed paths reveal a scanner fingerprinting the server for exposed files and known artifacts:

```
100.117.116.16 - [23/May/2026:03:45:28 +0100] "GET /100_108_27_54.jks HTTP/1.1" 404 491
100.117.116.16 - [23/May/2026:03:45:28 +0100] "GET /archive.war HTTP/1.1" 404 491
100.117.116.16 - [23/May/2026:03:45:27 +0100] "GET /100_108_27_54.sql HTTP/1.1" 404 491
```

Targeted extensions (`.jks`, `.war`, `.sql`) are characteristic of **Nikto** — a web vulnerability scanner that probes for Java keystores, application archives, and database dumps. The spoofed User-Agent (`Mozilla/5.0 Chrome/74`) is a common evasion attempt to blend scanner traffic with legitimate browser traffic.

**Step 2 — Path Traversal Attempt (Rule 31104)**

3 minutes later, the same source IP escalated to active exploitation attempts. Wazuh caught a path traversal sequence targeting `/etc/passwd`:

```
100.117.116.16 - [23/May/2026:03:48:23 +0100] "GET /../../../../../../../../../../../etc/passwd HTTP/1.1" 404 491
```

Rule 31104 fired **79 times** — indicating this was not a single probe but a sustained, repeated traversal campaign. The server returned `404` on all attempts, confirming the traversal did not succeed, but the intent to read sensitive system files is unambiguous. This maps to **T1083 (File and Directory Discovery)** and **T1190 (Exploit Public-Facing Application)**.

---

### Analyst Notes

- Same source IP as Incidents 1 & 2 (`100.117.116.16`) — confirms this is part of a coordinated campaign, not an isolated scan
- `.jks` / `.war` / `.sql` probing pattern is a Nikto signature — scanner was not customized or obfuscated beyond a fake User-Agent
- Rule 31104 fired 79 times on the traversal path → high-confidence automated tool, not manual probing
- All responses were `404` → DVWA was not directly compromised via this vector, but server structure and response behavior were enumerated
- Decoder `web-accesslog` confirms Wazuh is parsing `/var/log/apache2/access.log` in real time — detection latency is minimal
- Timeline context: this reconnaissance occurred **after** root access was already obtained (03:01–03:30), suggesting the attacker was mapping additional attack surfaces in parallel

---

### Response Actions Taken

| Step | Action | Tool |
|---|---|---|
| 1 | HTTP flood alert reviewed, source IP correlated to prior incidents | Wazuh SIEM |
| 2 | Path traversal attempts identified and documented | Wazuh SIEM |
| 3 | Source IP already blocked from Incident 1 response | OPNsense blocklist |

> **Note:** No new SOAR-triggered block was needed — `100.117.116.16` was already present in the OPNsense `blocklist_suricata` from the automated response to Incident 1. This demonstrates the value of persistent firewall rule saving.

---

### Evidence

| File | Description |
|---|---|
| Wazuh alert — T1595.002, rule 31151, HTTP 404 flood |
<img width="1893" height="581" alt="image" src="https://github.com/user-attachments/assets/befae479-61dc-4de5-8de4-2fdf8a8db995" />

| Full log detail — `.jks`, `.war`, `.sql` probing from `100.117.116.16` |
<img width="1908" height="690" alt="image" src="https://github.com/user-attachments/assets/b23d206c-6d6c-4839-a61c-cb5ab7c64d86" />


| Wazuh alert — rule 31104, common web attack, T1055/T1083/T1190 |
<img width="1893" height="581" alt="image" src="https://github.com/user-attachments/assets/9dd03e8b-3bd4-4f5d-a897-a66b47e7e795" />


| `wazuh_path_traversal_logs.png` | Full log — `/etc/passwd` traversal attempt, fired 79 times |
<img width="1733" height="738" alt="image" src="https://github.com/user-attachments/assets/a91e65a4-a4b6-436c-b2c8-2e222ac7b95e" />

## Incident 4 — Malware Simulation (EICAR + FIM + VirusTotal)
**Date:** 2026-05-23 22:25–22:26 UTC+1 | **Severity:** HIGH | **MITRE ATT&CK:** T1203 — Execution · T1565.001 — Stored Data Manipulation

---

### Alert Triage

#### Case A — Malicious File Detected

| Field | Value |
|---|---|
| Rule ID | 87105 |
| Rule Level | 12 |
| MITRE Technique | T1203 — Execution |
| Description | VirusTotal: Alert — `/tmp/eicar_test.txt` — 62 engines detected this file |
| Agent Name | `vm-vulnerable` |
| Agent IP | `100.108.27.54` |
| Data Integration | `virustotal` |
| Timestamp | `2026-05-23T21:25:34.500Z` |

| Rule ID | Description | Level |
|---|---|---|
| 554 | File added to the system | 5 |
| 87105 | VirusTotal: 62 engines detected this file | 12 |

#### Case B — Clean File (Baseline Comparison)

| Field | Value |
|---|---|
| Rule ID | 87106 |
| Rule Level | 3 |
| Description | VirusTotal: File scanned — No threats found |
| Timestamp | `2026-05-23T22:26:05.606Z` |

| Rule ID | Description | Level |
|---|---|---|
| 550 | Integrity checksum changed — T1565.001 Impact | 7 |
| 87106 | VirusTotal: File scanned — No threats found | 3 |

---

### Log Analysis

**Case A — Malicious File Drop & Automated Threat Intel Enrichment**

The attacker dropped an EICAR standard test file into `/tmp/eicar_test.txt` on `vm-vulnerable`. This directory was under real-time Wazuh FIM monitoring. The detection chain fired in sequence:

1. **Rule 554** — FIM detected a new file added to the system (`/tmp/eicar_test.txt`)
2. Wazuh automatically extracted the file hash and submitted it to the **VirusTotal API** (native integration, no manual step)
3. **Rule 87105** (level 12) — VirusTotal returned a malicious verdict: **62 out of 72 engines** flagged the file

This entire pipeline — file drop → hash extraction → API submission → verdict — completed automatically with zero analyst interaction.

**Case B — Clean File Modification (Baseline)**

A separate file modification was also captured by FIM on the same host. The pipeline ran identically:

1. **Rule 550** — FIM detected an integrity checksum change on a monitored file (T1565.001 — Impact)
2. Hash submitted automatically to VirusTotal
3. **Rule 87106** (level 3) — VirusTotal returned a clean verdict: **no threats found**

This case validates that the FIM → VirusTotal pipeline runs on **every** monitored file change, not just known-bad files — and that Wazuh correctly distinguishes between malicious (rule 87105) and clean (rule 87106) results, reducing false positive fatigue.

---

### Analyst Notes

- Rule level jump from 5 (file added) to 12 (VT malicious verdict) in under 3 seconds — fully automated enrichment with no analyst action
- 62/72 engines on EICAR is expected — some engines whitelist the test file by design; 62 positive detections still constitutes a confirmed malicious verdict
- The clean file comparison (rule 87106, level 3) is critical for tuning context: the pipeline works symmetrically and does not generate false positives on benign changes
- FIM is monitoring `/tmp` in real-time mode — appropriate for a high-risk directory often abused for staging malware
- T1565.001 (Integrity checksum changed) on the clean file suggests the attacker or a process also modified an existing monitored file — worth correlating with the earlier binary tampering from Incident 1

---

### Response Actions Taken

| Step | Action | Tool |
|---|---|---|
| 1 | FIM alert reviewed — new file in `/tmp` flagged | Wazuh SIEM |
| 2 | VirusTotal verdict ingested automatically — 62/72 malicious | Wazuh → VirusTotal API |
| 3 | Alert escalated for file removal and `/tmp` audit | Manual analyst action |
| 4 | Clean file change reviewed and closed as low severity | Wazuh SIEM |

---

### Evidence

| File | Description |
|---|---|
| Alert list — rule 554 (file added) + rule 87105 (VT malicious, 62 engines) |
<img width="1828" height="206" alt="image" src="https://github.com/user-attachments/assets/d543d9a0-6c31-4553-a05b-48dc3633bdec" />

| Full alert detail — T1203, rule 87105, agent `vm-vulnerable`, integration `virustotal` |
 <img width="1839" height="516" alt="image" src="https://github.com/user-attachments/assets/6a3d0a66-ebb9-4c18-8aa5-40e347a09a1f" />

| Alert list — rule 550 (checksum changed) + rule 87106 (VT clean) |
<img width="1833" height="195" alt="image" src="https://github.com/user-attachments/assets/cab16852-3e70-475a-9ce8-bb42500290e8" />



