# Responsive SOC/SIEM Architecture Lab

> **Projet Pluridisciplinaire — USTHB, Faculty of Computer Science | 2025–2026**  
> Instructor: Mr. Halim Zaidi

## Overview

A fully functional, open-source Security Operations Center (SOC) lab built from scratch, covering the complete **detect → enrich → contain → notify** lifecycle across a segmented network environment.

The architecture validates automated threat detection and near-instant network-level remediation without any proprietary commercial platforms, in compliance with **NIST SP 800-61** and **NIST SP 800-125B**.

## Architecture

Four isolated VLANs distributed across physical machines interconnected via **Tailscale VPN**:

| VLAN | Role | Key Hosts |
|------|------|-----------|
| VLAN 10 — Users | Victim endpoints | Windows 10 (Sysmon), Ubuntu Desktop |
| VLAN 20 — Servers | Target services | Windows Server AD/DC, DVWA, File Server |
| VLAN 30 — Security | SOC stack | Wazuh SIEM, Shuffle SOAR |
| Attacker Zone | Red team | Kali Linux |

## Stack

| Layer | Tool |
|-------|------|
| Firewall / IPS | OPNsense + Suricata (Emerging Threats ruleset) |
| SIEM / EDR | Wazuh + Microsoft Sysmon |
| SOAR | Shuffle |
| Threat Intel | VirusTotal API |
| Alerting | Discord Webhooks |
| VPN Overlay | Tailscale (WireGuard) |

## Attack Scenarios Validated

All scenarios are mapped to the **MITRE ATT&CK** framework and the **Cyber Kill Chain**:

1. **Network Reconnaissance** — Nmap scanning (T1046, T1595)
2. **SSH Brute Force & Initial Access** — Hydra + rockyou.txt (T1110.001, T1078)
3. **Privilege Escalation & Persistence** — sudo abuse, backdoor account (T1548.003, T1136.001)
4. **Web Probing** — Nikto against DVWA (T1595)
5. **Malware Simulation** — EICAR drop + VirusTotal enrichment (T1105, T1204)

## Automated Response Flow

```
Wazuh Alert (level ≥ 10)
  → Shuffle SOAR webhook
    → Discord SOC notification
    → OPNsense API: append attacker IP to drop list
    → OPNsense API: apply & commit firewall ruleset
```

Host-level containment: Wazuh active response blocks the offending IP via local firewall tables (600 s timeout).

## Team

| Member |
|--------|
| Ammouche Abderraouf |
| Akli Sara |
| Kaddache Mey Quatre El Nada |
| Touati Inas |
