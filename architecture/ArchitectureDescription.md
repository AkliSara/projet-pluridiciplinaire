# Responsive SOC/SIEM Architecture Lab


## Overview

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

