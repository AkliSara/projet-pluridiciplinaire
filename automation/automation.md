# automation/

Wazuh configuration files for the SOC/SIEM lab — custom detection rules, outbound integrations, and automated host-level response.

---

## Files

### `local_rules.xml`
**Path on server:** `/var/ossec/etc/rules/local_rules.xml`

Custom detection rules extending Wazuh's native capabilities. Covers:

| Rule ID | Trigger | Level | MITRE |
|---------|---------|-------|-------|
| 100001 | SSH auth failure baseline | 5 | — |
| 100002 | 3+ SSH failures in 60s from same IP | 12 | T1110.001 |
| 100003 | SSH success immediately after brute force | 15 | T1110.001 |
| 100004 | sudo to root executed | 10 | T1548.003 |
| 100005 | New local user account created | 10 | T1136.001 |
| 100006 | `/etc/shadow` modified | 12 | T1003.008 |
| 100007 | `/etc/passwd` modified | 10 | T1136.001 |

---

### `integrations.xml`
**Path on server:** paste inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`

Two outbound integrations:

- **VirusTotal** — on any FIM event (rules 550–554), Wazuh extracts the file hash and queries VirusTotal. A malicious verdict escalates the alert to level 7.
- **Shuffle SOAR** — any alert level ≥ 10 fires a webhook to the Shuffle instance, triggering the automated playbook (Discord notification → OPNsense IP block).

---

### `active_response.xml`
**Path on server:** paste inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`

Host-level containment block. When brute force rules fire, Wazuh instructs the target agent to drop all inbound traffic from the offending IP via local firewall tables. Block duration: **600 seconds**.

---

## Deployment

1. Copy `local_rules.xml` content into `/var/ossec/etc/rules/local_rules.xml`
2. Paste `integrations.xml` and `active_response.xml` blocks into `/var/ossec/etc/ossec.conf` inside `<ossec_config>`
3. Restart the Wazuh manager:
   ```bash
   sudo systemctl restart wazuh-manager
   ```
4. Verify rules loaded without errors:
   ```bash
   sudo /var/ossec/bin/wazuh-logtest
   ```
