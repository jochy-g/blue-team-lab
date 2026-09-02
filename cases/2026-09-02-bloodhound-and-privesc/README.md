# BloodHound Analysis + GenericAll Privilege Escalation Attempt

**Date:** 2026-09-02
**Environment:** lab.local (BadBlood-populated, ~2500 users)
**Attacker start:** DELLA_GUERRERO (compromised via previous Kerberoasting case)
**Objective:** Enumerate AD attack paths, attempt privilege escalation to Domain Admin

## MITRE ATT&CK

- T1087.002 — Account Discovery: Domain Account
- T1069.002 — Permission Groups Discovery: Domain Groups
- T1482 — Domain Trust Discovery
- T1018 — Remote System Discovery
- T1098 — Account Manipulation (password reset)
- T1078.002 — Valid Accounts: Domain Accounts
- T1484.001 — Domain Policy Modification (attempted)

## Phase 1 — Reconnaissance with BloodHound

### Collection execution
​```bash
bloodhound-python \
  -u DELLA_GUERRERO -p 'LabUser2026!' \
  -d lab.local -ns 10.10.10.10 -c All --zip
​```

**Result:** 25 MB of AD relationship data extracted:
- 2500+ users (20.5 MB of user objects)
- 500+ groups
- 145 computers
- 89 OUs
- 45 GPOs

Second collection performed as TAD_HINTON (kerberoasted service
account from previous case) for comparative analysis.

## Phase 2 — Critical detection finding: Windows audit policy gap

### Initial observation
During BloodHound collection, Wazuh registered only 7 Event 4662
despite the collector extracting 25 MB of AD data (thousands of
LDAP queries).

### Root cause investigation
Windows AD auditing operates in TWO layers:


**Layer 1 — auditpol (OS-level):**
​```
Directory Service Access             Success (default, insufficient)
Directory Service Changes            No Auditing
​```

**Layer 2 — SACLs (object-level):**
Default AD setup has NO SACLs on domain root or high-value objects.
Without SACLs, only internal system operations are audited by default.

### Verification
Sample 4662 event captured had:
- subjectUserSid: S-1-5-18 (SYSTEM)
- subjectUserName: DC01$ (machine account, internal traffic)

**Attacker (DELLA_GUERRERO) LDAP queries generated ZERO 4662 events**
before applying fixes.

### Fix applied

**auditpol enable:**
​```powershell
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
​```

**SACL on domain root (Everyone/GenericAll/Success):**
​```powershell
$domainDN = (Get-ADDomain).DistinguishedName
$acl = Get-Acl -Path "AD:$domainDN"
$everyone = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $everyone,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AuditFlags]::Success,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
)
$acl.AddAuditRule($ace)
Set-Acl -Path "AD:$domainDN" -AclObject $acl
​```

### Impact measured

| Configuration                  | 4662 events for full BloodHound run     |
| ------------------------------ | --------------------------------------- |
| Default (no auditpol, no SACL) | 0                                       |
| auditpol only, no SACL         | 1 (SYSTEM internal, attacker invisible) |
| auditpol + domain root SACL    | 200+ (attacker identity captured)       |

### Real-world implication

Many production SIEM deployments have Layer 1 (auditpol) without
Layer 2 (SACLs). The result: BloodHound / SharpHound recon is
effectively invisible via 4662 events despite "auditing being enabled".

This is a common finding in AD security assessments that most
defenders don't realize they have.

## Phase 3 — Custom detection rules

Three rules developed to close the detection gap:

| Rule ID | Level | Purpose |
|---------|-------|---------|
| 100200 | 5 | Baseline visibility for all 4662 events |
| 100201 | 10 | LDAP burst correlation (15+ queries in 60s) |
| 100202 | 12 | Sustained enumeration (50+ queries in 120s) |

MITRE-tagged for T1087.002, T1069.002, T1482, T1018.

Full source: [detections/wazuh/bloodhound-detection.xml]

### Rule tuning insight
Initial thresholds (50/60s and 200/120s) were reduced empirically
to 15/60s and 50/120s. Real environments generate fewer 4662 events
than expected without SACL coverage, requiring calibration.

**Detection engineering principle validated:** thresholds must be
calibrated against real telemetry from the environment, not chosen
from generic values.

## Phase 4 — Attack path identified

BloodHound revealed the following path from DELLA_GUERRERO to
Domain Admins:

​```
DELLA_GUERRERO
  → MemberOf → DOMAIN USERS
  → GenericAll → DANTE_BARRETT (user)
  → MemberOf → AM-ELAMIG029-DISTLIST (group)
  → GenericAll → USERS (container)
  → Contains → DOMAIN ADMINS
​```

**Analysis:** 5 hops from a compromised low-priv user to Domain Admin
via misconfigured ACLs. No exploits required — only permission abuse.

## Phase 5 — Attack execution (partial)

### Step 1 — Password reset via GenericAll (SUCCESS)
As DELLA_GUERRERO on WS01:
​```powershell
net user DANTE_BARRETT "P@wnedByJochy2026!" /domain
​```

**Result:** password changed successfully.

**Detection:** Event 4738 generated on DC01 (NOT 4724 — see finding
below). Custom rule 100300 (level 10) fired correctly.

### Detection engineering finding: 4724 vs 4738

The `net user X /domain` command modifies passwords via SAM API,
generating event 4738 (Account changed) — NOT event 4724 (Password
reset attempted) as many detection rules assume.

**Impact:** Rules built ONLY around 4724 miss common password reset
attacks executed via net.exe. Coverage requires both event IDs
plus 4723 for full account manipulation detection.

Updated rule 100300 now captures 4738, 4724, and 4723.

### Step 2 — Impersonation (SUCCESS)
Logged into WS01 as DANTE_BARRETT with new password.
Event 4624 (successful logon) generated and correlated.

### Step 3 — Domain Admin addition (PARTIAL / BLOCKED)
As DANTE_BARRETT:
​```powershell
net group "Domain Admins" DANTE_BARRETT /add /domain
# Result: Access denied
​```

### Analysis of blocked step

BloodHound edge showed `AM-ELAMIG029-DISTLIST → GenericAll → USERS
container → Contains → DOMAIN ADMINS`. In practice:

- GenericAll on a CONTAINER (Users) does NOT automatically grant
  permissions on the objects within (specifically Domain Admins group)
- The "Contains" edge represents directory structure, not privilege
- Exploitation would require additional ACL manipulation steps
  using PowerView, Impacket, or manual ADSI operations

Attack halted at this step. Full chain exploitation is possible
with additional techniques but was out of scope for this session.

## Phase 6 — Escalation detection rules (deployed but partially validated)

Three rules developed for the escalation chain:

| Rule ID | Level | Trigger |
|---------|-------|---------|
| 100300 | 10 | Password/account modification (4724, 4738, 4723) |
| 100301 | 14 | Addition to privileged group (4728/4732/4756 with DA/EA/SA) |
| 100302 | 15 | Chain correlation: password change + priv group add |

Rules 100300 confirmed firing on real events.
Rules 100301 / 100302 would fire on successful escalation
(untested this session due to attack halt).

## Hardening recommendations

### Immediate (addresses discovered paths)
1. **Remove GenericAll from Domain Users on user objects** — this
   is the pivot enabling initial escalation. Should never exist by
   default; audit and remove case-by-case.
2. **Audit distribution lists with elevated permissions** — 
   AM-ELAMIG029-DISTLIST-style groups with ACL rights over
   containers are BadBlood-generated but mirror real production
   technical debt.
3. **Implement Tier 0/1/2 administrative model** — separate
   accounts for DA operations from daily-use accounts.

### Detection layer
4. **Configure Windows audit policy properly on ALL DCs:**
   - auditpol: DS Access and DS Changes → Success + Failure
   - SACL on domain root: minimum Everyone/GenericAll/Success
5. **Deploy custom Wazuh rules** (or equivalent for other SIEMs):
   - LDAP recon burst detection
   - Password modification correlation
   - Privileged group membership change (CRITICAL level)
   - Chain correlation across multiple events
6. **Cross-reference SIEM alerts with Windows Event Log** during
   incident response — SIEM coverage is not guaranteed complete
   without validated pipeline health.

### Preventive
7. **Regularly run BloodHound as blue team** — identify new attack
   paths introduced by daily AD changes
8. **Baseline group memberships and alert on changes** — Event 4728
   should be a CRITICAL alert requiring immediate investigation

## Portfolio value

This case demonstrates skills expected of mid-level SOC / Detection
Engineering roles:

1. **Systematic troubleshooting under uncertainty** — diagnosed
   audit policy gap through empirical testing, not assumption
2. **Detection engineering** — wrote and calibrated custom rules
   based on real telemetry, not generic thresholds
3. **Attack chain understanding** — recognized that "Contains" edge
   in BloodHound requires additional exploitation steps
4. **Honest reporting** — documented partial attack execution
   accurately rather than fabricating success
5. **Blue-team perspective on offensive tooling** — used BloodHound
   as both attacker (recon) and defender (detection design) tool

## Files
- `README.md` — this write-up
- `screenshots/` — attack path visualization, custom rule alerts,
  audit policy comparison
- `rules/bloodhound-detection.xml` — Wazuh rules 100200-100202
- `rules/escalation-detection.xml` — Wazuh rules 100300-100302

## Related cases
- [2026-08-27 Kerberoasting](../2026-08-27-kerberoasting/) — how
  DELLA_GUERRERO credentials were initially obtained
