## Lab hygiene — password expiration in long-pause environments

Default AD domain password policy expires passwords every 42 days.
After pauses > 42 days, lab accounts become unauthenticatable
without password reset.

### Symptoms
- Impacket LDAP binds fail with "data 532" (password expired)
- AS-REP Roasting against expired accounts may not generate 4768
  depending on tool behavior
- Authenticated recon tools fail silently or with cryptic errors

### Mitigation for labs
- Set PasswordNeverExpires=$true on all BadBlood-generated accounts
  immediately after population
- Document reset procedure in lab runbook for post-pause recovery
- Snapshot AD state before extended pauses

### Real-world implication
In production environments, service accounts hitting expiration
is a common incident cause. SOC analysts should know that
authentication failures spike around 42-day boundaries from
account provisioning dates.
