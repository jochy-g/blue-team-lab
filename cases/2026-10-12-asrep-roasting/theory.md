#### What is AS-REP Roasting (T1558.004)

**Kerberos Context:** Normally, when requesting a TGT from the DC (Authentication Service Request, AS-REQ), you must pre-authenticate by sending a timestamp encrypted with your password. Without pre-auth, the DC returns an "AS-REP" ticket containing data encrypted with your password.

**The Gap:** Some accounts have the `DONT_REQ_PREAUTH` flag (Kerberos pre-authentication NOT required). For these accounts, anyone can request an AS-REP without even authenticating. That AS-REP contains data that can be cracked offline.

**Vs. Kerberoasting:**

- Kerberoasting: Requires credentials for any user + target must have an SPN.
- AS-REP Roasting: Does NOT require prior credentials + target must have `DONT_REQ_PREAUTH` set.

**Operational Implication:** An attacker *without* credentials can identify AS-REP-roastable accounts and extract crackable hashes. In a sense, it is worse than Kerberoasting (due to the lower barrier to entry).
