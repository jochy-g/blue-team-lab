# blue-team-lab
# Blue Team Detection Lab

A hands-on SOC detection engineering lab: full Active Directory
environment with SIEM instrumentation, adversary simulation, and
custom detection rules. Built to practice SOC L2/L3 skills and
develop detection engineering capabilities.

## Environment

Fully virtualized lab (VirtualBox) on isolated NAT network:

| VM    | Role                  | Purpose |
|-------|-----------------------|---------|
| DC01  | Windows Server 2022   | Active Directory (lab.local) + BadBlood populated |
| WS01  | Windows 10 Enterprise | Domain-joined endpoint |
| KALI  | Kali Linux            | Attacker simulation |
| WAZUH | Ubuntu 22.04          | Wazuh SIEM 4.9.2 (all-in-one) |

Telemetry: Sysmon (SwiftOnSecurity config) on all Windows endpoints
forwarding to Wazuh via agent.

## What's here

### Attack case studies
Full end-to-end scenarios: attacker perspective + defender detection.
Each case includes attack narrative, SIEM detection view, custom
rules developed, and hardening recommendations.

- [Kerberoasting](cases/2026-08-27-kerberoasting/) — T1558.003, credential access

### Custom detection rules
Wazuh rules written to close gaps identified in out-of-the-box
detection. Each rule includes MITRE mapping.

- [detections/wazuh/](detections/wazuh/)

### Lab setup guides
Reproducible step-by-step deployment. Documented every gotcha
encountered along the way.

- [setup/](setup/)

### Operational runbooks
Troubleshooting notes from real problems encountered. Useful
for future SOC work.

- [troubleshooting/](troubleshooting/)

## Skills demonstrated

- Active Directory security (attack + defense)
- SIEM deployment, tuning, custom rule engineering
- MITRE ATT&CK mapping
- Adversary emulation with Impacket, BadBlood
- Systematic troubleshooting under uncertainty
- Technical documentation

## Author

Jochy Méndez — Cybersecurity Consultant | Blue Team
[LinkedIn](https://www.linkedin.com/in/jochy-antonio-mendez-melendez-334a28186/) — [Contact](mailto:tu@email)
