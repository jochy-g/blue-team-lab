# Blue Team Detection Lab

A hands-on SOC detection engineering lab: full Active Directory environment 
with SIEM instrumentation, adversary simulation, custom detection rules, 
LLM-assisted triage, and SOAR automated containment. Built to practice 
SOC L2/L3 and detection engineering, and to publish reproducible case studies.

## What's new

This lab has grown from attack-only detection cases into a **full modern SOC 
pipeline** — detect, enrich with LLM, and contain automatically. Five 
published case studies, 15+ custom detection rules, two Cortex analyzers 
(including a local LLM for privacy-preserving triage), two Cortex responders 
for automated containment, and a custom Docker image. The latest case study 
post reached 1,800+ views and 29 saves on LinkedIn in six days.

## Environment

Fully virtualized lab (VirtualBox) on isolated NAT network `10.10.10.0/24`:

| VM         | OS                   | Role                                                          |
|------------|----------------------|---------------------------------------------------------------|
| DC01       | Windows Server 2022  | Active Directory `lab.local` + BadBlood populated             |
| WS01       | Windows 10 Enterprise| Domain-joined endpoint with Sysmon                            |
| KALI       | Kali Linux           | Attacker simulation (Impacket, BloodHound, etc.)              |
| WAZUH      | Ubuntu 22.04         | Wazuh SIEM 4.9 (all-in-one)                                   |
| SOC-TOOLS  | Ubuntu Server 22.04  | TheHive 5.8 + Cortex 4.1 + Ollama + Elasticsearch 8 + Cassandra|

**Telemetry pipeline:** Sysmon (SwiftOnSecurity config) on Windows endpoints 
→ Wazuh via agent → custom Python integration POSTs alerts to TheHive → 
Cortex analyzers enrich observables (VirusTotal + local Phi-3 via Ollama) → 
Cortex responders contain via WinRM remote PowerShell on DC01.

## What's here

### Published case studies

Each case includes attack narrative, SIEM detection view, custom rules 
developed, defensive hardening recommendations, and public LinkedIn write-up.

- **[Case 1 — Kerberoasting Detection](cases/01-kerberoasting-detection/)** — 
  T1558.003 credential access with 3 custom rules including burst correlation
- **[Case 2 — BloodHound + GenericAll Privilege Escalation](cases/02-bloodhound-genericall-escalation/)** — 
  T1087.002 / T1069.002 / T1482 / T1098 full kill chain with 6 custom rules
- **[Case 3 — AS-REP Roasting Detection](cases/03-asrep-roasting-detection/)** — 
  T1558.004 correlation rule using Wazuh `frequency + timeframe + same_field` syntax
- **[Case 4 — Modern SOC Pipeline with LLM-Assisted Triage](cases/04-modern-soc-workflow-llm/)** — 
  End-to-end detect + enrich. Wazuh → TheHive 5.8 → Cortex 4.1 with 
  VirusTotal + custom OllamaForensics analyzer running local Phi-3 via 
  Ollama for privacy-preserving triage. Custom Cortex Docker image.
- **[Case 5 — SOAR Automated Containment](cases/05-soar-responders-automated-containment/)** — 
  Two custom Cortex responders in Python (BlockIP_Windows, DisableUser_AD) 
  via WinRM remote PowerShell with safety-by-design — protected users list, 
  dedicated service account with least privilege, audit trail. 
  Mean Time To Contain under 60 seconds.

### Custom components

- **[Wazuh detection rules](detections/wazuh/)** — 15+ custom rules with 
  MITRE ATT&CK mapping, including correlation rules with 
  `frequency + timeframe + same_field` syntax
- **[Cortex analyzers](custom-analyzers/)** — OllamaForensics custom analyzer 
  (local LLM via Ollama + Phi-3 Mini for privacy-preserving triage)
- **[Cortex responders](custom-responders/)** — BlockIP_Windows and 
  DisableUser_AD; Python with cortexutils + pywinrm; safety-by-design
- **[Custom Cortex Docker image](custom-images/cortex-custom/)** — 
  Python runtime baked in so custom analyzers persist across reboots

### Lab infrastructure

- **[Setup guides](setup/)** — Reproducible step-by-step deployment with 
  every gotcha documented (vm.max_map_count, LVM extension, NTLM auth, etc.)
- **[Troubleshooting runbooks](troubleshooting/)** — Real problems and 
  resolutions useful for future SOC work

## Skills demonstrated

- **SOC Operations** — Alert triage, incident lifecycle in TheHive, 
  observable enrichment with Cortex analyzers
- **Detection Engineering** — Custom Wazuh rules (Sigma-style), correlation 
  rules, full MITRE ATT&CK mapping
- **SOAR & Response Automation** — Python responder development with 
  cortexutils, WinRM remote PowerShell via pywinrm, service account design 
  with least privilege, safety-by-design patterns (protected users, 
  idempotency, undo instructions)
- **LLM Integration in Security** — Local LLM deployment (Ollama + Phi-3), 
  custom Cortex analyzer for privacy-preserving triage, prompt engineering 
  for forensic analysis, on-prem alternative to commercial LLM APIs
- **Active Directory Security** — Kerberos attacks and detections 
  (Kerberoasting, AS-REP Roasting), AD attack path analysis with BloodHound, 
  SACL audit configuration, privileged account hardening
- **Infrastructure** — Docker, Docker Compose, custom image builds, 
  Elasticsearch and Cassandra stack operations
- **Documentation** — Public write-ups with architecture diagrams, 
  troubleshooting logs, and reproducibility notes

## Tech stack

Wazuh 4.9 · TheHive 5.8 · Cortex 4.1 · Ollama + Phi-3 Mini · Elasticsearch 8 · 
Cassandra 4.1 · Docker · Python 3.11 (cortexutils, pywinrm, requests) · 
PowerShell · Windows Server 2022 + Kerberos · VirusTotal API · MITRE ATT&CK

## Author

**Jochy Méndez** — Cybersecurity Consultant · Detection & Response Engineer  
EY Santo Domingo · Dominican Republic

[LinkedIn](https://www.linkedin.com/in/jochy-antonio-mendez-melendez-334a28186/)
