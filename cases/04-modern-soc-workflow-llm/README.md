# Case 4 — Modern SOC Workflow: AI-Assisted Triage with Ollama + TheHive + Cortex

 **Date:** October 2026 \
 **Author:** Jochy Mendez \
 **Lab:** Personal VirtualBox blue team lab \
 **Tags:** `blue-team` `soar` `siem` `sirp` `llm` `ollama` `wazuh` `thehive` `cortex`

---

## TL;DR

Este caso demuestra un **SOC moderno end-to-end** con enriquecimiento 
asistido por LLM local:

1. **Attack:** AS-REP Roasting desde Kali contra lab AD
2. **Detect:** Wazuh correlaciona con custom rule 100402 (level 12)
3. **Automate:** Custom Python integration envía alerta a TheHive 
   automáticamente (filter by group `attack_pattern`)
4. **Triage:** Analista importa como caso, corre analyzers Cortex
5. **Enrich:** VirusTotal + custom OllamaForensics (local LLM via 
   Ollama + Phi-3 Mini) enriquecen observables

Todo open source. Zero API comercial (opcional). Fully air-gappable.

<img width="2720" height="2480" alt="case4_modern_soc_pipeline" src="https://github.com/user-attachments/assets/293421eb-cd7c-491f-976e-4763f5c770c9" />


---

## Why this matters

En muchos SOCs tradicionales el flujo es manual: analista ve alerta, 
copia observable, pega en VirusTotal, pega en AbuseIPDB, escribe 
hallazgos en ticket. 

Este case demuestra que **el enriquecimiento se puede automatizar 
end-to-end**, incluyendo LLM local que preserva privacidad de datos 
sensibles del cliente (los observables nunca salen del perímetro 
corporativo).

---

## Lab environment

| VM | OS | IP | Role |
|----|----|-----|------|
| DC01 | Windows Server 2022 | 10.10.10.10 | Active Directory (lab.local) |
| WS01 | Windows 10 Enterprise | 10.10.10.20 | Domain-joined endpoint |
| Wazuh | Ubuntu 22.04 | 10.10.10.50 | SIEM (Wazuh 4.9) |
| Kali | Kali Linux | 10.10.10.200 | Attacker |
| SOC-TOOLS | Ubuntu Server 22.04 | 10.10.10.60 | TheHive 5.8 + Cortex 4.1 + Ollama |

![VBox VMs](./screenshots/02-vbox-vms.png)

<img width="1142" height="307" alt="Pasted image 20261019161307" src="https://github.com/user-attachments/assets/72edb571-3cf8-4a1c-8c3f-1d1124ff4990" />

![Docker stack healthy](./screenshots/03-docker-compose-ps.png)

<img width="1042" height="125" alt="Pasted image 20261019161244" src="https://github.com/user-attachments/assets/a451d343-ea50-4735-bdc4-e43be965a183" />


<img width="460" height="43" alt="Pasted image 20261019181648" src="https://github.com/user-attachments/assets/73fcafe4-86d1-4b44-8063-371dc33aadde" />

---

## 1. The attack

**Technique:** AS-REP Roasting (MITRE T1558.004)

AS-REP Roasting explota cuentas AD con la flag `DONT_REQ_PREAUTH`. 
El atacante solicita un TGT via AS-REQ sin autenticarse. El DC responde 
con un AS-REP que contiene material cifrado con el hash NTLM del usuario, 
que el atacante puede crackear offline.

**Comando usado:**

\```bash
impacket-GetNPUsers lab.local/ -dc-ip 10.10.10.10 -no-pass -usersfile targets.txt -format hashcat
\```

![AS-REP attack from Kali](./screenshots/04-kali-asrep-attack.png)
<img width="1257" height="623" alt="Pasted image 20261019161447" src="https://github.com/user-attachments/assets/314bd514-a049-4930-988e-434a9aa100ec" />

---

## 2. Detection — Wazuh custom rules

Dos rules trabajando en cascada:

- **100400** (level 5): baseline — cada Event 4768 (TGT request)
- **100402** (level 12): correlation — 5+ TGT requests en 60s desde 
  misma IP (`same_field: win.eventdata.ipAddress`)

### Design choice: correlación por IP, no por usuario

En AS-REP Roasting el atacante **no está autenticado** (eso es el punto 
de la técnica). Por lo tanto los campos `subjectUserName` o `userName` 
estarán vacíos. Pero la IP origen de todos los AS-REQ sí es constante 
durante la enumeración → correlacionamos por `ipAddress`.

Ver [`artifacts/wazuh-rules.xml`](./artifacts/wazuh-rules.xml) para el XML completo.

![Wazuh alert dashboard](./screenshots/05-wazuh-alert.png)
<img width="1280" height="655" alt="Pasted image 20261019175321" src="https://github.com/user-attachments/assets/05a1bee7-1450-4b72-b331-134f0e1f4f78" />


---

## 3. Automation — Wazuh → TheHive integration

Custom Python integration que:
- Recibe alert JSON de Wazuh via stdin
- Extrae observables automáticamente (IPs, usuarios, hostnames)
- Mapea severity Wazuh (0-15) a TheHive (1-4)
- Envía POST a `/api/v1/alert` de TheHive
- Incluye MITRE tactics/techniques como tags

Archivo: [`artifacts/wazuh-custom-thehive.py`](./artifacts/wazuh-custom-thehive.py)

### Design choice: filter by group, not rule_id

El `<integration>` block en ossec.conf filtra por el group 
`attack_pattern` (que todas mis correlation rules tienen) en vez de 
rule_ids específicos.

**Beneficio:** cada rule nueva que escribo con group `attack_pattern` 
llega automáticamente a TheHive sin modificar ossec.conf. 
Future-proof + escalable.

\```xml
<integration>
  <name>custom-thehive</name>
  <hook_url>http://10.10.10.60:9000/thehive</hook_url>
  <api_key>...</api_key>
  <level>10</level>
  <group>attack_pattern</group>
  <alert_format>json</alert_format>
</integration>
\```

![Integration logs](./screenshots/06-wazuh-integration-logs.png)

---

## 4. SIRP — TheHive case management

Al dispararse el ataque desde Kali, Wazuh correlaciona y la integration 
crea alertas en TheHive automáticamente:

![TheHive alerts list](./screenshots/07-thehive-alerts-list.png)
<img width="1266" height="706" alt="Pasted image 20261019175852" src="https://github.com/user-attachments/assets/aba2d47f-af94-469a-b740-60ff517aab41" />


![Alert detail with observables](./screenshots/08-thehive-alert-detail.png)

Click "Import as Case" → caso creado con los observables heredados: 
IPs del atacante, usuarios target, hostnames afectados.

![Case with observables](./screenshots/09-thehive-case-observables.png)

<img width="1246" height="575" alt="Pasted image 20261019175932" src="https://github.com/user-attachments/assets/adf9bbb2-661c-4842-a702-07e71a3fca5b" />


---

## 5. AI-assisted enrichment — custom OllamaForensics analyzer

Analyzer custom escrito en Python que:
- Recibe un observable (IP, hash, domain, url, mail, fqdn)
- Construye prompt forense para Phi-3 Mini (3.8B params, Microsoft)
- Phi-3 responde con JSON estructurado:
  - `verdict`: safe/suspicious/malicious/info
  - `confidence`: 0-100
  - `reasoning`: 2-3 sentences
  - `recommended_actions`: list of SOC next steps
  - `iocs_to_pivot`: related IOCs to search for

Archivos:
- [`artifacts/cortex-OllamaForensics.py`](./artifacts/cortex-OllamaForensics.py)
- [`artifacts/cortex-OllamaForensics.json`](./artifacts/cortex-OllamaForensics.json)
- [`artifacts/cortex-OllamaForensics-Dockerfile`](./artifacts/cortex-OllamaForensics-Dockerfile)

### Why local LLM

| Dimension | Local LLM | External API (Claude/GPT) |
|-----------|-----------|---------------------------|
| Privacy | ✅ Observables nunca salen | ❌ Datos del cliente a terceros |
| Cost | ✅ Zero API costs | ⚠️ Costo por request |
| Latency | ⚠️ 30-60s per analysis | ✅ 2-5s per analysis |
| Model quality | ⚠️ Phi-3 3.8B | ✅ State-of-the-art |
| Air-gapped SOC | ✅ Funciona sin internet | ❌ Requiere conectividad |

Trade-off aceptable para casos no urgentes donde privacy > latency.

![Analyzers results](./screenshots/10-cortex-analyzers-results.png)
<img width="1273" height="578" alt="Pasted image 20261019181015" src="https://github.com/user-attachments/assets/595febdd-b715-4c8c-ae50-5fe39c13ddb8" />


![LLM JSON output](./screenshots/11-ollamaforensics-json-detail.png)
<img width="1244" height="608" alt="Pasted image 20261019181220" src="https://github.com/user-attachments/assets/993d5481-2f5b-4858-a7e3-a300cc2572de" />


---

## Technical challenges solved

Ver [`notes/troubleshooting-log.md`](./notes/troubleshooting-log.md) 
para el log completo. Highlights:

1. Ubuntu Server LVM default (50% disk) → ES 8 flood_stage watermark
2. vm.max_map_count insufficient for ES 8
3. Nginx template interpolation failure → bypass con ports directos
4. Cortex job runner: python3 missing → workaround con install in-container
5. Ollama default listening en 127.0.0.1 → fix via systemd override

---

## What's next

- Build custom Cortex Dockerfile (persistent Python runtime)
- Add SOAR responders (Cortex active response: block IP, disable user)
- Additional analyzers: MISP, Shodan, Hybrid Analysis
- Grafana dashboard sobre datos Wazuh + TheHive para métricas MTTR, 
  alert volume, analyst workload

---

## References

- MITRE ATT&CK T1558.004: https://attack.mitre.org/techniques/T1558/004/
- Wazuh Integrator docs: https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html
- TheHive 5 API: https://docs.strangebee.com/thehive/api-docs/
- Cortex Analyzer dev: https://github.com/TheHive-Project/CortexDocs/blob/master/api/how-to-create-an-analyzer.md
- Ollama: https://ollama.com/
- Microsoft Phi-3: https://huggingface.co/microsoft/Phi-3-mini-4k-instruct
