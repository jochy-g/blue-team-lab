# Case 4 — Troubleshooting Log

Problemas reales encontrados durante deployment, con causa raíz y resolución.
Esta sección demuestra ingeniería real, no un "happy path" idealizado.

## 1. Ubuntu Server LVM default (50% disk assignment)

**Síntoma:** Elasticsearch 8 refusing to allocate shards. 
Error: `UnavailableShardsException: at least one primary shard for the index [.security-7] is unavailable`.

**Causa raíz:** Ubuntu Server crea LV del tamaño de ~50% del disco virtual 
por default. Con 40GB asignados, el LV solo usaba 20GB. ES 8 por default 
refuses to allocate when disk usage >85% (flood_stage watermark).

**Diagnóstico:**
\```bash
df -h /
# /dev/mapper/ubuntu--vg-ubuntu--lv   19G   17G  942M  95%
\```

**Fix:**
\```bash
sudo lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv
sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv
\```

## 2. vm.max_map_count insufficient for Elasticsearch 8

**Síntoma:** ES bootstrap check failures en logs.

**Fix:**
\```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
\```

## 3. Elasticsearch 8 reserved user password hash corruption

**Síntoma:** `failed to retrieve password hash for reserved user [elastic]` 
después de múltiples boots fallidos.

**Fix:** Wipe de volúmenes y start limpio.

## 4. Nginx template interpolation failure

**Síntoma:** Nginx responde con 404 porque `${SERVER_NAME}` no se expande.
Logs muestran: `server: ${server_name:-localhost}`.

**Workaround:** Bypass nginx exponiendo puertos directos:
- http://127.0.0.1:9000/thehive
- http://127.0.0.1:9001/cortex

## 5. Cortex job runner config (process vs docker)

**Síntoma:** `Cannot run program ".../OllamaForensics.py" (in directory 
"/opt/cortexneurons/analyzers"): error=13, Permission denied` seguido de 
`env: 'python3': No such file or directory`.

**Causa raíz:** Cortex container no incluye Python en su imagen base. 
Job runner por default es `[process]` y intenta ejecutar Python nativo.

**Workaround (no persistente):**
\```bash
sudo docker compose exec cortex bash -c "apt-get update && apt-get install -y python3 python3-pip && pip3 install --break-system-packages cortexutils requests"
\```

**Fix pendiente (sesión siguiente):** Construir Dockerfile custom que 
extienda imagen de Cortex con python3 incluido.

## 6. Permissions on cortex/cortex-jobs

**Síntoma:** `java.nio.file.AccessDeniedException: /tmp/cortex-jobs/...`

**Fix:**
\```bash
sudo chown -R $(id -u):$(id -g) cortex/cortex-jobs/
sudo chmod -R 777 cortex/cortex-jobs/
\```

## 7. Ollama default listening on 127.0.0.1

**Síntoma:** Containers de analyzer no pueden alcanzar Ollama API.

**Fix:**
\```bash
sudo mkdir -p /etc/systemd/system/ollama.service.d
sudo tee /etc/systemd/system/ollama.service.d/override.conf > /dev/null << 'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
EOF
sudo systemctl daemon-reload
sudo systemctl restart ollama
\```
