# Case 5 — Troubleshooting Log

## 1. Cortex persistence fix (Bloque 0)

**Síntoma:** OllamaForensics del Case 4 funciona pero requiere re-instalar Python manualmente después de cada `docker compose down`.

**Causa raíz:** imagen `thehiveproject/cortex:4.1.0` upstream no incluye python3. Instalación manual dentro de container no es persistente.

**Fix:**
Construir Dockerfile custom que extiende imagen upstream:

\```dockerfile
FROM thehiveproject/cortex:4.1.0
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages --no-cache-dir cortexutils requests
USER 1001
\```

Build:
\```bash
sudo docker build -t cortex-custom:4.1.0-jochy .
\```

Update docker-compose.yml:
\```yaml
cortex:
  image: "cortex-custom:4.1.0-jochy"
\```

Verificado: `docker compose down && up` + test OllamaForensics → funciona sin intervención manual.

---

## 2. Docker-compose variable corruption during edit

**Síntoma:** `invalid reference format` al levantar Cortex con imagen custom.

**Causa raíz:** Al editar el valor de `image:` con nano, reemplacé solo el contenido de `${...}` en vez de toda la línea. Resultado:
\```yaml
image: "thehiveproject/cortex:${cortex-custom:4.1.0-jochy}"
\```
Docker intentaba usar "thehiveproject/cortex:" + variable (que no existe y tiene `:` inválido en nombre de variable).

**Fix:**
\```bash
sed -i 's|image: "thehiveproject/cortex:\${cortex-custom:4.1.0-jochy}"|image: "cortex-custom:4.1.0-jochy"|g' docker-compose.yml
\```

**Lesson:** cuando se reemplaza una línea con nano, borrar toda la línea y reescribir, no editar in-place.

---

## 3. WinRM credentials escaping hell

**Síntoma:** `InvalidCredentialsError` desde el container del responder, aunque las mismas credenciales funcionan desde el host.

**Diagnóstico:** El responder report mostraba `lab\\svc-soc-automation` (doble backslash literal) en el error. Trazamos a:

- JSON del responder: `"defaultValue": "lab\\\\svc-soc-automation"` (4 backslashes en JSON = 2 reales en string)
- pywinrm NTLM espera `lab\svc-soc-automation` (1 backslash)

**Fix: UPN format elimina el problema completamente.**

Cambiar de `DOMAIN\user` a `user@domain.local`:
- En Cortex UI → svc_username: `svc-soc-automation@lab.local` (o solo `svc-soc-automation` sin dominio)

**Lesson aplicable:** cuando trabajes con credenciales Windows en configs JSON/YAML/TOML, SIEMPRE preferir UPN format. Backslashes en configs anidadas son fuente garantizada de bugs.

---

## 4. "TheHive dice success pero responder no se ejecutó" diagnóstico

**Síntoma:** TheHive UI muestra "Responder ran successfully" pero `docker ps -a` no muestra container del responder.

**Red herring:** inicialmente pensé que Cortex no podía ejecutar containers.

**Causa real:** Cortex usa `--rm` al lanzar containers de analyzers/responders. Después de ejecutar, el container se auto-elimina. No queda en `docker ps -a`.

**Para debugging real:** ver logs de Cortex (`docker compose logs cortex`) que captura stdout/stderr del container antes de que se elimine.

**Lesson:** no asumir que ausencia en `docker ps -a` significa "no ejecutó". Verificar con logs de orquestrador.

---

## 5. Responder dataTypeList affects visibility in TheHive

**Síntoma:** Responder visible y Enabled en Cortex, pero no aparece al click "Run Responder" en TheHive.

**Causa raíz:** `"dataTypeList": ["thehive:case_artifact"]` por sí solo no es suficiente para que TheHive asocie el responder a observables específicos.

**Fix:** incluir también los dataTypes del observable: `["thehive:case_artifact", "ip"]` para BlockIP, `["thehive:case_artifact", "other", "mail", "username"]` para DisableUser.
