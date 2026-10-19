```
#!/bin/sh
# Wazuh integrator calls this with: $1=alert_json_file $2=api_key $3=hook_url
WPYTHON_BIN="framework/python/bin/python3"
SCRIPT_PATH_NAME="$0"
DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"
PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"

if [ -x "/var/ossec/${WPYTHON_BIN}" ]; then
    /var/ossec/${WPYTHON_BIN} "${PYTHON_SCRIPT}" "$@"
else
    python3 "${PYTHON_SCRIPT}" "$@"
fi
```
