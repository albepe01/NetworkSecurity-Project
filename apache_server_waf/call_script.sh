#!/bin/bash

echo "Script executed at $(date)" >> /var/log/modsec_payload.log

# Legge il payload dallo stdin
PAYLOAD="${MODSEC_PAYLOAD}"

# Verifica se il payload è vuoto
if [ -z "$PAYLOAD" ]; then
  echo "No payload received" >> /var/log/modsec_payload.log
  exit 1
fi

echo "Received payload: $PAYLOAD" >> /var/log/modsec_payload.log

# Passa il payload allo script Python
output = $(/usr/local/bin/python3.9 /etc/modsecurity/decision_script.py "$PAYLOAD")

if [ "$output" == "Blocked" ]; then
    # Se il classificatore segnala un attacco
    echo "ModSecurity+ML: Potential SQL Injection detected. Blocking query: $PAYLOAD"
    exit 1
elif [ "$output" == "Allow" ]; then
    # Query consentita
    echo "Allowed: Query is safe. Payload: $PAYLOAD"
    exit 0
else
    # Caso in cui l'output non sia riconosciuto (errore)
    echo "Error: Unexpected response from classifier. Output: $output"
    exit 2
fi

