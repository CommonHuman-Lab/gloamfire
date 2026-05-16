#!/bin/bash
set -e

echo "[gloamfire-agent] Waiting for wazuh.manager:1514..."
until (echo > /dev/tcp/wazuh.manager/1514) 2>/dev/null; do
    sleep 5
done
echo "[gloamfire-agent] Manager reachable — starting Wazuh agent"

/var/ossec/bin/wazuh-control start

# Stream agent log so Docker captures it, keeping the container alive
exec tail -f /var/ossec/logs/ossec.log
