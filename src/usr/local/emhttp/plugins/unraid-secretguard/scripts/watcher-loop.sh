#!/bin/bash
set -u
PIDFILE=/run/unraid-secretguard/watcher.pid
mkdir -p /run/unraid-secretguard
chmod 700 /run/unraid-secretguard
printf '%s\n' $$ > "$PIDFILE"
trap 'rm -f "$PIDFILE"' EXIT
while true; do
  php /usr/local/emhttp/plugins/unraid-secretguard/scripts/watcher.php >/dev/null 2>&1 || true
  sleep 8
done
