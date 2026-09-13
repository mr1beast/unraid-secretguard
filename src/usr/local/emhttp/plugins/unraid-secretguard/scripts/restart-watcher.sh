#!/bin/bash
set -u
PIDFILE=/run/unraid-secretguard/watcher.pid
if [ -f "$PIDFILE" ]; then
  pid=$(cat "$PIDFILE" 2>/dev/null || true)
  if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null || true; fi
  rm -f "$PIDFILE"
fi
mode=$(awk -F= '/^AUTO_WATCH=/{gsub(/"/,"",$2); print $2}' /boot/config/plugins/unraid-secretguard/settings.cfg 2>/dev/null || true)
[ "${mode:-yes}" = "no" ] && exit 0
nohup /usr/local/emhttp/plugins/unraid-secretguard/scripts/watcher-loop.sh >/dev/null 2>&1 &
