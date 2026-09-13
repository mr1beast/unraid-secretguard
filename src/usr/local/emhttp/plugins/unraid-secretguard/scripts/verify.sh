#!/bin/bash
set -euo pipefail
php -l /usr/local/emhttp/plugins/unraid-secretguard/include/SecretGuard.php
php -l /usr/local/emhttp/plugins/unraid-secretguard/scripts/watcher.php
[ -r /boot/config/plugins/dockerMan/templates-user ] || true
echo "SecretGuard runtime files passed basic verification."
