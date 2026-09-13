#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/src"; OUT="$ROOT/dist"; NAME="unraid-secretguard"; VERSION="0.4.1"
mkdir -p "$OUT"; TAR="$OUT/${NAME}-${VERSION}.tar.gz"; PLG="$OUT/${NAME}.plg"; rm -f "$TAR" "$PLG"
tar -C "$SRC" -czf "$TAR" .; B64=$(base64 -w 0 "$TAR")
cat > "$PLG" <<PLG
<?xml version='1.0' standalone='yes'?>
<!DOCTYPE PLUGIN [
<!ENTITY name "unraid-secretguard">
<!ENTITY author "mr1beast">
<!ENTITY version "$VERSION">
<!ENTITY pluginURL "https://github.com/mr1beast/unraid-secretguard/releases/latest/download/unraid-secretguard.plg">
<!ENTITY launch "Settings/SecretGuard">
]>
<!-- Repository: https://github.com/mr1beast/unraid-secretguard -->
<PLUGIN name="&name;" author="&author;" version="&version;" launch="&launch;" pluginURL="&pluginURL;" min="6.12.0" icon="secretguard.png">
<CHANGES>
### 0.4.1
- Added Unraid plugin update URL using GitHub Releases.
- Installed plugin now checks:
  https://github.com/mr1beast/unraid-secretguard/releases/latest/download/unraid-secretguard.plg
- No migration, rollback, vault, scanning, recreation, UI or icon behavior changed.

### 0.4.0
- First GitHub-ready public beta release.
- Publisher changed to mr1beast.
- Based on the tested v0.3.5 codebase.
- SecretGuard audits installed Docker templates only.
- Migrates likely credentials into managed env files or encrypted Vault storage.
- Automatically recreates containers after protection changes.
- Shows protection status per installed container.
- Supports variable-level rollback without restoring whole XML snapshots.
- Includes User Utilities tile and matching Plugins icon.
- Keeps audit columns aligned across container sections.

### &version;
- Align Docker audit columns across all container sections.
- Use a fixed shared grid for Move, Variable, Risk, Value and Reason.
- UI-only change based on the working v0.3.4 build; no backend, icon, migration, rollback, vault or recreation logic changed.

### &version;
- Plugins-page icon fix only.
- Package the existing SecretGuard logo at both plugin root and images/secretguard.png, matching Unraid Plugin Manager lookup behavior.
- Keep icon="secretguard.png" as a bare filename.
- No UI, migration, rollback, scan, vault, recreate or layout behavior changed from v0.3.1.

### &version;
- Reworked rollback to be variable-level instead of restoring an XML snapshot.
- SecretGuard no longer creates XML backups for new migrations or rollback operations.
- Each migrated variable stores its original Docker Config attributes and human-readable description as comments in the managed env data.
- Rollback restores only those protected variables, removes only SecretGuard's env-file argument, deletes the managed env/vault/runtime file, and recreates the container.
- Unrelated template changes such as ports, paths, labels and later edits are left untouched.
- Legacy env files without per-variable metadata are detected and rollback is refused safely instead of guessing.

### &version;
- Automatically recreate a container immediately after protecting secrets, using Unraid's native update_container helper.
- Preserve stopped/running state when recreating where possible.
- Add a Protection overview showing which installed containers are currently SecretGuard-protected and how many variables are protected.
- Add one-click Rollback: restore the oldest pre-SecretGuard XML snapshot, delete the container's SecretGuard env/vault/runtime file, and recreate the container.
- Create a fresh pre-rollback safety backup before restoring.
- Scan only templates for containers currently installed in Docker (docker ps -a).
- Ignore stale/unused XML templates in both manual audit and background watcher.
- Fail closed: if Docker cannot be queried, SecretGuard scans no templates instead of scanning everything.

- Fixed valid Unraid form submissions being rejected as "Invalid CSRF token".
- Forms still include Unraid csrf_token fields; redundant page-level CSRF revalidation was removed.
- Added a dedicated SecretGuard shield-and-lock logo for the User Utilities tile.
- SecretGuard now visually matches normal Unraid utility tiles while keeping the full settings page behind the tile.
- Kept the dedicated Settings > User Utilities navigation and all v0.2.2 security functionality.

### 2026.09.13.4
- Moved SecretGuard to a dedicated tile under Settings > User Utilities.
- Clicking the tile opens the full SecretGuard configuration/audit page.
- Kept the flash-filesystem-safe extraction fix from v0.2.1.
- Fixed watcher/install guidance to point to User Utilities.

### 2026.09.13.3
- Fixed installation on Unraid flash filesystems by not restoring archive ownership/mode metadata.

### 2026.09.13.2
- Added Encrypted Vault mode for unencrypted secret storage.
- Argon2id (when PHP sodium is available) with PBKDF2 fallback; authenticated encryption.
- Master password is never persisted; derived key and decrypted env files live only in /run.
- Added watcher for new/changed Docker templates with native Unraid notifications.
- Moved template backups off /boot; vault-mode backups are encrypted.
- Added explicit warning about Docker metadata on unencrypted Docker storage.
</CHANGES>
<FILE Name="/tmp/unraid-secretguard.tar.gz.b64"><INLINE>$B64</INLINE></FILE>
<FILE Run="/bin/bash" Method="install"><INLINE><![CDATA[
set -e
base64 -d /tmp/unraid-secretguard.tar.gz.b64 > /tmp/unraid-secretguard.tar.gz
mkdir -p /usr/local/emhttp/plugins/unraid-secretguard /boot/config/plugins/unraid-secretguard
tar --no-same-owner --no-same-permissions -xzf /tmp/unraid-secretguard.tar.gz -C /
chmod 700 /boot/config/plugins/unraid-secretguard
chmod 755 /usr/local/emhttp/plugins/unraid-secretguard/scripts/*.sh 2>/dev/null || true
rm -f /tmp/unraid-secretguard.tar.gz /tmp/unraid-secretguard.tar.gz.b64
/usr/local/emhttp/plugins/unraid-secretguard/scripts/restart-watcher.sh >/dev/null 2>&1 || true
if [ -f /boot/config/plugins/unraid-secretguard/vault.json ]; then
  /usr/local/emhttp/webGui/scripts/notify -e "Unraid SecretGuard" -s "SecretGuard vault locked" -d "Encrypted Vault is locked after plugin install/reboot. Open Settings > User Utilities > Unraid SecretGuard and unlock it before recreating containers that use vault env files." -i warning >/dev/null 2>&1 || true
fi
echo "Unraid SecretGuard installed. Open Settings -> User Utilities -> Unraid SecretGuard."
]]></INLINE></FILE>
<FILE Run="/bin/bash" Method="remove"><INLINE><![CDATA[
if [ -f /run/unraid-secretguard/watcher.pid ]; then kill "\$(cat /run/unraid-secretguard/watcher.pid)" 2>/dev/null || true; fi
rm -rf /run/unraid-secretguard /usr/local/emhttp/plugins/unraid-secretguard
# Preserve persistent settings/vault metadata; encrypted/plain secret files live in the user-selected secret directory.
echo "Unraid SecretGuard removed. Persistent settings and vault metadata were preserved in /boot/config/plugins/unraid-secretguard."
]]></INLINE></FILE>
</PLUGIN>
PLG
cat > "$OUT/install-local.sh" <<'INSTALL'
#!/bin/bash
set -euo pipefail
PLG="${1:-/boot/config/plugins/unraid-secretguard.plg}"
[ -f "$PLG" ] || { echo "Usage: $0 /path/to/unraid-secretguard.plg" >&2; exit 1; }
cp -f "$PLG" /boot/config/plugins/unraid-secretguard.plg
plugin install /boot/config/plugins/unraid-secretguard.plg
INSTALL
chmod +x "$OUT/install-local.sh"; sha256sum "$PLG" "$TAR" > "$OUT/SHA256SUMS"
