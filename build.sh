#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/src"; OUT="$ROOT/dist"; NAME="unraid-secretguard"; VERSION="2026.09.18.5"
mkdir -p "$OUT"; TAR="$OUT/${NAME}-${VERSION}.tar.gz"; PLG="$OUT/${NAME}.plg"; rm -f "$TAR" "$PLG"
tar -C "$SRC" -czf "$TAR" .; B64=$(base64 -w 0 "$TAR")
cat > "$PLG" <<PLG
<?xml version='1.0' standalone='yes'?>
<!DOCTYPE PLUGIN [
<!ENTITY name "unraid-secretguard">
<!ENTITY author "mr1beast">
<!ENTITY version "$VERSION">
<!ENTITY pluginURL "https://raw.githubusercontent.com/mr1beast/unraid-secretguard/main/unraid-secretguard.plg">
<!ENTITY launch "Settings/SecretGuard">
]>
<PLUGIN name="&name;" author="&author;" version="&version;" launch="&launch;" pluginURL="&pluginURL;" min="6.12.0" icon="secretguard.png">
<CHANGES>
### 2026.09.18.5
- Validate the public Unraid plugin update channel from 2026.09.18.4.
- Version and changelog only; no runtime, UI or security behavior changed.

### 2026.09.18.4
- Enable Unraid plugin update checks through the public GitHub main-branch manifest.
- pluginURL: https://raw.githubusercontent.com/mr1beast/unraid-secretguard/main/unraid-secretguard.plg
- No SecretGuard migration, Vault, rollback, storage, Docker recreation or UI behavior changed.

### 2026.09.18.3
- Make Overview the default landing tab.
- Move Protection overview and Docker template audit onto the Overview tab.
- Group Secret storage, Dedicated SecretGuard share and Encrypted Vault together on one Settings tab.
- UI-only change; SecretGuard backend behavior is unchanged.

### 2026.09.18.1
- Split Secret storage, Dedicated SecretGuard share and Encrypted Vault into separate tabs.
- Keep Protection overview and Docker template audit visible below the tabbed settings area.
- Remember the selected settings tab in the browser.
- UI-only change; SecretGuard backend behavior is unchanged.

### 2026.09.18
- Collapse Docker audit containers by default using an expandable accordion layout.
- Show per-container variable count and HIGH/MEDIUM finding summary in the collapsed row.
- Keep the existing migration form and variable table unchanged inside each expanded container.
- UI-only change; no migration, Vault, storage, rollback or container recreation logic changed.

### 2026.09.13.6
- Add optional one-click creation of a dedicated Unraid share named secretguard.
- Pin the share to the selected physical disk/pool and disable SMB/NFS export.
- SecretGuard uses the direct physical path instead of /mnt/user/secretguard.
- Refuse to overwrite an existing non-SecretGuard share or non-empty directory.

### 2026.09.13.5
- Discover mounted persistent Unraid storage instead of assuming a cache pool exists.
- Always show cache as the conventional option; mark it NOT MOUNTED / NOT PERSISTENT when absent.
- Prefer mounted encrypted storage and block Plain env migration on rootfs/tmpfs/RAM or unmounted pool paths.
- Add safe Delete / Reset Vault.
- Improve Plugins-page title and description.

### 0.5.0
- Harden Vault lock/unlock and reboot lifecycle.
- Add staged and verified master-password change.
- Add unlock rate limiting, logging and notifications.
- Wrong passwords never automatically delete Vault data.

### 0.4.0
- First GitHub-ready public beta.
- Scan installed Docker templates and migrate likely credentials to managed env files or encrypted Vault storage.
- Add automatic recreation, protection overview and variable-level rollback.
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
chmod +x "$OUT/install-local.sh"
(cd "$OUT" && sha256sum "$(basename "$PLG")" "$(basename "$TAR")" > SHA256SUMS)
