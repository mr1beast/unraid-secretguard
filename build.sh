#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/src"
OUT="$ROOT/dist"
NAME="unraid-secretguard"
VERSION="2026.09.25"
ARCH="noarch"
BUILD="1"
PACKAGE="${NAME}-${VERSION}-${ARCH}-${BUILD}.txz"
PACKAGE_PATH="$OUT/$PACKAGE"
PLG="$OUT/${NAME}.plg"
PKGROOT="$OUT/.pkgroot"
RELEASE_URL="https://github.com/mr1beast/unraid-secretguard/releases/download/v${VERSION}/${PACKAGE}"

rm -rf "$PKGROOT"
mkdir -p "$OUT" "$PKGROOT"
rm -f "$PACKAGE_PATH" "$PLG" "$OUT/SHA256SUMS" "$OUT/install-local.sh"

# Build a transparent Slackware package containing only SecretGuard's own files.
# No install/doinst.sh is used; lifecycle actions stay visible in the .plg.
cp -a "$SRC/usr" "$PKGROOT/"
chmod 755 "$PKGROOT/usr/local/emhttp/plugins/unraid-secretguard/scripts/"*.sh

mkdir -p "$PKGROOT/install"
cat > "$PKGROOT/install/slack-desc" <<'DESC'
unraid-secretguard: unraid-secretguard (SecretGuard for Unraid)
unraid-secretguard:
unraid-secretguard: Scans installed Docker templates for likely credentials and can move
unraid-secretguard: selected values into managed env files or an encrypted Vault.
unraid-secretguard: Secret values are not displayed in the WebGUI audit.
unraid-secretguard:
unraid-secretguard: Project: https://github.com/mr1beast/unraid-secretguard
unraid-secretguard:
unraid-secretguard:
unraid-secretguard:
unraid-secretguard:
DESC

# Archive files only (not parent directory entries), avoiding metadata changes to
# stock directories such as /usr, /usr/local and /usr/local/emhttp.
mapfile -d '' PACKAGE_FILES < <(
  cd "$PKGROOT"
  find usr/local/emhttp/plugins/unraid-secretguard install -type f -print0 | sort -z
)
(
  cd "$PKGROOT"
  tar --no-recursion --mtime=@0 --owner=0 --group=0 --numeric-owner -cJf "$PACKAGE_PATH" "${PACKAGE_FILES[@]}"
)

PACKAGE_SHA256="$(sha256sum "$PACKAGE_PATH" | awk '{print $1}')"

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
### 2026.09.25
- Replace the opaque inline encoded tarball with a public, checksummed Slackware .txz release asset for Community Applications reviewability.
- Keep install/update lifecycle commands readable in the .plg and install package files with upgradepkg --install-new.
- Package only SecretGuard-owned files, without archive entries for stock parent directories.
- Document that the always-on watcher stops Vault-protected containers after reboot until the Vault is unlocked.

### 2026.09.18.6
- Add generic adoption of eligible legacy plain env files without rewriting secrets, templates or Docker settings.
- Store only container, env path, variable names and adoption state under the SecretGuard plugin configuration.
- Keep rollback unavailable for adopted env files that do not contain original XML metadata.

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
- UI-only change; no migration, Vault, storage, rollback or container recreation logic changed.

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

<FILE Name="/boot/config/plugins/unraid-secretguard/$PACKAGE" Run="upgradepkg --install-new">
<URL>$RELEASE_URL</URL>
<SHA256>$PACKAGE_SHA256</SHA256>
</FILE>

<FILE Run="/bin/bash" Method="install"><INLINE><![CDATA[
set -e
mkdir -p /boot/config/plugins/unraid-secretguard
chmod 700 /boot/config/plugins/unraid-secretguard
chmod 755 /usr/local/emhttp/plugins/unraid-secretguard/scripts/*.sh 2>/dev/null || true
/usr/local/emhttp/plugins/unraid-secretguard/scripts/restart-watcher.sh >/dev/null 2>&1 || true
if [ -f /boot/config/plugins/unraid-secretguard/vault.json ]; then
  /usr/local/emhttp/webGui/scripts/notify -e "Unraid SecretGuard" -s "SecretGuard vault locked" -d "Encrypted Vault is locked after plugin install/reboot. Vault-protected containers are stopped by SecretGuard until you unlock the Vault in Settings > User Utilities > Unraid SecretGuard." -i warning >/dev/null 2>&1 || true
fi
echo "Unraid SecretGuard installed. Open Settings -> User Utilities -> Unraid SecretGuard."
]]></INLINE></FILE>

<FILE Run="/bin/bash" Method="remove"><INLINE><![CDATA[
if [ -f /run/unraid-secretguard/watcher.pid ]; then kill "\$(cat /run/unraid-secretguard/watcher.pid)" 2>/dev/null || true; fi
rm -rf /run/unraid-secretguard
for pkg in /var/log/packages/unraid-secretguard-*; do
  [ -f "\$pkg" ] || continue
  removepkg "\$(basename "\$pkg")" >/dev/null 2>&1 || true
done
rm -rf /usr/local/emhttp/plugins/unraid-secretguard
# Preserve persistent settings/vault metadata; encrypted/plain secret files live in the user-selected secret directory.
echo "Unraid SecretGuard removed. Persistent settings and vault metadata were preserved in /boot/config/plugins/unraid-secretguard."
]]></INLINE></FILE>
</PLUGIN>
PLG

cat > "$OUT/install-local.sh" <<INSTALL
#!/bin/bash
set -euo pipefail
PACKAGE="\${1:-$PACKAGE_PATH}"
[ -f "\$PACKAGE" ] || { echo "Package not found: \$PACKAGE" >&2; exit 1; }
upgradepkg --install-new "\$PACKAGE"
mkdir -p /boot/config/plugins/unraid-secretguard
chmod 700 /boot/config/plugins/unraid-secretguard
chmod 755 /usr/local/emhttp/plugins/unraid-secretguard/scripts/*.sh 2>/dev/null || true
/usr/local/emhttp/plugins/unraid-secretguard/scripts/restart-watcher.sh >/dev/null 2>&1 || true
echo "Local SecretGuard package installed."
INSTALL
chmod +x "$OUT/install-local.sh"

(
  cd "$OUT"
  sha256sum "$PACKAGE" "$(basename "$PLG")" > SHA256SUMS
)

rm -rf "$PKGROOT"
printf 'Built %s\n' "$PACKAGE_PATH"
printf 'SHA256 %s\n' "$PACKAGE_SHA256"
printf 'Manifest %s\n' "$PLG"
