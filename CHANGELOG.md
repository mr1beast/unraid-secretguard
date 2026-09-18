# Changelog

## 2026.09.18.4

- Overview is now the default landing tab.
- Protection overview and Docker template audit are grouped on Overview.
- Secret storage, Dedicated SecretGuard share and Encrypted Vault are grouped together on one Settings tab.
- UI-only release; backend behavior is unchanged.

## 2026.09.18.1

- Added separate tabs for **Secret storage**, **Dedicated SecretGuard share**, and **Encrypted Vault**.
- Protection overview and Docker template audit remain visible below the tabs.
- The selected tab is remembered locally in the browser.
- UI-only release; no migration, Vault, storage, rollback, or recreation logic changed.

## 2026.09.18

- Added expandable/collapsible Docker container rows in the template audit.
- Containers are collapsed by default and show counts for variables, HIGH findings and MEDIUM findings.
- Expanding a container shows the existing variable table and migration controls.
- No backend or secret-handling behavior changed.

## 2026.09.13.6

- Added optional **Create SecretGuard share** workflow.
- Creates a dedicated `secretguard` share on a selected mounted persistent disk/pool.
- Uses `/mnt/<storage>/secretguard` directly for credentials.
- Disables SMB and NFS export in the generated share config.
- Pins pool shares with `shareUseCache="only"` + `shareCachePool`, or array disk shares with `shareInclude`.
- Refuses to overwrite an existing unrelated `secretguard` share/directory.

## 2026.09.13.5

- Added persistent-storage discovery for Unraid disks and pools instead of assuming a cache pool exists.
- Cache is always visible as the conventional Unraid option, but an absent/unmounted cache is marked `NOT MOUNTED / NOT PERSISTENT` and is never recommended automatically.
- Prefer a mounted cache pool when available; otherwise recommend another mounted encrypted disk/pool.
- Block Plain env migration when the configured secret path resolves to rootfs/tmpfs/RAM or an unmounted pool path.
- Storage status distinguishes confirmed encrypted storage, unknown/unconfirmed encryption, and non-persistent storage.
- Added safe Delete / Reset Vault, blocked while Vault-protected containers or encrypted `.sgv` files remain.
- Improved Plugins-page title and description.
- Continued Unraid-style date versioning with numeric same-day revisions.

## 0.5.0

- Hardened Vault LOCKED/UNLOCKED lifecycle and reboot handling.
- Stop/resume Vault-protected containers around lock/unlock.
- Added staged and verified master-password change with fresh salt/KDF parameters.
- Added authenticated verifier blob with legacy verifier upgrade support.
- Added unlock cooldown/rate limiting, syslog events and Unraid notifications.
- Wrong passwords never automatically delete Vault data.

## 0.4.0

First GitHub-ready public beta release, based on the tested v0.3.5 codebase.

- Scans installed Docker containers only.
- Detects likely credentials without showing values.
- Supports managed `.env` secret storage and encrypted Vault mode.
- Automatically recreates containers after migration or rollback.
- Provides a protection overview and variable-level rollback without restoring whole XML snapshots.
- Includes matching User Utilities and Plugins icons.

## Pre-GitHub beta history

Earlier 0.2.x and 0.3.x builds were local development/beta iterations.
