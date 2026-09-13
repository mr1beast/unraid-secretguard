# Changelog

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
