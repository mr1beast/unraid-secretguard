# Unraid SecretGuard

Unraid SecretGuard helps keep Docker credentials out of Unraid's unencrypted
Docker template XML files on the flash device.

> **Status:** Public beta. Test migrations on a non-critical container first.

## What it does

- Scans only Docker containers currently installed on the Unraid host.
- Detects likely secrets such as passwords, API keys, tokens and client secrets.
- Never displays secret values in the WebGUI.
- Moves selected values from Docker XML templates into managed `.env` files.
- Supports an encrypted Vault mode for hosts without encrypted secret storage.
- Automatically recreates the affected Docker container after migration.
- Shows which containers are protected and which variables are managed.
- Supports variable-level rollback without restoring an old XML snapshot.
- Keeps unrelated ports, paths, labels and later template changes untouched.
- Watches new or changed installed Docker templates and can send Unraid notifications.

## Security model

SecretGuard discovers mounted persistent Unraid storage instead of assuming that every server has a cache pool. The storage selector always shows `cache` as the conventional Unraid choice, but an absent/unmounted cache is clearly marked **NOT MOUNTED / NOT PERSISTENT** and is never recommended automatically.

On systems with confirmed encrypted persistent storage, the recommended mode is **Plain env files**. SecretGuard prefers a mounted cache pool when available; otherwise it can use another mounted disk or pool selected by the user, for example:

```text
/mnt/cache/appdata/secrets/
/mnt/disk1/appdata/secrets/
```

Plain mode is blocked when the configured path resolves to `rootfs`, `tmpfs`, RAM, or an unmounted pool path. If storage encryption cannot be confirmed, SecretGuard recommends **Encrypted Vault** instead.

Important: standard Docker environment variables may still be persisted in Docker's
own container metadata. For strongest at-rest protection, use encrypted Docker storage
or application-supported file secrets where possible.


## Vault lifecycle and reboot procedure

Vault mode deliberately does **not** store the master password or derived master key.

Persistent data contains only:

```text
/boot/config/plugins/unraid-secretguard/vault.json
    salt
    KDF parameters
    authenticated encrypted verifier

<secret directory>/*.sgv
    encrypted SecretGuard data
```

While the Vault is unlocked, volatile RAM contains:

```text
/run/unraid-secretguard/master.key
/run/unraid-secretguard/env/*.env
```

`/run` disappears at reboot.

### After reboot

1. SecretGuard starts with the Vault **LOCKED**.
2. The background watcher stops Vault-protected containers that autostart while locked.
3. Open **Settings -> User Utilities -> Unraid SecretGuard**.
4. Enter the same Vault master password used when the Vault was created (or the most recently changed password).
5. SecretGuard derives the same key from the password, stored salt and KDF parameters.
6. The authenticated verifier confirms whether the derived key is correct.
7. SecretGuard decrypts runtime env files into `/run`.
8. Containers remembered by the lock/boot guard are recreated and started.

A wrong password does not alter or delete encrypted data.

### Failed unlock protection

Failed attempts are rate-limited for the current boot:

- Attempts 1-3: 2 second cooldown
- Attempts 4-5: 10 second cooldown
- Attempts 6-10: 60 second cooldown
- Attempt 11 and later: 15 minute cooldown

Repeated failures generate syslog events and Unraid notifications. The retry state is intentionally volatile and resets at reboot; its purpose is to slow WebGUI guessing, not to replace Argon2id protection against offline attacks.

SecretGuard never automatically destroys Vault data after failed password attempts.

### Changing the master password

The current master password must be verified first. SecretGuard then:

1. decrypts the existing Vault data in memory;
2. generates fresh salt/KDF metadata and a new derived key;
3. re-encrypts every `.sgv` to temporary files;
4. decrypts and authenticates each temporary file with the new key;
5. only after all files verify, activates the new files and Vault metadata.

If staging or verification fails, SecretGuard attempts to retain/restore the old encrypted Vault.

If the master password is forgotten, SecretGuard has no recovery password or backdoor. Back up important credentials separately in a secure password manager.


## Versioning

SecretGuard uses Unraid-style date versions (`YYYY.MM.DD`). If multiple releases are needed on the same day, a numeric revision suffix is used, for example `2026.09.13.5`.

## Resetting the Vault

The WebGUI provides **Delete / Reset Vault**. The action is fail-safe: it is blocked while any installed container still uses Vault mode or any encrypted `.sgv` file remains in the configured secret directory. After a successful reset, a new Vault can be initialized with a completely new master password.

## Installation

Download `unraid-secretguard.plg` from a release and install it on Unraid:

```bash
plugin install /path/to/unraid-secretguard.plg
```

After installation open:

```text
Settings -> User Utilities -> Unraid SecretGuard
```


## Updates

The current public-beta manifest does not include a `pluginURL`. Install releases manually from GitHub while the repository/update endpoint is being finalized. A stable GitHub Releases update URL can be enabled later without changing SecretGuard's storage or migration behavior.

## Local build

Requirements:

- bash
- tar
- base64
- sha256sum

Build with:

```bash
./build.sh
```

Output is written to:

```text
dist/
```

## Repository layout

```text
.
├── README.md
├── CHANGELOG.md
├── LICENSE
├── .gitignore
├── build.sh
└── src/
    └── usr/local/emhttp/plugins/unraid-secretguard/
```

## Rollback behavior

SecretGuard does **not** restore a complete historical Docker XML file.

Each migrated variable stores the metadata required to rebuild only that Docker
variable. Rollback restores those variables, removes the SecretGuard env source,
deletes the managed secret file, and recreates the container.

This avoids rolling back unrelated changes made to ports, paths, labels or other
container configuration after the secret migration.

## License

MIT License.

## Publisher

**mr1beast**
