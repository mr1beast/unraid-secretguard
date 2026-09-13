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

On systems with encrypted cache/array storage, the recommended mode is **Plain env files**
stored on encrypted storage, for example:

```text
/mnt/cache/appdata/secrets/
```

On systems without encrypted storage, **Encrypted Vault** encrypts SecretGuard-managed
data at rest and only restores plaintext runtime env files beneath `/run`.

Important: standard Docker environment variables may still be persisted in Docker's
own container metadata. For strongest at-rest protection, use encrypted Docker storage
or application-supported file secrets where possible.

## Installation

Download `unraid-secretguard.plg` from a release and install it on Unraid:

```bash
plugin install /path/to/unraid-secretguard.plg
```

After installation open:

```text
Settings -> User Utilities -> Unraid SecretGuard
```

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
