# Community Applications description note

SecretGuard scans installed Unraid Docker templates for likely credentials without displaying secret values. Selected credentials can be moved out of flash-stored Docker XML templates into permission-restricted env files on persistent storage or into SecretGuard's encrypted Vault.

When Encrypted Vault mode is used, SecretGuard does not store the master password. After every reboot the Vault starts locked, and SecretGuard's always-on watcher stops Vault-protected containers until the Vault is unlocked in **Settings -> User Utilities -> Unraid SecretGuard**. This prevents those containers from starting without their protected runtime env files.

SecretGuard supports protection status, Docker template auditing, managed env-file migration, encrypted Vault storage, variable-level rollback where metadata is available, adoption of eligible existing env files, and Unraid notifications.
