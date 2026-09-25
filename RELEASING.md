# Releasing

1. Update `VERSION` in `build.sh` for every release.
2. Update `CHANGELOG.md` and `README.md`.
3. Run `./build.sh`.
4. Verify syntax:
   ```bash
   php -l src/usr/local/emhttp/plugins/unraid-secretguard/SecretGuard.page
   php -l src/usr/local/emhttp/plugins/unraid-secretguard/include/SecretGuard.php
   php -l src/usr/local/emhttp/plugins/unraid-secretguard/scripts/watcher.php
   bash -n src/usr/local/emhttp/plugins/unraid-secretguard/scripts/watcher-loop.sh
   bash -n src/usr/local/emhttp/plugins/unraid-secretguard/scripts/restart-watcher.sh
   ```
5. Validate `dist/unraid-secretguard.plg` as XML and inspect the `.txz` contents. The archive should contain only `usr/local/emhttp/plugins/unraid-secretguard/...` plus `install/slack-desc`; it must not contain an inline/base64 payload or stock parent-directory entries.
6. Test the `.txz` on a non-critical Unraid host with `dist/install-local.sh`, then test install/update/remove through the final `.plg` after the release asset exists. For adoption changes, verify that preview and saved metadata contain names and paths only, and that the env file, Docker template, `ExtraParams`, and container state remain unchanged.
7. Create GitHub tag/release `vYYYY.MM.DD[.revision]` and attach:
   - `dist/unraid-secretguard-YYYY.MM.DD[.revision]-noarch-1.txz`
   - `dist/unraid-secretguard.plg`
   - `dist/SHA256SUMS`
8. The generated `.plg` points to the `.txz` asset in that GitHub Release. Upload the `.txz` before testing the remote `.plg`.
9. Copy the tested `dist/unraid-secretguard.plg` to the repository root, commit/push it to `main`, and keep the repository/release public for anonymous Unraid update checks.
10. In the Community Applications listing description, explicitly state: **When Encrypted Vault mode is used, SecretGuard's watcher stops Vault-protected containers after reboot until the Vault is unlocked.**

## Update channel

`main/unraid-secretguard.plg` remains the live Unraid update manifest:

```text
https://raw.githubusercontent.com/mr1beast/unraid-secretguard/main/unraid-secretguard.plg
```

The manifest itself contains readable lifecycle shell code and a SHA256-pinned URL to the public `.txz` release asset.
