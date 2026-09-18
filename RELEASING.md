# Releasing

1. Update the version in `build.sh` when runtime behavior changes.
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
5. Validate the generated `dist/unraid-secretguard.plg` as XML.
6. Test the release on a non-critical Unraid host before publishing.
7. Create a GitHub release using tag `vYYYY.MM.DD[.revision]` and attach:
   - `dist/unraid-secretguard.plg`
   - `dist/SHA256SUMS`
8. Keep the repository/release public before enabling an anonymous GitHub `pluginURL` for Unraid update checks.


## Update channel

`main/unraid-secretguard.plg` is the live Unraid update manifest:

```text
https://raw.githubusercontent.com/mr1beast/unraid-secretguard/main/unraid-secretguard.plg
```

Only push a tested release manifest to `main`. After building a release:

1. test the `.plg` locally;
2. copy the tested `dist/unraid-secretguard.plg` to repository root;
3. commit/push to `main`;
4. create the matching GitHub Release and attach `unraid-secretguard.plg` and `SHA256SUMS`.
