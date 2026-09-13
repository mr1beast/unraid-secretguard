# Releasing

1. Update the version in `build.sh`.
2. Update `CHANGELOG.md`.
3. Run:
   ```bash
   ./build.sh
   ```
4. Verify PHP syntax:
   ```bash
   php -l src/usr/local/emhttp/plugins/unraid-secretguard/SecretGuard.page
   php -l src/usr/local/emhttp/plugins/unraid-secretguard/include/SecretGuard.php
   ```
5. Create a GitHub release and attach:
   - `dist/unraid-secretguard.plg`
   - `dist/SHA256SUMS`
