# Standalone validation — 2026-10-13

Source checkout HEAD: `5ff6ddb852b572a05d4b1b5e6afdf2ecc1350a11`.
SOURCE-MANIFEST.json records working-tree input hashes, including unpublished
changes; it does not assert that the input bytes equal that commit. The vendored
contracts/vectors are pinned separately in testdata/manifest.json.

Runtime: **Node.js 25.9.0; npm 11.12.1; TypeScript 5.9.3**.

Contract hashes (4 files): pass. Offline npm ci: pass. npm test: **116 passed, 0 failed, 0 skipped**. Package dry-run: **30 files**, all exported JS/declarations present, tests/fixtures excluded.

Corrected package-lock root version 0.1.0 to package version 0.2.0 without changing dependency pins/integrity. Replaced the quoted-glob test launcher with explicit filenames for the declared Node 20 minimum. Additional Node CI versions are configured, not locally tested.

All restores used existing local caches with network package/module downloads
disabled. No Docker, database or public deployment was used; tests use synthetic
data and loopback mock servers. Commands: python3 scripts/check-contracts.py;
the standalone README and CI contain the build/test commands. npm used --offline;
Dart used pub get --offline; .NET used only local feeds and NuGetAudit=false.

Generated build outputs/dependencies and temporary consumer directories were
removed after verification. Dependency lockfiles and synthetic vectors remain.
Final documentation/repository metadata edits do not change runtime behavior.
The staging validation preceded source publication. The reviewed source is now
public at [`proudbase/proudauth-sdk-node`](https://github.com/proudbase/proudauth-sdk-node).
The [initial independent CI run](https://github.com/proudbase/proudauth-sdk-node/actions/runs/38454415415)
passed at commit `da57d7e75da68e06c30669383c76d46c70c8d8f0` on Node.js 20.10.0, 22 and 24.
npm audit and package-content checks passed.
GitHub private vulnerability reporting is enabled. No package-registry release
or SDK release tag has been published.

Excluded: original .git history, actual .env/credentials, deployment state,
private screenshots/database backups, SDK caches/build output, image archives,
benchmark seeds and customer data. The original checkout was not modified.

## npm release — 2026-10-16

Published [`@proudauth/sdk@0.2.0`](https://www.npmjs.com/package/@proudauth/sdk/v/0.2.0)
with public access and the `latest` tag.

Validation used Node.js 25.9.0, npm 11.12.1 and TypeScript 7.0.2.
Locked dependency installation reported zero vulnerabilities. All 4 vendored
contract/vector files passed their integrity checks. All 116 SDK tests passed;
the publish dry run and package-content check passed with 30 files.

An unauthenticated registry request confirmed `latest` resolves to 0.2.0. The
published tarball was downloaded without authentication and its SHA-512 integrity
matched the locally verified tarball. A new consumer with empty npm credential
configuration and a fresh cache installed `npm install @proudauth/sdk` from the
public registry. All five public entry points imported successfully, the SDK and
package versions agreed, no runtime dependencies were installed, and the
TypeScript declarations resolved in the consumer. Chrome also showed version
0.2.0 as Public and published under Apache-2.0.

Published tarball SHA-1: `ab46c431d97e43976c94f4016f6001ab3b7cc1c0`.
Published tarball integrity:
`sha512-gpfGBHJLaEkTtHnJ5AYb/z6gj5Vy10bwGddhncAvPbFcY9ID1Dedo2TUvmu2h91DSNbAr1IeY8s8DMBOT6cCxA==`.

The release preparation changes package metadata and documentation, without
changing SDK runtime behavior. The npm publication preceded the GitHub update;
the release documentation and public publishing settings are included in the
subsequent repository update.
