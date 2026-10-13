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
