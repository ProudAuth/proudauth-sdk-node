# Changelog

All changes, including breaking changes, are documented here. Package releases
will use semantic versioning; the initial 0.x API may change between minor versions.

## Unreleased

- Add live npm and repository version badges, package links, and installation
  instructions that follow the latest published release.

### Known limitations

- A running verifier keeps a retired or compromised signing key trusted until
  the process restarts: the JWKS cache has no expiry, no `refresh()` or
  `rejectKey()`, and `BoundedState` ignores `signing_key.rotated`. Restart
  resource servers after an emergency rotation; 0.3.0 adds key expiry,
  refresh and rejection. This applies to the published 0.2.0 as well.

## 0.2.0 — 2026-10-16

### Added

- Independent repository layout, root-level package metadata and CI.
- Vendored shared access-token and support-operation fixtures, with source HEAD
  and SHA-256 provenance, and an offline integrity check.
- Standalone contribution and private vulnerability reporting policies.
- Public npm publishing configuration and prepublish test/package validation.

### Changed

- Monorepo-relative test inputs and documentation links now work from this checkout.
- Installation instructions cover npm and building a local tarball.

First npm release of the standalone SDK, published as `@proudauth/sdk@0.2.0`
with the `latest` tag. The existing SDK behavior and 0.2.0 version identifiers
are retained. The repository tag `v0.2.0` (2026-10-18) points at `7f65324`, the
commit of the publication; the published tarball differs from that commit's
pack in `README.md` only ([VALIDATION.md](VALIDATION.md)).
