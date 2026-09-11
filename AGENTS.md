# Agent Guide

This file applies to the entire repository. Keep it current when a change alters a durable project
rule, command, contract, or architectural boundary.

## Read First

- Payload work must follow `.agents/skills/payload/SKILL.md`; use its reference directory when the
  quick reference is insufficient.
- Product setup and operator basics are in `README.md`.
- OTserver Otter usage and its canonical wire contract live in the separate `otserver-otter`
  repository, pinned here as the `otserver-otter/` submodule.

## Project Summary

OTserver is an OT asset-management application built with Payload CMS 3, Next.js 16, React 19, and
MongoDB. It manages assets, hierarchical sites, scoped user roles, imports, observations, topology,
custom asset fields, and an immutable audit trail. Its product domain is `otserver.org`.

OTserver integrates with OTserver Otter, a separate AGPL Rust discovery tool that exports
`otserver-scan` schema-version-2 JSON.

Main locations:

- `src/collections/`: Payload collections and hooks.
- `src/access/authorization.ts`: site-scoped authorization shared by collections and hooks.
- `src/importers/`: PRONETA XML, Nmap XML, OTserver Otter JSON, source metadata, and quality merging.
- `src/search/`: Lucene syntax translation and graphical-filter integration.
- `src/vulnerabilities/`: CISA/NVD/CSAF/ICS-advisory feed synchronization, CPE parsing, and passive
  asset matching.
- `src/components/`: custom Payload admin views and fields.
- `otserver-otter/contracts/otserver-scan-v2.schema.json`: pinned canonical Otter wire contract.
- `tests/int/`: application and importer integration tests.

## Non-Negotiable Domain Rules

### Asset identity

- A normalized MAC address is the only asset identity key. Never merge or deduplicate by IP, name,
  serial number, or site.
- Store MAC addresses as uppercase colon-separated values via `normalizeMAC` in
  `src/collections/Assets.ts`.
- Assets and imported assets require a MAC. Skip uncorrelatable observations instead of inventing an
  asset identity.
- Every asset and every import belongs to a mandatory site.
- Asset classes are first-class, admin-managed documents. Assets reference an asset class; do not
  replace the relationship with hard-coded class options.
- Automatic class assignment rules combine case-insensitive manufacturer and model regular
  expressions. Shipped defaults live in `src/data/default-asset-class-rules.json`; seed them once
  and preserve administrator changes. Human class assignments must outrank automatic matches.

### Data quality and provenance

Field merging is centralized in `src/importers/assetQuality.ts`. Do not reproduce this logic in an
importer.

Quality order is `human > high > medium > low`:

- Empty fields may always be filled.
- Equal quality may replace a changed value.
- Higher quality may replace lower quality and upgrades field provenance even when the value agrees.
- Lower quality must not overwrite higher quality.
- Human edits are always recorded as human provenance and must survive imports.
- Protocol arrays combine evidence instead of discarding lower-quality observations.

PRONETA is high quality, Nmap is medium quality, and scanner observations carry their own quality.
The scanner-source fallback is low quality. User-entered import overrides are human quality.

### Sites and authorization

- Site types and hierarchy depth are user-defined. Do not hard-code continent/country/plant levels.
- A site cannot be its own parent or a descendant of itself. Preserve both the UI filter and the
  server-side cycle guard in `src/collections/Sites.ts`.
- Role permissions apply to a selected site and every descendant. A role can contain multiple site
  permissions with read-only or read/write access.
- The protected `Admin` role is created automatically, cannot be renamed or deleted, and always has
  unrestricted access.
- Non-admin users must not see or access access-control/configuration collections outside their
  permissions. UI hiding is not security; collection access functions are authoritative.
- Reuse `getAuthorization` and the shared access helpers. Do not add one-off permission checks.
- Avoid `overrideAccess: true` in user-facing operations. For necessary internal writes, pass the
  original `req`, keep the scope narrow, and add an authorization test.

### Auditability

- Every collection registered in `src/payload.config.ts` is wrapped by `withAudit`.
- Audit logs are immutable and redact fields whose names resemble secrets, tokens, passwords, hashes,
  or sessions.
- Asset-related observations and topology changes must retain their asset relationship so they appear
  in the asset detail history.
- New collection mutations are covered by `withAudit`; custom actions outside collection hooks must
  call `writeAudit` explicitly with the original request and target context.
- Never bypass auditing merely to simplify bulk operations or imports.

### Vulnerability matching

- Assets store only the derived vulnerability count. CVE details remain in the local vulnerability
  catalog and are looked up when the asset vulnerability view opens.
- Match only recorded metadata. Never add an active vulnerability probe, exploit, or scanner check.
- CSAF sources are the CERT@VDE aggregator and CISA OT/IT ROLIE feeds. Refresh CSAF as one complete
  snapshot, preserve the previous snapshot on any provider failure, and never overwrite NVD-owned
  records with CSAF data.
- Count a CVE only when fuzzy vendor/product matching succeeds and a reported asset version satisfies
  an affected NVD CPE or CSAF product-tree exact version or range. Missing version evidence does not
  count.
- CISA KEV enriches NVD records with known-exploitation data but cannot create a count by itself
  because the CISA feed has no affected-version constraints.
- The ICS Advisory Project master CSV is an enrichment source only. It writes just the `ics*` fields,
  so its per-advisory `Cumulative_CVSS` and free-text `Products_Affected` never displace NVD or CSAF
  evidence and never yield matchable version constraints. Do not parse that column into `affected`.
- NVD JSON 2.0 affected CPE entries use `vulnerable: true`. Feed parsers must fail closed on malformed
  top-level data and retain the previous usable catalog when downloads fail.
- Catalog bulk writes use the MongoDB collection for scale and are represented by one explicit
  `writeAudit` synchronization event. Asset count changes still use Payload and remain individually
  audited.

## Importer Development

Importers parse untrusted files. Keep size limits, validate structure and data types, treat optional
vendor fields as optional, ignore unknown fields safely, and return useful warnings.

To add an importer:

1. Add its durable UI metadata, quality, acquisition steps, and command if applicable to
   `src/importers/sources.ts`. The import modal reads this metadata.
2. Implement a parser returning `ImportResult` from `src/importers/types.ts`.
3. Register it in the parser map in `src/collections/AssetImports.ts`.
4. Merge through `mergeAssetData`; do not update assets directly from parser-specific logic.
5. Add an anonymized fixture and integration test covering parsing, MAC-only merging, quality, and
   malformed input.

PRONETA has no public stable schema: accept known paths and capitalization variants, tolerate missing
and unknown fields, and preserve useful raw data. Nmap input must be XML produced with `-oX`.
OTserver Otter JSON must validate against schema version 2. A contract change requires coordinated
updates to the canonical schema and Rust implementation in `otserver-otter`, an updated submodule
pointer here, plus this repository's TypeScript importer, fixtures, and tests.

Human-supplied bulk import fields are declared once in `userSuppliedAssetFields` in
`src/collections/Assets.ts`; the asset and import UIs derive from it. Custom field definitions are
admin-managed in `asset-fields`, stored by definition ID, validated server-side, and cannot change
type after creation.

Imports currently execute synchronously and can be partially applied. Introduce a queue and database
transaction only when real file sizes or atomicity requirements justify it.

## Search

Asset search accepts the supported Lucene subset in `src/search/assetLucene.ts`. The graphical filter
builder is a query-language assistant, not an independent filter path. Keep both representations in
sync. Unsupported regex, fuzzy, boost, unary NOT, invalid range, unknown-field, oversized, and deeply
nested queries must continue to fail with a clear HTTP 400 error.

## Generated Files

- Do not hand-edit `src/payload-types.ts`; run `pnpm generate:types` after collection schema changes.
- Regenerate the Payload admin import map with `pnpm generate:importmap` when component registrations
  change.
- Commit `pnpm-lock.yaml` when `package.json` changes.
- Never commit `.env`, `otter.json`, legacy `otscanner.json`, discovery output, uploads, build output,
  or caches. The root `.gitignore` contains the expected patterns.

## Local Setup and Checks

Requirements: Node.js 20.9+, pnpm 9-11, and MongoDB. Copy `.env.example` to `.env` and use
a long random `OTSERVER_SECRET`. `docker compose up` can provide OTserver and MongoDB.

Integration tests need a MongoDB matching `DATABASE_URL` in `.env`. Start a throwaway instance
with Podman:

```bash
podman run -d --rm --name otserver-test-mongo -p 27017:27017 \
  -e MONGO_INITDB_ROOT_USERNAME=admin -e MONGO_INITDB_ROOT_PASSWORD=admin \
  docker.io/library/mongo:8
```

Tear it down with `podman stop otserver-test-mongo`; `--rm` removes it. The credentials match the
`DATABASE_URL` in `.env`.

`vitest.config.mts` sets a 60s per-test timeout because these tests boot Payload against a real
MongoDB. A cold container makes the first run slower than later ones.

Run the smallest relevant checks while developing, then the full set before committing:

```bash
pnpm test
pnpm test:coverage
pnpm lint
pnpm build
git diff --check
```

`pnpm test:coverage` enforces at least 90% statements, branches, functions, and lines for the
application.

Vitest runs integration files serially because they share database state. New behavior affecting
authorization, imports, quality precedence, audit logs, parsing, or bulk operations needs a focused
integration test. Otter implementation and protocol tests belong in the `otserver-otter`
repository.

The development server permits HMR only from `192.168.50.*` in `next.config.ts`. Keep production
origin policy separate from this home-network development exception.

## Change Discipline

- Preserve existing user work in a dirty tree and avoid unrelated cleanup.
- Prefer existing helpers and standard-library behavior over new abstractions or dependencies.
- Fix invariants at their shared boundary rather than patching individual callers.
- Keep admin UI components free of server functions and other non-serializable Payload/Next objects.
- Do not weaken validation, access control, auditing, or Otter safety to make a test pass.
- Update this file only for durable guidance, not temporary status or implementation notes.
