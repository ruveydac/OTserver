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

OTserver is an OT asset-management application built with Payload CMS 3.90.1, Next.js 16.3.4,
React 19.2.6, Node 22, pnpm 10, and MongoDB 8. It manages assets, hierarchical sites, scoped user roles, imports, observations, topology,
custom asset fields, and an immutable audit trail. Its product domain is `otserver.org`.

OTserver integrates with OTserver Otter, a separate AGPL Rust discovery tool that exports
`otserver-scan` schema-version-2 JSON.

Main locations:

- `src/collections/`: Payload collections and hooks.
- `src/access/authorization.ts`: site-scoped authorization shared by collections and hooks.
- `src/importers/`: PRONETA XML, Nmap XML, OTserver Otter JSON, source metadata, and quality merging.
- `src/identity/`: physical hardware keys, scoped endpoint reconciliation, installations, lifecycle
  actions, and explicit migration. Operator details are in `docs/device-identity.md`; deferred
  scanner work is in `docs/otter-identity-roadmap.md`.
- `src/search/`: Lucene syntax translation and graphical-filter integration.
- `src/vulnerabilities/`: CISA/NVD/CSAF/ICS-advisory feed synchronization, CPE parsing, and passive
  asset matching.
- `src/components/`: custom Payload admin views and fields.
- `src/domain/`, `src/application/`, `src/integrations/`: pure rules, use cases, and Payload/MongoDB boundaries.
- `src/jobs/`, `src/worker.ts`: fenced import and maintenance queues using Payload jobs.
- `src/otter/`: site-scoped Otter enrollment, machine authentication, encrypted profiles, schedules, and controller API.
- `otter_management.md`: management protocol and scanner-side Otter implementation checklist.
- `otserver-otter/contracts/otserver-scan-v2.schema.json`: pinned canonical Otter wire contract.
- `tests/int/`: application and importer integration tests.

## Non-Negotiable Domain Rules

### Asset identity

- Assets represent physical hardware and may have no MAC. MAC addresses identify current endpoint
  bindings within one exact site, not globally unique physical devices. Site hierarchy affects
  authorization only; parent and child sites remain separate endpoint identity namespaces.
- Automatic physical correlation requires an exact accepted, source-qualified manufacturer/scoped
  serial key from `src/identity/keys.ts`. Generic serial strings, IP/name, topology, and adjacent MACs
  cannot authorize automatic physical merges. Conflicts become identity cases.
- UUIDv5 hardware keys are portable aliases; preserve Payload IDs and stable asset UUIDs. Keep module
  identity independent from its current chassis/slot. Preserve unknown slot positions as unknown.
- Store MAC addresses as uppercase colon-separated values via `normalizeMAC` in
  `src/collections/Assets.ts`.
- Preserve unresolved observations instead of inventing physical identity or assigning gateway MACs
  to routed targets. Qualified existing v2 evidence can identify MAC-free components.
- Endpoint/service assignments and module installations retain historical records. Use lifecycle
  states for retirement/replacement/merging; Payload trash is a separate deletion policy.
- Trash retains hardware identity reservations. Permanent asset deletion releases its identifiers,
  network endpoints, and service bindings through audited, transactional deletes. Imports repair
  legacy orphaned bindings only after a global owner-existence check including Trash; inaccessible
  or trashed assets are never orphans. Preserve observations, topology, and audit history.
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
- Identity resolution precedes descriptive field merging. Preserve conflicting identity evidence
  instead of overwriting a serial. Old uploads must not regress lastSeen or current endpoint state.

PRONETA is high quality, Nmap is medium quality, and scanner observations carry their own quality.
The scanner-source fallback is low quality. User-entered import overrides are human quality.

### Sites and authorization

- Site types and hierarchy depth are user-defined. Do not hard-code continent/country/plant levels.
- Site types are administrator-managed `site-types` documents used by every site in one hierarchy.
  Seed geographic and ISA-95 defaults by stable keys with canonical equipment-element mappings
  (Continent → Enterprise; Country, State / region, and City → Area; Site / plant and the
  To be changed fallback → Site; production types → their matching elements), preserve edits and
  retirement, and retire built-in types instead of deleting them. Every built-in type must carry a
  mapping. Retired types remain valid on existing
  assignments; new assignments require active types. Never accept free-text type values.
- The `20261018_120000_site_types` migration replaces every legacy free-text site type with the
  seeded **To be changed** relationship, without retaining a legacy text field. Original values
  remain only in immutable audit history. Back up and run `pnpm migrate` before serving an upgraded
  database; restoring a backup is required to reverse this migration.
- Use the same `sites` collection for geographic and production nodes, including areas, lines,
  and cells. Assets have one mandatory `site`; do not introduce a separate functional-location
  hierarchy or assignment. Types are descriptive, not different kinds of inventory scope.
  Role permissions include descendants; imports and scanners keep their exact-site scope.
  Catalogue reference locks protect type deletion/retirement races. Site deletion checks include
  assets in Trash.
- `site-types.blockImports` defaults to false; seed Continent, Country, and City with it enabled,
  preserving administrator changes on subsequent starts. It applies only to sites directly assigned
  that type, never to descendants with a different type. Enforce the current type policy through
  `src/application/importSites.ts` for upload creation/replacement, queued execution/retries,
  and Otter enrollment, run creation/claim/start. Blocking pauses Otter assignments and requests
  cancellation of active runs on polling/heartbeat. Keep inventory/history reads, cancellation,
  scanner revocation, and disabling schedules available. Internal status writes must still complete.
  Site/import selectors may retain a record's current blocked site for maintenance; that never
  authorizes a new import or scan. Do not copy the policy onto sites or run snapshots.
- `assets.purdueLevels` contains optional, manually assigned levels 0 through 5 using the documented
  Purdue cybersecurity convention. Empty means unclassified; level 0 is valid and multiple levels
  are allowed. These describe deployed functions, not ISA-95 equipment nesting, security zones,
  or IEC 62443 security levels. Never infer them from asset class, site type, IP, or topology.
  The site-scoped Purdue overview counts unique assets overall and per-level memberships separately.
  Keep its asset links and graphical filters on the shared Lucene/search manifest.
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
- Cross-site identity matches remain opaque until explicit reconciliation. Transfers require write
  access to both sites; import site selection never silently moves an existing physical asset.
- Identity relationships must belong to the same site. Graph/identifier changes lock the affected
  assets (including ancestry) to prevent snapshot-isolation races. Preserve history site scope.
- Otter Config is an additional role capability, not a substitute for site permissions. Scanner,
  profile, schedule, run, and managed import data stay bound to one exact site. Scanner credentials
  are machine principals restricted to `/api/otter/v1` and their own `/api/asset-imports` records;
  never give them generic Payload or descendant-site access.
- Otter enrollment tokens are single-use, short-lived digests; machine credentials are hashed,
  expiring, and revocable. SNMP/OPC UA credentials are encrypted with
  `OTSERVER_OTTER_ENCRYPTION_KEY` and must never be returned to ordinary profile reads or logged.
- Otter enrollment and polling inventory reports include the computer name and at most 32 adapters,
  each with technical/friendly names, description, MAC, and at most 16 IPv4/IPv6 addresses. Validate
  reports and keep them bound to the exact scanner; never include credentials in adapter inventory.
- Manage enrollment from the Otter Scanners collection popup. All scan options and human import
  overrides belong to Otter Configurations (`otter-profiles`); manual runs select a configuration
  explicitly and schedules reference one. Snapshot scan options, encrypted credentials, and import
  overrides together for every run. Never layer scanner-level network overrides onto configurations.
  Generic scanner writes may change only the name; controller-owned inventory and credentials remain
  protected. Internal controller updates use the `otterScannerUpdate` request context.
  Manual configuration runs require a Yes/No authorization confirmation. Schedules derive their
  scanner and exact site from the selected configuration on save, ignoring supplied scope fields.
  New configurations store an encrypted SNMP v2c `public` community by default; later credential
  replacement or clearing must survive configuration edits.
- Managed import display names include Otter, scanner name, site path/name, and a UTC timestamp.
  Scanner-supplied overrides are discarded in favor of the server-owned run snapshot.
- Otter Runs expose terminal failure reasons in `message`. Lease expiry records the missed-heartbeat
  reason, and older clients reporting failure without a message get an explicit missing-details
  fallback. Scanner-generated reasons must remain credential-safe and survive finish retries.
- Otter controller URLs require HTTPS except for HTTP on `localhost`, `127.0.0.1`, or `[::1]`,
  regardless of `NODE_ENV`. Browser management accepts loopback aliases only on the same scheme and
  port as an allowed origin; retain origin checks for external requests.
- Create due Otter schedule occurrences and claim runs transactionally during scanner polling.
  Preserve the schedule-occurrence partial unique index, one active assignment per scanner, lease
  checks, and latest-only offline catch-up. Scanner-side changes belong in `otserver-otter` and must
  coordinate with `otter_management.md`.

### Auditability

- Every collection registered in `src/payload.config.ts` is wrapped by `withAudit`.
- Audit logs are immutable and redact fields whose names resemble secrets, tokens, passwords, hashes,
  or sessions.
- Asset-related observations and topology changes must retain their asset relationship so they appear
  in the asset detail history.
- New audit entries snapshot their site; historical visibility must not migrate implicitly when the
  asset moves. Merged/split views may resolve aliases and endpoint evidence without rewriting logs.
- New collection mutations are covered by `withAudit`; custom actions outside collection hooks must
  call `writeAudit` explicitly with the original request and target context.
- Treat scanner operations as the explicit `otter` audit actor and redact credential/community fields
  when extending enrollment or controller configuration.
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
- The `sha256` in an NVD `.meta` file covers the **uncompressed** JSON, not the `.gz` download (its
  `size` field is the uncompressed length too). Hash while gunzipping. Hashing the compressed bytes
  fails every year, which silently empties the NVD state, marks the catalog unloaded, and makes each
  restart re-download all annual feeds.
- NVD online and offline processing must stream decompression, hashes, and record parsing. Validate
  the entire annual file before catalog writes; stage it on disk under `TMPDIR`, clean up in `finally`,
  and keep write batches and matching query pages bounded. Never restore whole-year `JSON.parse`.
- Catalog bulk writes use the MongoDB collection for scale and are represented by one explicit
  `writeAudit` synchronization event. Asset count changes still use Payload and remain individually
  audited.
- Feed management belongs to the administrator-only Vulnerability Feeds page. Keep automatic weekly
  maintenance updates and the on-demand button on the fenced maintenance queue. An on-demand request
  bypasses freshness, not NVD checksum reuse. `OTSERVER_VULNERABILITY_FEEDS=off` disables server-side
  online updates in both web and worker processes but must leave original-file offline imports usable.
- Offline selections use immutable `vulnerability-feed-uploads` under the shared `import-files` volume.
  Jobs snapshot upload IDs and reload the initiating administrator; verify stored digests and preflight
  all selected contents before catalog writes. Never fetch a missing offline file. NVD imports require
  matching `.meta` checksums of the uncompressed JSON and preserve unselected years. CSAF replaces only
  complete snapshots; distinguish repeated filenames by mirrored hostname/path or explicit source URL.
  Preserve publisher filenames in upload metadata; multipart sanitization changes dots and extensions,
  so source lookup must never depend on Payload's physical storage filename.
  Usable CSAF-only catalogs must enable derived counts. Seven-day staging cleanup retains active job
  files; catalog failures must not make previously loaded data unusable.
- The asset detail view shows the five most severe potential matches, known-exploited first and then
  highest CVSS, with a paginated view for all matches and their evidence. These are unvalidated
  metadata matches, not confirmation that a device is vulnerable.

### Vulnerability-feed operator reference

Administrators use **Vulnerabilities > Vulnerability Feeds > Update feeds now** for an on-demand
refresh. Work continues in the maintenance queue after the browser closes. For isolated installations,
set `OTSERVER_VULNERABILITY_FEEDS=off` in the application and any external maintenance worker;
**Upload downloaded feeds** remains available without network access.

Offline transfer workflow:

1. Open **Upload downloaded feeds**, choose a source, and save its download instructions.
2. Download the original publisher files on an internet-connected computer, retaining their filenames.
3. Transfer them to the isolated computer and use **Choose files** or **Choose folder**. Retain the
   selection ID to resume staged uploads.
4. Use **Check uploaded files** to review coverage, publisher dates, and missing-file links.
5. Select **Import uploaded … files** and review the results on the feed page.

Required files:

- CISA KEV: `known_exploited_vulnerabilities.json`.
- NVD: each selected `nvdcve-2.0-YYYY.json.gz` (or `.json`) with its matching `.meta` file.
- ICS Advisory Project: `CISA_ICS_ADV_Master.csv`.
- CSAF: the CERT@VDE aggregator, every referenced provider metadata/index/advisory file, and both
  CISA OT/IT indexes with their referenced advisories.

NVD years can be imported in batches; unselected years and other sources remain intact. Coverage
stays partial until all annual years from 2002 onward have been loaded. For CSAF, check the initial
aggregator and CISA indexes, transfer files from the resulting missing-file links, and repeat until
the snapshot is complete. Preserve `hostname/path/to/file.json` directories for repeated filenames,
or use **Upload this file** beside the specific missing URL.

Each upload is limited to 500 MiB, each selection to 8 GiB, and decompressed feeds to 2 GiB. Prefer
compressed NVD files for large years. Staged files expire after seven days, except those needed by
active jobs. External maintenance workers need the shared `import-files` volume. Successful imports
recalculate asset counts and audit the initiating administrator.

NVD catalog writes are bounded to 100 records per batch and also flush at roughly 4 MiB of serialized
data. Asset matching pages candidates in groups of 100.

For a GUI smoke test, import `tests/otserver_otter_files/OTserver-Otter-known-vulnerability.json` as
Otter JSON. Its Siemens S7-1500 CPU with firmware `V2.8.0` matches `CVE-2020-15782` when the NVD
catalog is loaded.

## Importer Development

Importers parse untrusted files. Keep size limits, validate structure and data types, treat optional
vendor fields as optional, ignore unknown fields safely, and return useful warnings.

To add an importer:

1. Add its durable UI metadata, quality, acquisition steps, and command if applicable to
   `src/importers/sources.ts`. The import modal reads this metadata.
2. Implement a parser returning `ImportResult` from `src/importers/types.ts`.
3. Register it in the parser map in `src/collections/AssetImports.ts`.
4. Merge through `mergeAssetData`; do not update assets directly from parser-specific logic.
5. Add an anonymized fixture and integration test covering parsing, scoped identity resolution, quality, and
   malformed input.

PRONETA has no public stable schema: accept known paths and capitalization variants, tolerate missing
and unknown fields, and preserve useful raw data. Nmap input must be XML produced with `-oX`.
Otter producer conformance is checked against the canonical schema and shared fixtures; management
also rejects malformed required structure while keeping unknown optional evidence opaque. A contract
change requires coordinated updates to the canonical schema and Rust implementation in
`otserver-otter`, an updated submodule pointer here, plus this repository's TypeScript importer,
fixtures, and tests.

Human-supplied bulk import fields are declared once in `userSuppliedAssetFields` in
`src/collections/Assets.ts`; the asset and import UIs derive from it. Custom field definitions are
admin-managed in `asset-fields`, stored by definition ID, validated server-side, and cannot change
type after creation.

Imports execute synchronously in replica-set transactions, capped at 2000 device/component/link
records. Parser failures are recorded; persistence failures must escape the hook to roll back the
inventory. Exact file/site/source/override replays do not duplicate evidence. Introduce queued
chunking when larger scans justify it. v2 lacks adequate negative coverage for automatic offline
inference; do not interpret a missing/partial observation as proof that a device is offline.

Deleting an import does not release asset identity bindings. To retry a previously applied upload
after asset cleanup, delete its import record and upload it again; otherwise exact-file replay
protection skips processing. The Assets CSV is a schema-dependent diagnostic export, whose columns
may change with the stored asset schema.

Queued imports retain the same 2000-record atomic limit and call the shared `processImport` service.
Workers must reload the executing user, recheck current site permissions, verify upload digests, and
run under the database fence. Never put credentials or serialized requests in job inputs. The web
process owns both queues by default. Set `OTSERVER_WORKER_MODE=external` only when dedicated workers
started with `pnpm worker:imports` and `pnpm worker:maintenance` are healthy. Queued uploads also
require `OTSERVER_QUEUED_IMPORTS=on`.

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
- Keep `brace-expansion` at 5.0.12 or newer; `patches/minimatch@3.1.5.patch` adapts the legacy
  CommonJS import to its named export. Include dependency patches in container installs.
- Never commit `.env`, `otter.json`, legacy `otscanner.json`, discovery output, uploads, build output,
  or caches. The root `.gitignore` contains the expected patterns.

## Local Setup and Checks

Requirements: Node.js 22, pnpm 10, and a MongoDB 8 replica set. Copy `.env.example` to `.env` and use
a long random `OTSERVER_SECRET`. `docker compose up` provides the standalone OTserver and MongoDB;
the optional `workers` profile is only for separate high-throughput workers.

Use `docker compose up -d mongo` for only the local development database, or
`docker compose up -d --build` for the complete application. Open `http://localhost:3000/admin`;
the first account receives the protected Admin role.

### Deployment and worker configuration

- Prebuilt images are published as `ghcr.io/ruveydac/otserver:latest`, `X.Y.Z`, and `X.Y`. Use an exact
  version tag for pinned deployments. The repository Compose file builds `otserver:local`.
- Standalone mode runs the web application and both fenced queues. To use separate workers, set
  `OTSERVER_WORKER_MODE=external` and `OTSERVER_QUEUED_IMPORTS=on`, then run
  `docker compose --profile workers up -d`. Confirm both worker heartbeats in the administrator
  operations endpoint before relying on external mode.
- For a custom Compose deployment, pass the optional settings from `.env` into container
  `environment` explicitly: `OTSERVER_PUBLIC_URL`, `OTSERVER_OTTER_ENCRYPTION_KEY`,
  `OTSERVER_QUEUED_IMPORTS`, `OTSERVER_VULNERABILITY_FEEDS`, `OTSERVER_WORKER_MODE`, and `NODE_OPTIONS`.
  The minimal README deployment passes only the database URL and application secret.
- External workers use the same database and `OTSERVER_SECRET` as the web application. Import workers
  need read access to `import-files`; maintenance workers need read/write access and the same online
  feed setting as the web process. The existing Compose `workers` profile defines these services.
- Managed Otter requires `OTSERVER_PUBLIC_URL` and a stable, backed-up encryption key generated with
  `openssl rand -hex 32`. For same-host development, use `http://localhost:3000`; remote controllers
  require HTTPS. See `otter_management.md` for enrollment, configuration, and protocol details.
- Standalone Otter uploads use a user's Payload API key and current site permissions. Managed
  uploads use scanner credentials instead. Standalone SNMP/OPC UA credentials remain in
  executable-adjacent `otter.json`; never include them in logs or scan exports.

### Container memory and temporary storage

Runtime commands must preserve operator-supplied `NODE_OPTIONS`. The production image defaults to
`--max-old-space-size=2048`; container memory must also cover native allocations and upload buffers.
NVD maintenance needs writable, disk-backed temporary storage for one decompressed annual file
(up to 2 GiB).

For a Kubernetes container with a 4 GiB memory limit, a starting point is:

```yaml
env:
  - name: NODE_OPTIONS
    value: '--max-old-space-size=2048'
resources:
  requests:
    memory: 1Gi
  limits:
    memory: 4Gi
```

Set `NODE_OPTIONS` before Node starts; loading it from the application's `.env` cannot resize a
running heap. Do not equate the V8 heap with the container memory limit. A JavaScript heap exhaustion
and Kubernetes `OOMKilled` are different failures. Roll out new pods after changing either limit,
and remove conflicting `--max-old-space-size` application arguments.

NVD staging uses `TMPDIR` (default `/tmp`). Give maintenance writable disk-backed storage even with
a read-only root filesystem; avoid memory-backed `emptyDir`. Allow at least 3 GiB of free temporary
disk space plus ephemeral-storage capacity for the image and logs. Handled failures clean up staging;
after a forced kill, remove abandoned `otserver-nvd-*` directories only while maintenance is stopped.

Inspect the environment and heap limit for a fresh Node process with:

```bash
kubectl exec <pod> -c <container> -- node -e 'console.log({NODE_OPTIONS:process.env.NODE_OPTIONS,heapLimitMiB:require("node:v8").getHeapStatistics().heap_size_limit/1024/1024,constrainedMemoryMiB:process.constrainedMemory()/1024/1024})'
```

Explicit arguments on the application command can still give that process a different limit.

### Test checks

Test commands own a disposable MongoDB 8 replica set and a unique upload directory. Use Docker or
Podman; direct Vitest invocations stop before loading Payload unless an owning test harness supplies
`OTSERVER_TEST_DATABASE_OWNER`, `TEST_DATABASE_URL`, and `OTSERVER_TEST_UPLOAD_DIR`.

```bash
pnpm test
```

MongoDB operations sharing a request transaction must run serially. `withAudit` establishes the
transaction before Payload 3.87's parallel relationship validation can race its first command.

Run `pnpm test:container` after changing the Dockerfile or startup/bootstrap behavior. It detects
Docker or Podman, builds the production image, starts an isolated MongoDB replica set, verifies the
fresh-database seeds, external workers without `.env`, queue processing, first-user registration,
and a database/upload/secret restore, then removes its containers and network.
Set `CONTAINER_RUNTIME=docker` or `CONTAINER_RUNTIME=podman` to select the runtime explicitly.

`vitest.config.mts` sets 60s per-test and hook timeouts because these tests boot Payload against a real
MongoDB. A cold container makes the first run slower than later ones.

Run the smallest relevant checks while developing, then the full set before committing:

```bash
pnpm test
pnpm test:coverage
pnpm lint
pnpm build
git diff --check
```

Run `pnpm check:generated` for generated-file drift. Production upgrades drain workers, back up the
database and uploads, and apply versioned migrations before workers restart; see `docs/operations.md`.

`pnpm test:coverage` enforces at least 90% statements, branches, functions, and lines for the
application. `src/migrations/**` is excluded from the percentage; exercise migration behavior with
the real database migration runner in focused integration tests.

Vitest runs integration files serially because they share database state. New behavior affecting
authorization, imports, quality precedence, audit logs, parsing, or bulk operations needs a focused
integration test. Otter implementation and protocol tests belong in the `otserver-otter`
repository. Run `pnpm test:otter-client` to build the headless executable and verify real-client REST
enrollment, import, and credential reuse after restart. To test a specific
build, use `OTTER_CLIENT_BIN=otserver-otter/target/debug/otserver-otter pnpm test:int
tests/int/otter-client.int.spec.ts`. Local-file CLI/GUI operation must
remain independent of the managed `controller` command and its private state directory.

The development server permits HMR only from `192.168.50.*` in `next.config.ts`. Keep production
origin policy separate from this home-network development exception.

## Change Discipline

- Preserve existing user work in a dirty tree and avoid unrelated cleanup.
- Prefer existing helpers and standard-library behavior over new abstractions or dependencies.
- Fix invariants at their shared boundary rather than patching individual callers.
- Keep admin UI components free of server functions and other non-serializable Payload/Next objects.
- Use `initPageResult.req.user` for custom-view authorization and server-side queries; top-level
  `user` props are read-filtered and may omit roles. List/dashboard slots without a request use
  `authenticatedAdminUser` from `src/integrations/payload/adminUser.ts`. Keep principals server-only.
- Admin copy uses sentence case and “Otter configuration” (the API retains `otter-profiles`).
  Passive catalog results are “Potential vulnerability matches”; use “Create” for documents,
  “Enroll” for scanners, and “Select” for choices. Reuse Payload controls and theme tokens.
- Do not weaken validation, access control, auditing, or Otter safety to make a test pass.
- Update this file only for durable guidance, not temporary status or implementation notes.
