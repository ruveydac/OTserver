# Agent Guide

This file applies to the entire repository. Keep it current when a change alters a durable project
rule, command, contract, or architectural boundary.

## Read First

- Payload work must follow `.agents/skills/payload/SKILL.md`; use its reference directory when the
  quick reference is insufficient.
- Product setup and operator basics are in `README.md`.
- Scanner usage and platform requirements are in `scanner/README.md`.
- The OTserver Scanner/importer wire contract is `contracts/otserver-scan-v2.schema.json`.

## Project Summary

OTserver is an OT asset-management application built with Payload CMS 3, Next.js 16, React 19, and
MongoDB. It manages assets, hierarchical sites, scoped user roles, imports, observations, topology,
custom asset fields, and an immutable audit trail. Its product domain is `otserver.org`.

The repository also contains OTserver Scanner, an AGPL Rust scanner for Windows and Linux. It
discovers devices without Nmap and exports `otserver-scan` schema-version-2 JSON for OTserver.

Main locations:

- `src/collections/`: Payload collections and hooks.
- `src/access/authorization.ts`: site-scoped authorization shared by collections and hooks.
- `src/importers/`: PRONETA XML, Nmap XML, OTserver Scanner JSON, source metadata, and quality merging.
- `src/search/`: Lucene syntax translation and graphical-filter integration.
- `src/components/`: custom Payload admin views and fields.
- `scanner/src/`: native discovery, protocol clients, SNMP, CLI, and export contract.
- `scanner/lab/`: isolated Docker interoperability lab.
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
OTserver Scanner JSON must validate against schema version 2. A contract change requires coordinated
updates to the schema, Rust serializer/validator, TypeScript importer, fixtures, and tests.

Human-supplied bulk import fields are declared once in `userSuppliedAssetFields` in
`src/collections/Assets.ts`; the asset and import UIs derive from it. Custom field definitions are
admin-managed in `asset-fields`, stored by definition ID, validated server-side, and cannot change
type after creation.

Imports currently execute synchronously and can be partially applied. Introduce a queue and database
transaction only when real file sizes or atomicity requirements justify it.

## OTserver Scanner Development

- OTserver Scanner is read-only and must require `--ack-authorized` for scans.
- Never add configuration writes, DCP Set, SNMP SET, brute force, exploits, vulnerability scripts, or
  Modbus requests without an explicit product decision and safety review.
- Supported native queries are ARP, PROFINET DCP Identify, S7 identity, EtherNet/IP List Identity,
  BACnet ReadProperty, Omron FINS identity, Niagara Fox hello, OPC UA asset discovery, SNMP GET/WALK, and LLDP.
- Scanner protocols are enabled by default and each has an independent CLI disable flag and GUI
  toggle. Keep SNMP inventory and SNMP-transported LLDP topology independently selectable.
- Linux raw Ethernet uses `AF_PACKET` and needs root or `CAP_NET_RAW`. Windows ARP uses native
  Win32 IP Helper. Windows active DCP dynamically loads an installed Win10Pcap `Packet.dll` from the
  system directory and binds the selected physical adapter by GUID; do not introduce a TAP adapter
  or Windows Network Bridge. Explicit elevated setup may install the bundled, unmodified, signed
  Win10Pcap GPLv2 MSI, but driver installation must never be a scan side effect. When Win10Pcap is
  absent, passive discovery uses Microsoft pktmon. Preserve these paths.
- Active DCP must verify that its source MAC belongs to the selected physical interface. Identify-All
  uses engineering-tool `ResponseDelayFactor` `0x0080` and is sent once per scan so responders spread
  their replies; never use the reserved zero factor or rapid retries that can create a response storm.
- Keep protocol framing and parsing in `scanner/src/protocols/` or the existing dedicated modules.
  Reject truncated, oversized, mismatched, or unsolicited responses.
- SNMP and OPC UA settings, including credentials, live in the executable-adjacent
  `otscanner.json` and are fully editable in the GUI. There are no separate SNMP profile files,
  credential environment variables, or interactive credential prompts. Without SNMP settings, scans
  default to SNMPv2c with community `public`, so SNMP must never gate or block a scan. Credentials
  must never appear in logs or scan exports. SNMP `auto` mode is opt-in: try usable v3 settings,
  then v2c, then v1 within the existing per-target timeout and stop at the first successful version.
  Explicit version selections do not fall back.
- Direct scanner imports use Payload's existing `asset-imports` REST upload with a native per-user API
  key so site authorization, validation, merging, and auditing remain shared with manual imports.
- `otscanner.json` lives beside the scanner executable and holds all scan defaults, SNMP and OPC UA
  credentials, and upload settings. It may contain one config object or an ordered list whose entries
  have unique names and output paths; the GUI can convert a single object into a list by cloning the
  selected config, and GUI and CLI batch runs are sequential. `--ack-authorized` must remain explicit
  for every invocation. `OTSERVER_API_KEY` overrides the config-file key. Every scan-log line starts
  with `[HH:MM]`.
  Keep the per-IP `<ip> Protocol <name> Success/Fail` result and sanitized SNMP attempt details, but
  never log communities, usernames, contexts, or passwords.
- The scanner version in `scanner/Cargo.toml` is authoritative for CLI output, GUI display, exports,
  uploads, and Windows file properties. Windows GUI startup may detach from the console, but CLI
  commands must retain normal terminal behavior.
- The Docker lab uses maintained stacks where available and minimal fixed responders for FINS and
  Fox. It must not publish OT ports to a physical adapter or use host networking. The Windows-host
  harness may bind its test ports only to Docker/WSL's host-only Hyper-V adapter and must clean up
  its temporary Compose project.

### OPC UA Design Decisions

- SecurityPolicy None only. The scanner opens only unsecured channels. Encrypted endpoints are not
  supported. Credentials travel unencrypted when username authentication is used; the scanner warns
  about this and requires explicit configuration. Most OT OPC UA servers in target environments use
  None security, and adding certificate management would complicate deployment without proportional
  benefit.
- No continuation point following. Browse operations that return continuation points fail with an
  error rather than paginating. OT asset servers typically have small address spaces; continuation
  points indicate an unexpectedly large result set that likely represents a misconfiguration or
  non-standard server. Failing fast surfaces these cases.
- Bounded batch reads. The scanner limits reads to 64 variables per batch. This prevents overwhelming
  servers with large address spaces and keeps discovery latency predictable. The OPC UA DI model
  specifies a fixed set of standard variables well under this limit.
- Certificate authentication rejected. The scanner supports anonymous and username/password
  authentication but never attempts certificate-based client authentication. Certificate management
  adds substantial complexity for a feature rarely used in OT environments.
- Multi-port probing. The scanner probes ports 4840, 4841, and 48400 by default. Port 4840 is the
  IANA-assigned OPC UA port; 4841 and 48400 are commonly used by specific vendors.
- FindAlias with DeviceSet fallback. Asset identity resolution uses the standardized
  `Objects/Aliases/Assets` alias categories with the `FindAlias` method when available, falling back
  to the OPC UA DI `DeviceSet` when aliases are absent.

## Search

Asset search accepts the supported Lucene subset in `src/search/assetLucene.ts`. The graphical filter
builder is a query-language assistant, not an independent filter path. Keep both representations in
sync. Unsupported regex, fuzzy, boost, invalid range, unknown-field, oversized, and deeply nested
queries must continue to fail with a clear HTTP 400 error.

## Generated Files

- Do not hand-edit `src/payload-types.ts`; run `pnpm generate:types` after collection schema changes.
- Regenerate the Payload admin import map with `pnpm generate:importmap` when component registrations
  change.
- Commit `scanner/Cargo.lock` and `pnpm-lock.yaml` when their manifests change.
- Never commit `.env`, `otscanner.json` with real credentials, scanner output, uploads, build output, Docker lab artifacts,
  or Python/Rust caches. The root `.gitignore` contains the expected patterns.

## Local Setup and Checks

Requirements: Node.js 20.9+, pnpm 9-11, MongoDB, and stable Rust. Copy `.env.example` to `.env` and use
a long random `OTSERVER_SECRET`. `docker compose up` can provide OTserver and MongoDB.

Run the smallest relevant checks while developing, then the full set before committing:

```bash
pnpm test
pnpm test:coverage
pnpm lint
pnpm build

cd scanner
cargo fmt -- --check
cargo check --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cd ..

./scanner/lab/test.sh
git diff --check
```

`pnpm test:coverage` requires `cargo-llvm-cov`. It enforces at least 90% statements, branches,
functions, and lines for the application, and at least 90% line coverage for the scanner library.

Vitest runs integration files serially because they share database state. New behavior affecting
authorization, imports, quality precedence, audit logs, parsing, or bulk operations needs a focused
integration test. Scanner branch/loop/parser logic needs a small Rust unit test; protocol
interoperability belongs in the Docker lab.

The development server permits HMR only from `192.168.50.*` in `next.config.ts`. Keep production
origin policy separate from this home-network development exception.

## Change Discipline

- Preserve existing user work in a dirty tree and avoid unrelated cleanup.
- Prefer existing helpers and standard-library behavior over new abstractions or dependencies.
- Fix invariants at their shared boundary rather than patching individual callers.
- Keep admin UI components free of server functions and other non-serializable Payload/Next objects.
- Do not weaken validation, access control, auditing, or scanner safety to make a test pass.
- Update this file only for durable guidance, not temporary status or implementation notes.
