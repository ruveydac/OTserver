<div align="center">

# OTserver

### Self-hosted OT inventory with automatic discovery found here [OTserver Otter repository](https://github.com/ruveydac/otserver-otter)

Native OT discovery · Quality-aware inventory · Site-scoped access · Immutable history

[![Website](https://img.shields.io/badge/otserver.org-111111?logo=firefoxbrowser&logoColor=white)](https://otserver.org)
[![Next.js](https://img.shields.io/badge/Next.js-000000?logo=nextdotjs&logoColor=white)](https://nextjs.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-001E2B?logo=mongodb&logoColor=47A248)](https://www.mongodb.com/)
[![Rust](https://img.shields.io/badge/Otter-Rust-000000?logo=rust&logoColor=white)](https://github.com/ruveydac/otserver-otter)
[![AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENCE.md)

[Quick start](#quick-start) · [How it works](#how-it-works) · [Imports](#discovery-and-imports) · [Otter](#otserver-otter) · [Development](#development)

</div>

---

OTserver provides a trustworthy industrial inventory. Automatic discovery lives in the separate
**[OTserver Otter](https://github.com/ruveydac/otserver-otter)** repository: a cross-platform Rust CLI
built specifically for identifying industrial devices through fixed, read-only protocol requests.
It collects structured evidence—not just a flat host list—and exports observations, interfaces,
ports, and topology through a strict versioned contract understood directly by the manager.

OTserver turns that evidence into a site-scoped inventory with provenance-aware
field merging, flexible hierarchies, role-based access, search, and a complete audit trail.

![OTserver asset management dashboard](public/otserver-dashboard.png)

## What you get

- **OTserver Otter** — Discover devices on Windows and Linux using native ARP, PROFINET
  DCP, S7, EtherNet/IP, BACnet, Omron FINS, Niagara Fox, DNP3, IEC 61850, OPC UA, SNMP, and LLDP
  requests.
- **Rich discovery evidence** — Preserve per-protocol observations, field quality, interfaces,
  ports, topology links, warnings, and partial failures in a validated JSON contract.
- **OT inventory** — Automatically track vendor, model, firmware, protocols, ownership, location,
  status, criticality, and custom fields.
- **Flexible site hierarchy** — Model regions, plants, areas, lines, cells, or any structure your
  organization uses.
- **Scoped access** — Grant read-only or read/write access to a site and all its descendants. A
  protected Admin role retains unrestricted access.
- **Discovery imports** — Ingest Siemens PRONETA XML, Nmap XML, and OTserver Otter JSON into a
  selected site.
- **Physical device identity** — Correlate qualified hardware identities across multiple network
  interfaces; retain scoped MAC bindings, module installations, and replacement history.
- **Evidence-aware merging** — Higher-quality discoveries can improve lower-quality data while
  human edits remain authoritative. Protocol evidence is combined across sources.
- **Search and filters** — Use the graphical filter builder or a supported Lucene query syntax for
  precise inventory searches.
- **Traceable history** — Retain source observations and topology links alongside an immutable,
  secret-redacting audit log.
- **Passive vulnerability lookup** — Match recorded vendor, product, and version data against local
  CISA KEV and NVD catalogs without probing the device.

## Quick start

### Docker deployment (GitHub Container Registry)

Deploy the prebuilt image from GitHub Container Registry:
`ghcr.io/ruveydac/otserver:latest`. Release images also have version tags (`X.Y.Z` and
`X.Y`); use an exact version tag for a pinned deployment.

With Docker Engine and Compose installed, create a deployment directory containing this
`compose.yaml`:

```yaml
services:
  otserver:
    image: ghcr.io/ruveydac/otserver:latest
    restart: unless-stopped
    ports:
      - '3000:3000'
    environment:
      DATABASE_URL: mongodb://mongo:27017/otserver?replicaSet=rs0
      OTSERVER_SECRET: ${OTSERVER_SECRET:?Set OTSERVER_SECRET in .env}
    volumes:
      - import-files:/app/import-files
    depends_on:
      mongo:
        condition: service_healthy

  mongo:
    image: mongo:8
    restart: unless-stopped
    command: ['--replSet', 'rs0', '--bind_ip_all']
    healthcheck:
      test:
        [
          'CMD',
          'mongosh',
          '--quiet',
          '--eval',
          'try { if (!rs.status().ok) quit(1) } catch (e) { rs.initiate({_id:"rs0",members:[{_id:0,host:"mongo:27017"}]}); quit(1) }',
        ]
      interval: 5s
      timeout: 5s
      retries: 30
    volumes:
      - data:/data/db

volumes:
  data:
  import-files:
```

Create a `.env` file beside it with a long random secret, and keep that secret across restarts:

```dotenv
OTSERVER_SECRET=replace-with-a-long-random-secret
```

Pull the images and start the application and MongoDB:

```bash
docker compose pull
docker compose up -d
```

Open <http://localhost:3000/admin> and create the first administrator account.
The named volumes persist database data and uploaded import files.

For an upgrade from MAC-only inventory, follow the [identity migration](docs/device-identity.md#upgrade-from-mac-only-inventory)
before starting this version. It requires a replica set and removal of the legacy unique MAC index.
For subsequent upgrades, back up those volumes, update the image tag if pinned, then run
`docker compose pull && docker compose up -d` again.

### Local development

Requirements: Node.js 20.9+, pnpm 9–11, and a MongoDB replica set.

```bash
cp .env.example .env
# Set DATABASE_URL and replace OTSERVER_SECRET with a long random value.
pnpm install
pnpm dev
```

Then open <http://localhost:3000/admin>. The first account receives the protected Admin role.

For container-based development, the repository's `docker-compose.yml` runs the source with
`pnpm dev`: prepare `.env` as above and run `docker compose up` from the repository root.
The source bind mount uses `:z` to allow container access on SELinux hosts (ignored on hosts
without SELinux). If an existing container reports `EACCES` opening `/home/node/app/package.json`,
apply the current Compose file with `docker compose up -d --force-recreate otserver`.

## First inventory

1. Create your hierarchy under **Sites**. Use any site types and nesting depth that fit the plant.
2. Add assets manually, or open **Imports → Create New** and select a discovery source.
3. Review created, updated, skipped, and unresolved records on the completed import.
4. Search the inventory or open an asset to inspect its details, observations, topology, and history.

## How it works

Every asset and import belongs to a site. Assets represent physical hardware; scoped network
endpoints store their interfaces and addresses. Qualified manufacturer/component serial identities
can correlate multiple interfaces to one device. Ambiguous identities create review cases, and
cross-site matches require explicit reconciliation. MAC-free chassis/modules can be inventoried.

See [device identity and migration](docs/device-identity.md) for the model, supported evidence,
operator actions, transaction requirements, and compatibility behavior. Scanner changes are tracked
in the [future Otter identity roadmap](docs/otter-identity-roadmap.md).

Field values are merged in this order:

```text
human > high > medium > low
```

Empty values can always be filled. Equal-quality evidence may replace changed values, stronger
evidence may replace weaker values, and weaker evidence cannot overwrite stronger data. Manual edits
are recorded as human provenance and survive future imports.

### Vulnerability lookup

OTserver downloads the CISA Known Exploited Vulnerabilities catalog, NVD JSON 2.0 feeds, the
CERT@VDE CSAF 2.0 aggregator, CISA's OT and IT CSAF ROLIE feeds, and the ICS Advisory Project master
CSV in the background when the application starts. Each start first checks when the catalogs were
last pulled and downloads nothing until they are seven days old, so restarts are cheap. Set
`OTSERVER_VULNERABILITY_FEEDS=off` for an air-gapped installation.

The first import is the expensive one: NVD publishes one file per year from 2002 onward, roughly
600 MB compressed and a dozen minutes of work, with a peak heap near 880 MB for the largest year.
Each year is recorded as it lands, so an interrupted import resumes where it stopped instead of
starting over.

Assets store only a derived vulnerability count. A CVE is counted only when its NVD or CSAF vendor
and product match the recorded asset data and the asset reports a version satisfying the affected
exact version or range. CISA KEV enriches matching records with known-exploitation information and
the ICS Advisory Project adds CISA ICS advisory identifiers, critical-infrastructure sectors,
product distribution, and vendor headquarters; neither can create a count on its own because neither
carries affected-version constraints.

The asset detail view lists the five most severe matches — known-exploited first, then highest CVSS —
and links to a paginated subview holding every match plus its evidence. Results are unvalidated
metadata matches, not evidence that the device is vulnerable. OTserver does not run active
vulnerability checks.

For a GUI smoke test, upload `tests/otserver_otter_files/OTserver-Otter-known-vulnerability.json`
under **Imports** as an OTserver Otter file. It creates a demo Siemens S7-1500 CPU with firmware
`V2.8.0`, which matches NVD `CVE-2020-15782` while the catalog is loaded.

## Discovery and imports

| Source          | Input                   | Default quality      | Best for                                                     |
| --------------- | ----------------------- | -------------------- | ------------------------------------------------------------ |
| OTserver Otter  | Schema-version-2 JSON   | Observation-specific | Native discovery with observations, interfaces, and topology |
| Siemens PRONETA | Topology XML            | High                 | Siemens-oriented discovery and topology exports              |
| Nmap            | XML produced with `-oX` | Medium               | Existing Nmap-based discovery workflows                      |

Import files are treated as untrusted input: parsers enforce size and structure limits, tolerate
optional vendor data, and report malformed or uncorrelatable observations as warnings. The canonical
wire contract is pinned through the `otserver-otter` submodule at
[`otserver-otter/contracts/otserver-scan-v2.schema.json`](otserver-otter/contracts/otserver-scan-v2.schema.json).

Example searches:

```text
vendor:Siemens AND status:online
protocol:profinet AND criticality:critical
site:"Plant 1" AND type:plc
lastseen:[2026-01-01 TO *]
```

## OTserver Otter

Download the scanner for your platform from the
[OTserver Otter releases page](https://github.com/ruveydac/otserver-otter/releases).

Otter is not a wrapper around a general-purpose scanning engine. Its discovery, protocol
framing, response validation, correlation, and export contract are implemented together for this
inventory workflow.

- **Native protocol identity** — Uses fixed queries designed to retrieve device identity without
  configuration changes, vulnerability scripts, or exploit behavior.
- **Evidence-preserving output** — Keeps protocol observations and raw source data alongside
  normalized devices instead of collapsing a scan into one guessed record.
- **Topology-aware collection** — Carries LLDP, SNMP, and PROFINET link evidence, network interfaces,
  and ports into OTserver.
- **Quality-aware by design** — Each observation reaches the importer with its source quality, so
  stronger evidence improves the inventory without overwriting human edits.
- **Predictable failure handling** — Produces valid partial results with warnings when individual
  probes fail, while malformed and unsolicited responses are rejected.

Otter requires `--ack-authorized` before a scan. Linux uses `AF_PACKET` raw sockets and needs
root or `CAP_NET_RAW`; Windows 10+ uses native Win32 IP Helper, a separately installed Npcap for
active PROFINET DCP, and Packet Monitor (pktmon) as a passive fallback.

```bash
otserver-otter doctor
sudo otserver-otter scan \
  --target 192.168.1.0/24 \
  --interface eth0 \
  --source-mac 00:11:22:33:44:55 \
  --output scan.otserver.json \
  --ack-authorized
```

Only scan networks you own or are authorized to assess. Otter does not perform configuration
writes, SNMP SET, DCP Set, DNP3 writes, operates, class assignment, freezes, or restarts, brute
force, exploits, vulnerability scripts, or Modbus requests.

Users can enable a Payload API key on their account. With an OTserver URL, site ID, and that key in
the Otter environment or executable-adjacent `otter.json`, Otter can send its completed
JSON directly to the existing REST importer with the user's current site permissions. The local
scan file is retained.

OTserver Otter, its platform guide, contract, tests, and interoperability lab are maintained in the
separate [`otserver-otter` repository](https://github.com/ruveydac/otserver-otter).

## Security and audit model

- Collection access rules enforce site permissions on the server; hiding an admin view is never the
  security boundary.
- Read and write permissions inherit through every descendant of the selected site.
- The protected Admin role is created automatically and cannot be renamed or deleted.
- All registered collections are audited for creates, updates, deletes, and authentication events.
- Audit entries are immutable and redact fields resembling passwords, secrets, tokens, hashes, or
  sessions.
- Otter SNMP and OPC UA settings, including credentials, live in executable-adjacent `otter.json`
  and are never included in logs or scan exports.

## Technology

| Layer         | Technology                                  |
| ------------- | ------------------------------------------- |
| Application   | Next.js 16, React 19, TypeScript            |
| Admin and API | OTserver, built on Payload CMS 3            |
| Database      | MongoDB                                     |
| Search        | Lucene subset translated to Payload queries |
| Otter         | Rust, native Windows and Linux capture      |
| Validation    | Vitest integration tests                    |

## Project layout

```text
src/collections/   OTserver collections, hooks, and domain rules
src/access/        Shared site-scoped authorization
src/importers/     PRONETA, Nmap, Otter parsers, and quality merging
src/search/        Lucene query translation and graphical-filter integration
src/vulnerabilities/ Feed synchronization, CPE parsing, and passive matching
src/components/    OTserver admin views, branding, and fields
otserver-otter/    Pinned scanner repository and canonical export contract
tests/int/         Application and importer integration tests
```

## Development

Run the smallest relevant check while working, then the full application suite:

```bash
pnpm test
pnpm lint
pnpm build
```

Coverage is enforced at 90% for the application:

```bash
pnpm test:coverage
```

Regenerate OTserver's Payload artifacts after schema or admin component changes:

```bash
pnpm generate:types
pnpm generate:importmap
```

## License

OTserver and OTserver Otter are dual-licensed:

The open-source core will remain open source: the scanner, all detection
needed to find assets and device capabilities, and the base asset-management
interface features. Enterprise offerings may add optional proprietary add-ons,
such as SSO integrations or customized dashboards; they do not replace or
restrict the open-source core.

1. **Open Source (GNU AGPLv3):** available under the
   [GNU Affero General Public License v3](LICENCE.md).
2. **Commercial License:** available for enterprises, SaaS providers, or
   organizations integrating OTserver into their systems.

For a commercial license, custom SLA support, enterprise features, or help
choosing the right license, visit [otserver.org/enterprise](https://otserver.org/enterprise/).
