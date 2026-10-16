# OTserver

Self-hosted asset management for operational technology (OT) networks.

OTserver helps you keep track of industrial devices, where they are installed, and how they
change over time. Add assets manually or import discovery results from
[OTserver Otter](https://github.com/ruveydac/otserver-otter), Siemens PRONETA, or Nmap.

[Website](https://otserver.org) · [Quick start](#quick-start) · [Discovery](#discovery-with-otserver-otter) · [License](#license)

![OTserver asset management dashboard](public/otserver-dashboard.png)

## What you can do

- Maintain an inventory of device manufacturers, models, firmware, protocols, ownership, and custom fields.
- Organize assets into sites using a hierarchy that fits your organization.
- Give teams read-only or read/write access to the sites they manage.
- Combine discovery results while preserving manual edits and the source of each value.
- Search and filter assets, inspect topology, and review an immutable change history.
- Enroll Otter scanners, configure discovery, schedule scans, and review results centrally.
- Find potential vulnerability matches using recorded device metadata and local vulnerability catalogs.
  This lookup does not actively test devices and does not confirm that a device is vulnerable.

## Quick start

With Docker Engine and Compose installed, save this as `compose.yaml`:

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

Create a `.env` file beside it:

```dotenv
OTSERVER_SECRET=replace-with-a-long-random-secret
```

Keep this secret across restarts. Then start OTserver:

```bash
docker compose pull
docker compose up -d
```

Open <http://localhost:3000/admin> and create the first administrator account.
The named volumes retain the database and uploaded import files.
For a pinned deployment, replace `latest` with an exact release tag (`X.Y.Z`).

### Build your first inventory

1. Create your site hierarchy under **Sites**.
2. Add assets manually or create an import, selecting its site and discovery source.
3. Review the import results, then open an asset to see its details and history.

Supported import formats are OTserver Otter JSON, Siemens PRONETA topology XML, and Nmap XML
produced with `-oX`.

## Discovery with OTserver Otter

[OTserver Otter](https://github.com/ruveydac/otserver-otter) is the companion discovery tool for
Windows and Linux. It uses read-only industrial protocol requests to collect device identities,
network interfaces, and topology. Only scan networks you own or are authorized to assess.

Download it from the [Otter releases page](https://github.com/ruveydac/otserver-otter/releases),
run discovery, and import the resulting JSON into OTserver. You can also enroll scanners in
OTserver to manage configurations and schedules centrally.

For managed scanners, set `OTSERVER_PUBLIC_URL` and a stable `OTSERVER_OTTER_ENCRYPTION_KEY`
in the OTserver container environment. See [Otter management](otter_management.md) for setup.

## Development and technical guidance

Local development requires Node.js 22, pnpm 10, and a MongoDB 8 replica set:

```bash
cp .env.example .env
# Set DATABASE_URL and replace OTSERVER_SECRET with a long random value.
pnpm install
pnpm dev
```

See [AGENTS.md](AGENTS.md) for architecture, domain rules, worker configuration, runtime sizing,
vulnerability-feed operations, and test commands.

## License

OTserver and OTserver Otter are dual-licensed:

1. [GNU Affero General Public License v3](LICENCE.md).
2. A commercial license for enterprises, SaaS providers, and organizations integrating OTserver.

The open-source core will remain open source, including the scanner, detection needed to find
assets and device capabilities, and base asset-management features. Optional proprietary add-ons,
such as SSO integrations or customized dashboards, do not replace or restrict that core.

For commercial licensing, SLA support, or enterprise features, visit
[otserver.org/enterprise](https://otserver.org/enterprise/).
