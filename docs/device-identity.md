# Physical device identity

## Model and rules

`assets` represent persistent physical entities and may have no MAC address. Asset classes remain
admin-managed. A chassis and its CPU/communication/I/O modules have separate records and versions.

- `network-endpoints` record interface/address evidence and its association with an asset.
  MAC uniqueness applies only to a current binding within one exact site. Ended associations remain.
- `service-bindings` record listeners for which an address/transport/port association is known.
- `asset-installations` record time-bounded parent/module containment, with an optional slot path.
  Unknown positions stay empty. Slot and module identities are independent.
- `asset-identifiers` reserve accepted hardware keys and retain contested/revoked identifiers.
- `identity-cases` retain explainable conflicts and replacement/cross-site reconciliation work.

Every collection is audited. Original observations are immutable and retain their original asset,
site, and optional endpoint. Reconciliation does not rewrite historical observations. Asset views
include merged aliases and observations attached to reassigned endpoints, subject to site access.

## Identity policy

The manager automatically associates exact accepted component-specific hardware keys within the
owning site. IP, names, OUI, and topology do not authorize automatic physical merges. Existing
site-scoped MAC bindings continue provisional tracking. Changed or ambiguous hardware serials create
review cases instead of overwriting an established identity.

The confidence field is ordinal (3 hardware, 2 endpoint, 1 heuristic, 0 unresolved), not a percentage.
Field-value quality remains separate: `human > high > medium > low`, using `mergeAssetData`.
`lastSeen` advances by observation time; old uploads retain evidence without regressing current
network state. A duplicate file with identical site, source, and overrides is reported as
`duplicateOf` and does not repeat its observations.

Hardware UUID keys use namespace `a346ed7e-daca-4e40-8bb1-72f0a9119943` and UUIDv5 over the UTF-8
encoding of this JSON array (no whitespace):

```
["ot-hardware-v1", authority, manufacturer, scope, productScopeOrEmptyString, serial]
```

Authority/manufacturer identifiers are trimmed and lowercased. Text serials preserve case and
leading zeros. CIP vendor IDs are decimal identifiers and CIP serials are eight uppercase hex
digits. Empty/placeholding values are rejected. UUIDv5 keys are portable aliases; an asset's
Payload ID and public UUID remain stable when stronger evidence or corrections arrive.
Revoke an incorrect key and add a corrected one rather than editing its canonical inputs.

## Supported Otter v2 evidence

- EtherNet/IP raw `vendorId`, `deviceType`, and serial agreeing with the exported field identify
  the responder: type 12 is an adapter, type 14 a CPU, other types the responding device.
- S7 serials accompanied by raw module identification identify the CPU queried. They do not
  identify a backplane. If another protocol identifies an adapter, the CPU is a separate record.
- ENTITY-MIB raw OIDs identify qualified chassis/module records, retaining containment. A raw
  table index does not become a fabricated slot number.
- Unresolved v2 observations can still yield qualified MAC-free hardware identities.
- Interface IP lists are preserved. Device-level port lists yield service bindings only when the
  protocol's observation identifies one unambiguous listening address. Unknown ownership/routes
  are left unspecified. A protocol-target association is not proof of physical NIC ownership.

PRONETA and Nmap use the same site-scoped endpoint and field-quality pipeline. Site hierarchy is an
authorization mechanism only: parent and child sites have separate endpoint identity namespaces.
The topology view infers network membership from recorded subnet, ARP, and topology evidence rather
than treating the site itself as proof of physical cable connectivity.

## Operator actions

The asset detail view provides verified identifier, endpoint, installation, and review links plus
identity actions. The API is `POST /api/assets/:id/identity` with a JSON body and authenticated user.
Every action requires a non-empty `reason` and write permission to affected assets.

| action | additional fields | behavior |
| --- | --- | --- |
| `merge` | `target` asset ID | Reassign current endpoints/accepted identifiers and installations; retain the source as a merged alias. Conflicting accepted serials must first be reviewed/revoked. Target descriptive metadata is retained; source metadata remains in its original record. |
| `split` | `endpoints` IDs; optional `target`, `identifiers`, `name` | Move selected associations to an existing active or new provisional asset. Move only explicitly selected identifiers. |
| `replace` | `target` asset ID | Close old bindings/installations, associate replacement hardware, and mark it unbaselined. Service availability must be observed again. |
| `transfer` | destination `site` ID | Require write permission to both sites; close old endpoints and create destination associations without assuming old IPs remain valid. Remove active installations before transfer and reinstall at the destination. |
| `retire` / `restore` | — | Change physical lifecycle independently of maintenance/reachability. Retirement closes current endpoints. |
| `close-endpoint` | `endpoint` ID | End an association while keeping evidence and service history. |

Cross-site discoveries create opaque reconciliation cases, not an automatic move or disclosure of
the other site's inventory. An administrator or user with both-site write permission can transfer
and then reconcile. Original observation sites remain the authorization scope for historical data.

Lifecycle archival uses `retired`, `replaced`, or `merged`, never Payload trash. Trash still follows
the separate existing deletion/retention policy. Mark reachability offline only from actual operator
knowledge. v2 lacks sufficient per-target negative coverage to infer offline state automatically;
the required collector work is in [otter-identity-roadmap.md](otter-identity-roadmap.md).

Vulnerability lookup uses each installed module's own metadata/version and shows distinct assembly
CVEs with affected component names. Catalog-backed CPE names are retained as match evidence. Counts
on individual asset records remain derived; detailed CVEs remain in the local catalog. Descriptive
catalog/part numbers improve product matching without becoming physical identity keys.

## Transactions and limits

MongoDB must be a replica set. A single-node replica set supports local development; use the normal
replica-set deployment appropriate to production availability requirements. Payload operations and
identity actions share their original request and transaction. Required uniqueness indexes are
awaited at startup. Payload 3.87's concurrent relationship validation is preceded by a serial read
to establish the transaction on the server.

Imports are synchronous, all-or-nothing transactions bounded to 2000 device/component/link records.
Parser failures are saved as failed imports. A persistence failure propagates and rolls back the
inventory transaction; the upload caller receives an error and may safely retry the retained scan
file. Concurrent conflicting transactions may be retried; unique hardware/binding/import keys
prevent duplicate accepted identities and replays. Larger workloads should use a coordinated
queued/chunked import design rather than raising this bound blindly.

## Upgrade from MAC-only inventory

1. Back up the database and import files. Stop manager writers for the maintenance window.
2. Configure MongoDB as a replica set. The repository Compose configuration initializes `rs0`.
   A host-side connection to that development container needs `directConnection=true`.
3. Before starting the upgraded manager, remove only the legacy unique MAC index:

   ```bash
   mongosh "$DATABASE_URL" scripts/migrate-identity-index.js
   ```

   The script is idempotent and does not change documents. Startup creates the new non-unique MAC
   lookup index and the unique site-scoped identity indexes. Do not run the old manager after this
   step.
4. Start the manager. As an administrator, POST to `/api/assets/migrate-identity` with `{"page":1}`
   for a dry run. POST `{"page":1,"apply":true}` to apply a batch of 100 records, then increment
   `page` while `hasNextPage` is true. Batches are transactional and can be repeated. Keep writers
   paused until the final page so pagination remains stable.
5. Verify UUIDs, endpoint counts, owning sites, search, and historical evidence on representative
   records. Legacy serial strings are deliberately not promoted into accepted hardware identities.
6. Resume writers and import new evidence. Review identity cases.

Rollback before resuming writes is a restore of the database/files backup and the prior manager
version. Once multi-interface/MACless identities exist, rolling back only the code is incompatible.

## Dedicated test replica set

```bash
podman run -d --rm --name otserver-identity-test-mongo -p 27018:27017 \
  docker.io/library/mongo:8 --replSet rs0 --bind_ip_all
podman exec otserver-identity-test-mongo mongosh --quiet --eval \
  'rs.initiate({_id:"rs0",members:[{_id:0,host:"localhost:27017"}]})'
TEST_DATABASE_URL='mongodb://127.0.0.1:27018/otserver-test?replicaSet=rs0&directConnection=true' \
  OTSERVER_VULNERABILITY_FEEDS=off pnpm test
podman stop otserver-identity-test-mongo
```
