# OTserver Otter management

OTserver now owns site-scoped scanner registrations, profiles, encrypted protocol credentials,
schedules, scan assignments, and run history. Scanner communication is outbound polling over HTTPS;
no inbound listener is required on an Otter host.

The Otter executable implements this protocol through the separate `controller` command. Its existing
local `otter.json`, CLI/GUI scans, and user API-key upload flow continue to work independently. Managed
mode enrolls, polls, executes assigned snapshots, and uploads with a machine credential. The scan
result remains the existing `otserver-scan` schema-version-2 document. Scanner setup, private state
storage, recovery, and verification commands are documented in `otserver-otter/README.md`.

## Scan-v2 contract and identity evidence

The canonical Draft 2020-12 schema is `otserver-otter/contracts/otserver-scan-v2.schema.json`.
Otter validates every serialized export against it, including UUID and date-time formats. Shared valid
and invalid fixtures are checked by both Rust and TypeScript tests. Management remains a tolerant
consumer for unknown optional protocol evidence, but required scan metadata, observations, links, and
their required fields must be valid. New exports set `scan.interface.ipRoutePolicy` to
`operating-system`; the selected interface records capture selection and does not bind native IP
probes to that interface.

Only these source-qualified fields can authorize physical identity in management:

- **EtherNet/IP:** `raw.vendorId` and `raw.deviceType` must be integers; `raw.serialNumber`, the
  source-qualified `raw.serialClaim`, and `fields.serialNumber` must agree. The claim manufacturer
  ID/scope must match the vendor ID/device type. `raw.subject` must identify the same device or
  qualified MAC-free endpoint as the observation.
- **S7:** `raw.module` and `fields.serialNumber` must both be present, and `raw.serialClaim` must name
  the same serial with Siemens as issuer and CPU scope. `raw.subject` must resolve to the observed
  device or qualified MAC-free endpoint.
- **SNMP ENTITY-MIB:** `raw.physicalEntities` supplies the entity reference, class, and scoped serial
  claim. The claim reference, class/scope, issuer, and original serial must match the SNMP OID values.
  `raw.subject` must match the reported device MAC, or a MAC-free endpoint must match its observation
  IP and UUID `raw.observationId`. Only one unparented chassis/stack selected by
  `raw.identityComponentRef` and the matching top-level `raw.serialClaim` can identify the device.
  Module-only and ambiguous-root records cannot identify the device; a separately qualified component
  claim can identify only that component.
- **PROFINET:** `raw.pnioRecords` retains API/slot/subslot/index selection and
  `raw.physicalEntities` retains component-scoped serial claims as evidence. Management does not
  promote those claims to device identity. Legacy device-level manufacturer/software fields come only
  from API 0, slot 0, subslot 1, index `0xAFF0`.

Other `raw` protocol data remains opaque to identity resolution. A serial-like string without the
source, manufacturer, component reference, and subject scope above can remain evidence, but it cannot
authorize an automatic physical merge.

## Operator setup

Set these values on every OTserver web process that manages or serves Otter requests:

```dotenv
OTSERVER_PUBLIC_URL=https://otserver.example
OTSERVER_OTTER_ENCRYPTION_KEY=64-hexadecimal-characters-from-openssl-rand-hex-32
```

Generate the encryption key with `openssl rand -hex 32`. Keep it separate from `OTSERVER_SECRET`,
back it up securely, and use the same value on all web replicas. Losing it makes stored SNMP and OPC
UA credentials unavailable. Changing it requires decrypting and re-encrypting those credentials and
active run snapshots before replacing the old key. Keep `OTSERVER_PUBLIC_URL` set to the externally
reachable HTTPS base URL; jobs use it to tell Otter where to upload scan results. Same-host setups
may use `OTSERVER_PUBLIC_URL=http://localhost:3000` (also `127.0.0.1` or `[::1]`), including
production-mode builds. Restart OTserver after changing `.env`. Browser management requests accept
these loopback aliases on the same scheme and port; external cross-origin requests remain rejected.

For a manager on the same host, Otter also accepts `--server-url 127.0.0.1:3000` (equivalent to
`http://127.0.0.1:3000`). With `--enroll`, paste the token from **Manage Otters** at the prompt and
press Enter. Use the same controller URL as `OTSERVER_PUBLIC_URL`; subsequent starts omit `--enroll`.

The controller endpoints are registered with Payload under `/api/otter/v1`. Apply the versioned
database migrations as part of normal production upgrades; they establish partial unique indexes for
scanner credentials and scheduled occurrence deduplication.

## Roles and site scope

Enable **Otter Config** on a user role. Admin has this capability implicitly. The capability does
not grant inventory or site permissions by itself:

- Reading scanner management data requires Otter Config and read permission for the scanner's site.
- Creating enrollment tokens, editing profiles, scheduling runs, starting a manual run, revoking, and
  re-enrolling require Otter Config and write permission for that exact site.
- Existing site permissions continue to inherit through descendants.
- Each scanner is bound to one mandatory site. Its machine credential can only create/read its own
  Otter imports for that exact site; it does not inherit descendant access.
- Moving a scanner is not an edit. Revoke/re-enroll it for the new site so historical runs/imports
  keep their original site scope.

Administrators can enable **Block imports** on a site type. Only sites directly using that type are
blocked; child sites follow their own types. The controller rejects enrollment, re-enrollment, new
configurations/schedules, manual runs, run starts, and uploads into blocked sites. Existing schedules
and queued runs wait while the site is blocked. Polling returns idle for new work, and polling or
heartbeats request cancellation for active runs using the existing cancel response. Imports queued
before a policy change fail before inventory writes with an explicit blocked-site reason; they can
be retried after imports are allowed again. History, cancellation, credential revocation, and disabling
existing schedules remain available. The controller rechecks the site's current type rather than a
policy copied into the run snapshot.

Open **Otter → Otter Scanners** and select **Create New**. The enrollment popup provides the
download link, creates a site-bound scanner, and shows its one-time token and enrollment commands.
Use **Otter → Otter Configurations** to select the scanner and site, edit network and protocol options,
configure import overrides, and queue the first scan with **Run now**. Save the configuration before
running. Schedules select a configuration bound to that same scanner and exact site. Scanner documents
manage enrollment and inventory only. Legacy scanner network overrides are no longer applied; copy
them into the appropriate configuration before running it. The old `/admin/otters` URL redirects to
the scanner list. The API collection slug remains `otter-profiles`.

Otter binds its private state directory to the enrolled controller URL. To reuse that directory for
a different controller, generate a fresh enrollment token and start with `--enroll --overwrite-state-dir`.
The scanner replaces the saved enrollment and run state only after successful enrollment, retaining
existing local scan exports. Subsequent starts omit both flags.
Enrollment and polling report the computer name and network adapter inventory (technical and friendly
names, MAC, and IP addresses). OTserver stores this with the scanner and refreshes it while the
controller is running. The **Otter** Payload collections expose scanner details and the native profile
editor, including selectable adapters, all scan options, encrypted credentials, schedules, and run
history. Reports are bounded to 32 adapters and 16 IP addresses per adapter. Enrollment credentials
are single-use and only shown in the response that creates or re-enrolls a scanner. Copy the token at
that time.

## Enrollment and credentials

1. A permitted operator creates a named scanner at a writable site using **Otter Scanners → Create New**.
2. OTserver creates a 256-bit random enrollment token. Only its SHA-256 digest is stored; it expires
   after 15 minutes.
3. On the Otter host, run the enrollment command shown by the management page and paste the token
   when prompted. Otter redeems it once with `POST /api/otter/v1/enroll` over HTTPS.
4. OTserver consumes the token transactionally and returns a distinct 256-bit scanner credential,
   valid for one year. Only the credential digest is stored.
5. Otter authenticates with `Authorization: Otter <scanner-credential>`.

The machine strategy is accepted only on `/api/otter/v1/*` and `/api/asset-imports*`. It does not
authenticate the scanner to general Payload REST, GraphQL, or the admin UI. Each request checks that
the credential remains enabled and unexpired. Revoke takes effect immediately. Re-enrollment revokes
the old credential and issues a new single-use token; it also terminates an active assignment.

The scanner can rotate its credential with `POST /api/otter/v1/credentials/rotate`. The returned
credential is only shown once, and the previous one stops working immediately. It must be saved
durably by Otter before the old token is discarded. Operators can always recover a lost local
credential by re-enrolling the scanner.

Use a reverse proxy/WAF to rate-limit `/api/otter/v1/enroll`, cap request sizes, and require HTTPS.
Enrollment tokens have 256 bits of entropy and short expiry, but rate-limiting still protects the
public endpoint from avoidable traffic. Do not log `Authorization` headers, enrollment tokens,
credential responses, configuration responses, or request bodies containing credentials.

## Profiles and secrets

Profiles are named, site/scanner-bound scan settings. The Payload profile editor exposes these
non-secret `ScannerConfig` options as native fields:

```json
{
  "targets": ["192.168.1.0/24"],
  "interface": "eth0",
  "sourceMac": "00:11:22:33:44:55",
  "noProtocols": false,
  "allowDcpSource": false,
  "noArp": false,
  "noProfinet": false,
  "noS7": false,
  "noEnip": false,
  "noBacnet": false,
  "noFins": false,
  "noFox": false,
  "noDnp3": false,
  "noIec61850": false,
  "noNetbios": false,
  "noSmb": false,
  "noRpc": false,
  "noOpcua": false,
  "opcuaPorts": [4840, 4841, 48400],
  "noSnmp": false,
  "noLldp": false
}
```

`targets` must be IPv4 addresses or CIDRs; unknown options, non-IPv4 targets, excessive target
lists, and invalid ports are rejected. `noProtocols` disables native IP protocols (including SMB
and RPC), but does not disable ARP, PROFINET, SNMP, or LLDP; those have separate switches. The
interface selector displays each reported adapter's friendly name, MAC, and addresses and stores its
technical name. `sourceMac` is optional; Otter refreshes the selected adapter's actual MAC at scan
start. The controller supplies the scanner's fixed site, OTserver URL, profile name, and upload
destination. Profiles cannot specify `site`, `serverUrl`, `apiKey`, or an arbitrary local output path.
The selected interface controls Layer-2 capture and ARP/DCP source selection. TCP/UDP, SNMP, and other
native IP probes use the operating system's route table; operators of multi-homed scanners must set
routes for the target networks in the operating system.

Enter SNMP/OPC UA secrets through the profile's **SNMP and OPC UA credentials** controls. They are
validated and encrypted at rest with AES-256-GCM using `OTSERVER_OTTER_ENCRYPTION_KEY`. The regular
profile API, edit form, and reads never return credential values or ciphertext. The GUI exposes SNMP
version/community/user/context/authentication/privacy settings, OPC UA credential entries, and the
single-credential fallback. An operator can replace or clear the credential set; the form does not
preload it. Audit entries redact both credential settings and key/token-shaped field names.

Configurations also expose **Apply to imported assets** and **Custom field overrides**, using the same
fields and validation as manual imports. These are human-quality values in the shared import merger.
When a run is queued, OTserver snapshots the validated profile, encrypted credentials, and import overrides. Later
profile changes affect future runs only. The assigned scanner receives the snapshot over its
authenticated HTTPS polling connection. Store neither the returned credentials nor scan results in
logs.

## Schedules and run lifecycle

Schedules are owned by the management server. Supported types are:

- **Run once** at a selected timestamp.
- **Interval** from 5 minutes through 7 days.
- **Calendar schedule** with a five-field cron expression and IANA time zone, for example
  `0 2 * * 1-5` in `Europe/Berlin`.

Timestamps are stored in UTC. Croner handles time-zone rules and DST; nonexistent local times are
skipped and repeated times run once. When an Otter is offline, each due schedule creates at most its
latest missed occurrence. Older missed occurrences are coalesced rather than sent in a burst.

Every run has an immutable configuration snapshot and progresses through `queued`, `assigned`,
`running`, and a terminal state (`completed`, `partial`, `failed`, `cancelled`, or `expired`). Only
one assigned/running run is active per scanner. Polling returns the existing assignment again until
it is finished, which lets a scanner recover a lost poll response. Assigned and running jobs use a
two-minute lease. If the lease expires, OTserver records `expired`; it does not silently repeat an
uncertain scan. Human cancellation is immediate while queued and becomes `cancel-requested` after
assignment; Otter observes it on its next poll/heartbeat.

The dispatcher calculates due schedules during polling. It does not run scans on OTserver and does
not need a separate scheduled worker process. MongoDB transactions plus partial unique indexes
prevent duplicate schedule occurrences and ensure concurrent polls do not create duplicate runs.

## Controller API v1

All request/response JSON is UTF-8. Responses carrying tokens or credentials use
`Cache-Control: no-store`. Scanner calls require the `Otter` authorization scheme; browser
management mutations require the logged-in user, same-origin `Origin`, Otter Config, and site write
access.

### Enroll

```http
POST /api/otter/v1/enroll
Content-Type: application/json

{
  "token":"<single-use-enrollment-token>",
  "version":"0.9.0",
  "capabilities":["scan-v2","controller-v1"],
  "interfaces":["eth0"],
  "computerName":"otter-host",
  "networkAdapters":[{
    "name":"eth0",
    "friendlyName":"Ethernet",
    "description":"Ethernet adapter",
    "macAddress":"00:11:22:33:44:55",
    "ipAddresses":["192.168.1.20"]
  }]
}
```

Success returns `{ "credential": "...", "credentialExpiresAt": "...", "scanner": { "id":
"...", "name": "...", "site": "..." } }`. Invalid, expired, or consumed tokens return an
authentication error.

### Poll

```http
POST /api/otter/v1/poll
Authorization: Otter <scanner-credential>
Content-Type: application/json

{
  "version":"0.9.0",
  "capabilities":["scan-v2","controller-v1"],
  "interfaces":["eth0"],
  "computerName":"otter-host",
  "networkAdapters":[{
    "name":"eth0",
    "friendlyName":"Ethernet",
    "description":"Ethernet adapter",
    "macAddress":"00:11:22:33:44:55",
    "ipAddresses":["192.168.1.20"]
  }]
}
```

Idle scanners receive `{ "action": "idle", "retryAfterSeconds": 30 }`. A job response has this
shape:

```json
{
  "action": "run",
  "run": {
    "id": "RUN_ID",
    "configuration": {
      "name": "Line A",
      "targets": ["192.168.1.0/24"],
      "serverUrl": "https://otserver.example",
      "site": "SITE_ID"
    },
    "credentials": { "snmp": [{ "version": "3", "username": "inventory" }] },
    "uploadPath": "/api/asset-imports",
    "leaseExpiresAt": "2026-10-10T12:02:00.000Z"
  }
}
```

The credential header is used for the import upload too. OTserver injects the site and
`otserver-otter` source on scanner uploads; supplied conflicting sites and non-Otter sources are
rejected. A cancellation response is `{ "action": "cancel", "runID": "RUN_ID" }`.

### Run actions

```text
POST /api/otter/v1/runs/:id/start
POST /api/otter/v1/runs/:id/heartbeat     {"progress": 50}
POST /api/otter/v1/runs/:id/finish        {"status":"completed","importID":"..."}
```

Heartbeats extend the lease. A heartbeat returns `cancelRequested`; the scanner should stop safely
and finish with `cancelled` when cancellation is acknowledged. Finish accepts `completed`, `partial`,
`failed`, or `cancelled`, an optional bounded diagnostic message, and an optional import ID. An import
ID must be an upload by this scanner associated with this active run. Scan completion and import
processing are separate outcomes: a queued import can still be pending when the scan run finishes.

Failed runs include a credential-safe `message` explaining setup/discovery failures or an interrupted
scan. Otter persists this reason before finishing so retries and restarts retain it. Arbitrary protocol
errors and credential values are not included. The native **Otter Runs** list and document show the
message. Lease expiry records a missed-heartbeat reason; older clients that omit failure details get
an explicit missing-diagnostics message.

The import API remains Payload's existing multipart endpoint. The scanner sends `_payload` metadata
with its run association and the scan JSON as `file`, plus
`Authorization: Otter <scanner-credential>`. Example metadata:

```json
{
  "source": "otserver-otter",
  "sourceVersion": "0.9.0",
  "otterRun": "RUN_ID",
  "executionMode": "queued"
}
```

The manager pins `site` and `source`, discards scanner-supplied human overrides, applies the run's
server-owned import override snapshot, and names imports `Otter — scanner name — site — UTC datetime`.
It preserves normal
parser validation, identity reconciliation, quality merging, auditing, upload limits, and the
2,000-record transaction cap. Exact retries use the existing import digest/idempotency logic. Queued
scanner uploads require `OTSERVER_QUEUED_IMPORTS=on`; workers reload the scanner and fail closed if
it was disabled, revoked, or expired before processing.

### Management actions

```text
GET  /api/otter/v1/overview
POST /api/otter/v1/scanners
POST /api/otter/v1/scanners/:id/reenroll
POST /api/otter/v1/scanners/:id/revoke
POST /api/otter/v1/profiles/:id/credentials
POST /api/otter/v1/runs                     {"scannerID":"...","profileID":"..."}
POST /api/otter/v1/runs/:id/cancel
```

Create scanner accepts `{ "name": "Line A Otter", "site": "SITE_ID" }` and responds with a
single-use `enrollmentToken` and expiry. Credential management accepts
`{ "credentials": { "snmp": [...], "opcuaCredentials": [...] } }`; `{ "clear": true }` clears
stored credentials. Re-enrollment revokes the current scanner credential and terminates its active
assignment before returning a new token.

## Client implementation checklist in `otserver-otter`

These requirements are implemented in the separate `otserver-otter` repository. The client uses
`controller --server-url URL --enroll --ack-authorized` with the token on stdin, then restarts without
`--enroll`. Imports default to synchronous execution; `--queued-imports` opts into the example queued
metadata below. This does not change OTserver's TypeScript scanner parser or schema-version-2 result
contract. The Rust tests, HTTPS lab, and management `pnpm test:otter-client` (real Rust client, REST API,
and test replica set) cover:

1. Add a `controller`/managed-agent mode that accepts the OTserver URL and one-time enrollment token
   without requiring a scanner-side inbound listener.
2. Redeem the enrollment token over HTTPS, then persist the returned credential in an
   OS-appropriate secret store where available; support a permission-restricted file fallback.
3. Poll `/api/otter/v1/poll` on a configurable interval with bounded exponential backoff and jitter.
   Send version, supported capabilities, locally available capture interfaces, computer name, and
   adapter technical/friendly names, description, optional MAC, and IP addresses.
4. Decode the supported server configuration fields and credential snapshot. Apply profile options
   without weakening the existing `--ack-authorized`, read-only protocol behavior, interface/source
   MAC checks, response validation, or process-wide traffic pacing.
5. Persist run IDs and assignment state across restarts. Repeated poll responses for the same run must
   resume/reconcile that run rather than launching a duplicate scan.
6. Send start, bounded progress/lease heartbeats, and finish status. Stop promptly on a cancellation
   request or lost lease. A scanner must not continue uploading stale work after a terminal response.
7. Upload the existing schema-v2 JSON to `/api/asset-imports` with
   `Authorization: Otter <credential>`, `site` omitted or matching the bound site,
   `source: otserver-otter`, and the run ID in `otterRun`. Keep the local result file on upload
   failure.
8. Retry imports using the returned import ID/status where appropriate, and report scanner completion
   separately from import completion/failure.
9. Rotate credentials before expiry, atomically persist the returned credential before replacing the
   old one, and stop/re-enroll on revocation or authentication failure.
10. Add Rust tests for enrollment responses, config mapping/validation, persisted assignment recovery,
    cancellation, upload auth/metadata, credential redaction, and retry/backoff. Add protocol
    interoperability cases to the Otter lab. Update its README/AGENTS safety rules and the
    interoperability tests in this repository in the coordinated change.

The controller protocol is versioned independently (`/otter/v1`). A future breaking change requires
a new controller protocol version; it does not by itself require changing
`otserver-scan` schema version 2.
