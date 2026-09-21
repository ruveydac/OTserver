# Future OTserver Otter identity work

This manager release consumes the pinned `otserver-scan` v2 contract. The Otter source,
canonical schema, and submodule revision are maintained separately. The following changes
require a coordinated Otter release, importer updates, shared fixtures, and a submodule update.

## 1. Publish a component-aware v3 contract

- Separate physical components, interfaces/endpoints, physical ports, and protocol listeners.
- Give every observation a stable scan-local ID and an explicit subject reference.
- Describe serial scope: device, chassis, CPU, adapter, or module. Include the serial issuer,
  manufacturer identifier, original serial encoding, catalog number, and normalization version.
- Export component containment and slot/subslot positions separately from module identity.
- Preserve a service's listening address, transport, port, and full industrial routing path.
  Distinguish the listener/adapter from the target CPU or module reached through it.
- Include stable collector identifiers as observation provenance. Endpoint identity remains scoped
  by the exact site selected in the manager.
- Include per-target and per-protocol outcomes, attempted coverage, cancellation, and incomplete
  inventories. Distinguish an empty slot from inaccessible, unsupported, and failed queries.
- Preserve unresolved observations without inventing physical IDs or assigning next-hop MACs.

## 2. Preserve SNMP physical inventory

`src/snmp.rs` already reads ENTITY-MIB containment, class, serial, hardware, firmware, and
manufacturer data, but flattens the structured result into a preferred entity. Export the entire
tree. Add `entPhysicalParentRelPos` and supported interface-to-physical-entity mappings.
`entPhysicalIndex` and `ifIndex` are observation references, not permanent hardware identities.

The manager can recover qualified chassis/module claims from existing v2 raw OIDs. It leaves
slot position unknown when v2 did not collect it and does not infer a module's physical NIC
ownership from a common query address.

## 3. Discover routed targets without a MAC

`src/main.rs::probe_protocols` currently starts from MAC-correlated IP identities. Probe explicitly
selected routed targets independently and export successful identity responses even without a
target MAC. The gateway's ARP address must never become the remote controller's identity.

## 4. Qualified CIP backplane traversal

Extend EtherNet/IP List Identity with bounded, read-only routed Identity Object requests for
qualified chassis families. Keep adapter, CPU, and chassis serials distinct. Record every routing
hop. Derive slot bounds from known models or supported inventory responses rather than assuming
that every chassis has slots 0–16. Export partial results on unsupported or inaccessible slots.

## 5. Model-specific S7 inventory

The pinned implementation reads SZL `0x0011` and `0x001C`. Validate additional SZL IDs/indexes
against exact CPU families and firmware before adding CP/I/O enumeration. `0x0011`/`0x0111`
are not a universal backplane enumeration mechanism. Publish a tested support matrix and
preserve partial identification when auxiliary module queries fail.

## 6. Distributed canonicalization and lifecycle evidence

Share the manager's `ot-hardware-v1` namespace and canonical JSON-array UTF-8 UUIDv5 test vectors.
Do not hash display model names or include the current slot in a module's hardware key.
Workers may publish provisional IDs; the manager returns accepted reconciliation mappings when
that capability is added to the coordinated wire contract. Deterministic UUIDs are names, not
authentication of a device response.

Preserve observation time and collector clock information. Add sufficient negative evidence for
the manager to evaluate missed endpoints and services without treating partial scans, blocked
protocols, or old offline uploads as proof of hardware disappearance.

## Required checks

Keep the existing acknowledgement, read-only protocol boundaries, process-wide pacing,
cancellation, and response validation. Add focused Rust parser/identity tests, shared TypeScript
contract fixtures, and protocol interoperability cases in Otter's lab. Run the Otter repository's
required checks. Active vulnerability checks are outside this work.
