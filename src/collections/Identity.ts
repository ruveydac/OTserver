import { randomUUID } from 'node:crypto'
import { APIError, type CollectionConfig, type Field, type FieldAccess } from 'payload'
import {
  canCreateSiteDocument,
  canReadSiteDocuments,
  canWriteSiteDocuments,
  enforceWritableSite,
  filterWritableSites,
} from '../access/authorization'
import { enforceIdentityRelationships, idOf, requireTransaction } from '../identity/access'
import {
  hardwareKey,
  endpointBindingKey,
  identityScopes,
  normalizeIdentity,
  scopedKey,
  slotUUID,
  type HardwareIdentity,
} from '../identity/keys'
import { normalizeMAC, validateIPAddress, validateMACAddress } from './Assets'
import {
  syncEndpointProjection,
  validateInstallation,
  lockIdentityAssets,
} from '../identity/relationships'
import { trackHumanAssetChanges } from '../importers/assetQuality'

const site: Field = {
  name: 'site',
  type: 'relationship',
  relationTo: 'sites',
  required: true,
  index: true,
  filterOptions: filterWritableSites,
}
const asset: Field = {
  name: 'asset',
  type: 'relationship',
  relationTo: 'assets',
  index: true,
  maxDepth: 0,
}
const internal: { create: FieldAccess; update: FieldAccess } = {
  create: () => false,
  update: () => false,
}
const base = (slug: CollectionConfig['slug'], fields: Field[]): CollectionConfig => ({
  slug,
  fields: [site, ...fields],
  timestamps: true,
  admin: { group: 'Device identity', useAsTitle: 'id' },
  access: {
    create: canCreateSiteDocument,
    read: canReadSiteDocuments,
    update: canWriteSiteDocuments,
    delete: () => false,
  },
  hooks: {
    beforeChange: [
      enforceWritableSite,
      enforceIdentityRelationships,
      async ({ req, data }) => {
        await requireTransaction(req)
        return data
      },
    ],
  },
})

export const NetworkContexts: CollectionConfig = {
  ...base('network-contexts', [
    { name: 'name', type: 'text', required: true },
    {
      name: 'uuid',
      type: 'text',
      unique: true,
      index: true,
      defaultValue: randomUUID,
      access: internal,
      admin: { readOnly: true },
    },
    { name: 'legacyKey', type: 'text', unique: true, access: internal, admin: { hidden: true } },
    { name: 'vlan', type: 'number', min: 0, max: 4094 },
    { name: 'routingDomain', type: 'text' },
    { name: 'description', type: 'textarea' },
  ]),
  admin: {
    group: 'Device identity',
    useAsTitle: 'name',
    description:
      'A shared collector network scope. VLAN numbers and IP addresses are not global identities.',
  },
}

export const NetworkEndpoints: CollectionConfig = {
  ...base('network-endpoints', [
    asset,
    {
      name: 'networkContext',
      type: 'relationship',
      relationTo: 'network-contexts',
      required: true,
      index: true,
    },
    { name: 'bindingKey', type: 'text', unique: true, access: internal, admin: { hidden: true } },
    { name: 'interfaceKey', type: 'text' },
    { name: 'name', type: 'text' },
    {
      name: 'macAddress',
      type: 'text',
      index: true,
      validate: validateMACAddress,
      hooks: { beforeValidate: [({ value }) => (value ? normalizeMAC(value) : value)] },
    },
    {
      name: 'addresses',
      type: 'array',
      fields: [
        { name: 'address', type: 'text', required: true, index: true, validate: validateIPAddress },
        { name: 'networkMask', type: 'text', validate: validateIPAddress },
        { name: 'gatewayAddress', type: 'text', validate: validateIPAddress },
      ],
    },
    {
      name: 'firstSeen',
      type: 'date',
      required: true,
      defaultValue: () => new Date().toISOString(),
    },
    { name: 'lastSeen', type: 'date', index: true },
    { name: 'endedAt', type: 'date', index: true, admin: { readOnly: true } },
    {
      name: 'reachability',
      type: 'select',
      defaultValue: 'unknown',
      options: ['online', 'offline', 'unknown'],
    },
    { name: 'source', type: 'text', defaultValue: 'human' },
    { name: 'fieldProvenance', type: 'json', admin: { hidden: true } },
  ]),
  admin: {
    group: 'Device identity',
    defaultColumns: ['asset', 'networkContext', 'macAddress', 'lastSeen', 'endedAt'],
  },
  hooks: {
    beforeChange: [
      enforceWritableSite,
      enforceIdentityRelationships,
      ({ data, originalDoc, req }) => {
        if (!req.context.assetImport && !req.context.identityAction)
          data = trackHumanAssetChanges({ ...data, source: 'human' }, originalDoc)
        if (originalDoc?.endedAt && !req.context.identityAction)
          throw new APIError('Historical endpoints are immutable.', 400)
        if (data.endedAt && !req.context.identityAction)
          throw new APIError('Close endpoints through an identity action.', 400)
        const value = { ...originalDoc, ...data }
        data.bindingKey = value.endedAt
          ? scopedKey('historical-endpoint', originalDoc?.id || randomUUID())
          : endpointBindingKey(
              idOf(value.networkContext),
              value.macAddress,
              idOf(value.asset),
              value.interfaceKey || originalDoc?.id || randomUUID(),
            )
        if (!value.macAddress && !value.interfaceKey && !value.addresses?.length)
          throw new APIError('Supply an interface identifier, MAC address, or IP address.', 400)
        return data
      },
    ],
    afterChange: [syncEndpointProjection],
  },
  indexes: [{ fields: ['networkContext', 'macAddress'] }, { fields: ['asset', 'endedAt'] }],
}

export const ServiceBindings = base('service-bindings', [
  asset,
  {
    name: 'endpoint',
    type: 'relationship',
    relationTo: 'network-endpoints',
    required: true,
    index: true,
  },
  { name: 'bindingKey', type: 'text', unique: true, access: internal, admin: { hidden: true } },
  { name: 'address', type: 'text', validate: validateIPAddress },
  { name: 'transport', type: 'select', options: ['tcp', 'udp', 'ethernet'], required: true },
  { name: 'port', type: 'number', min: 0, max: 65535 },
  { name: 'protocol', type: 'text', required: true, index: true },
  {
    name: 'route',
    type: 'text',
    admin: { description: 'Only record a route actually observed or explicitly supplied.' },
  },
  { name: 'firstSeen', type: 'date', required: true, defaultValue: () => new Date().toISOString() },
  { name: 'lastSeen', type: 'date' },
  { name: 'endedAt', type: 'date', admin: { readOnly: true } },
  { name: 'source', type: 'text', defaultValue: 'human' },
])
ServiceBindings.hooks!.beforeChange!.push(({ data, originalDoc, req }) => {
  const value = { ...originalDoc, ...data }
  if (originalDoc?.endedAt && !req.context.identityAction)
    throw new APIError('Historical service bindings are immutable.', 400)
  if (data.endedAt && !req.context.identityAction)
    throw new APIError('Close service bindings through an identity action.', 400)
  if (value.port != null && !Number.isInteger(value.port))
    throw new APIError('Ports must be integers.', 400)
  return {
    ...data,
    bindingKey: value.endedAt
      ? scopedKey('historical-service', originalDoc?.id || randomUUID())
      : scopedKey(
          'service',
          idOf(value.endpoint),
          value.address,
          value.transport,
          value.port,
          value.protocol,
        ),
  }
})

export const AssetIdentifiers: CollectionConfig = {
  ...base('asset-identifiers', [
    { ...asset, required: true },
    { name: 'key', type: 'text', unique: true, access: internal, admin: { readOnly: true } },
    {
      name: 'authority',
      type: 'text',
      required: true,
      admin: {
        description:
          'Serial issuer namespace, e.g. cip, siemens, or a verified manufacturer namespace.',
      },
    },
    { name: 'manufacturer', type: 'text', required: true },
    { name: 'scope', type: 'select', options: [...identityScopes], required: true },
    { name: 'serial', type: 'text', required: true },
    { name: 'productScope', type: 'text' },
    {
      name: 'state',
      type: 'select',
      options: ['accepted', 'contested', 'revoked'],
      defaultValue: 'accepted',
      required: true,
    },
    { name: 'source', type: 'text', defaultValue: 'human' },
    { name: 'evidence', type: 'json', admin: { readOnly: true } },
  ]),
  hooks: {
    beforeChange: [
      enforceWritableSite,
      enforceIdentityRelationships,
      async ({ data, originalDoc, req }) => {
        try {
          const identity = normalizeIdentity({ ...originalDoc, ...data } as HardwareIdentity)
          const key = hardwareKey(identity)
          if (originalDoc?.id && key !== originalDoc.key)
            throw new Error(
              'Revoke the previous key and add a new identifier to correct hardware identity.',
            )
          const assetID = idOf(data.asset ?? originalDoc?.asset)
          await lockIdentityAssets([assetID], req)
          if ((data.state ?? originalDoc?.state ?? 'accepted') === 'accepted') {
            const conflicts = await req.payload.find({
              collection: 'asset-identifiers',
              depth: 0,
              limit: 1,
              overrideAccess: false,
              req,
              where: {
                and: [
                  { asset: { equals: assetID } },
                  { state: { equals: 'accepted' } },
                  { authority: { equals: identity.authority } },
                  { manufacturer: { equals: identity.manufacturer } },
                  { scope: { equals: identity.scope } },
                  { serial: { not_equals: identity.serial } },
                ],
              },
            })
            if (conflicts.docs.length)
              throw new Error('Conflicting accepted hardware serials require identity review.')
          }
          return { ...data, ...identity, key }
        } catch (error) {
          throw new APIError((error as Error).message, 400)
        }
      },
    ],
  },
}

export const AssetInstallations: CollectionConfig = {
  ...base('asset-installations', [
    { name: 'parent', type: 'relationship', relationTo: 'assets', required: true, index: true },
    { name: 'module', type: 'relationship', relationTo: 'assets', required: true, index: true },
    {
      name: 'slotPath',
      type: 'text',
      admin: {
        description: 'Leave empty when containment is known but slot position is not reported.',
      },
    },
    { name: 'slotUUID', type: 'text', access: internal, admin: { readOnly: true } },
    { name: 'activeSlot', type: 'text', unique: true, access: internal, admin: { hidden: true } },
    { name: 'activeModule', type: 'text', unique: true, access: internal, admin: { hidden: true } },
    {
      name: 'installedAt',
      type: 'date',
      required: true,
      defaultValue: () => new Date().toISOString(),
    },
    { name: 'removedAt', type: 'date' },
    { name: 'source', type: 'text', defaultValue: 'human' },
  ]),
  hooks: {
    beforeChange: [
      enforceWritableSite,
      enforceIdentityRelationships,
      validateInstallation,
      async ({ data, originalDoc, req }) => {
        const value = { ...originalDoc, ...data }
        const parent = await req.payload.findByID({
          collection: 'assets',
          id: idOf(value.parent),
          overrideAccess: false,
          req,
        })
        const uuid = value.slotPath ? slotUUID(parent.uuid!, value.slotPath) : null
        return {
          ...data,
          slotUUID: uuid,
          activeSlot: value.removedAt
            ? `removed:${originalDoc?.id}`
            : uuid || `unknown:${idOf(value.module)}`,
          activeModule: value.removedAt ? `removed:${originalDoc?.id}` : idOf(value.module),
        }
      },
    ],
  },
}

export const IdentityCases = base('identity-cases', [
  asset,
  { name: 'candidate', type: 'relationship', relationTo: 'assets', index: true },
  { name: 'caseKey', type: 'text', unique: true, access: internal, admin: { hidden: true } },
  {
    name: 'kind',
    type: 'select',
    required: true,
    options: ['identity-conflict', 'possible-duplicate', 'replacement', 'cross-site'],
  },
  {
    name: 'confidence',
    type: 'number',
    min: 0,
    max: 3,
    defaultValue: 0,
    admin: {
      description:
        'Ordinal rule score, not a probability: 3 hardware, 2 endpoint, 1 heuristic, 0 unresolved.',
    },
  },
  { name: 'reason', type: 'textarea', required: true },
  { name: 'evidence', type: 'json', admin: { readOnly: true } },
  {
    name: 'status',
    type: 'select',
    defaultValue: 'open',
    options: ['open', 'resolved', 'rejected'],
    required: true,
  },
  { name: 'resolution', type: 'textarea' },
])
