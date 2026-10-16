import {
  APIError,
  type Access,
  type CollectionBeforeChangeHook,
  type CollectionBeforeDeleteHook,
  type CollectionConfig,
} from 'payload'
import { filterWritableSites, getAuthorization, relationshipID } from '../access/authorization'
import {
  encryptOtterCredentials,
  requireOtterConfigAccess,
  validateOtterConfiguration,
} from '../otter/security'
import { validateScheduleInput } from '../otter/scheduling'
import { userSuppliedAssetFields } from '../domain/assetFields'
import { sanitizeCustomFieldValues } from './AssetFields'

const canReadOtter: Access = async ({ req }) => {
  if (req.context.otterScannerID) return false
  const authorization = await getAuthorization(req)
  if (!authorization.canConfigureOtter) return false
  return authorization.isAdmin ? true : { site: { in: authorization.readableSiteIDs } }
}

const canWriteOtter: Access = async ({ req }) => {
  if (req.context.otterScannerID) return false
  const authorization = await getAuthorization(req)
  if (!authorization.canConfigureOtter) return false
  return authorization.isAdmin ? true : { site: { in: authorization.writableSiteIDs } }
}

const canCreateOtter: Access = async ({ data, req }) => {
  if (req.context.otterScannerID) return false
  const authorization = await getAuthorization(req)
  if (!authorization.canConfigureOtter) return false
  if (authorization.isAdmin) return true
  if (!data) return authorization.writableSiteIDs.length > 0
  const siteID = relationshipID(data.site)
  return Boolean(siteID && authorization.writableSiteIDs.includes(String(siteID)))
}

const internal = { create: () => false, read: () => false, update: () => false }
const serverReadOnly = { create: () => false, update: () => false }

const validateScannerSettings: CollectionBeforeChangeHook = async ({ data, req }) => {
  if (!req.user || req.context.otterScannerUpdate) return data
  if (Object.hasOwn(data, 'profile') || Object.hasOwn(data, 'network'))
    throw new APIError('Scan settings must be changed in Otter configurations.', 400)
  return data
}

const scheduleProfile = async (
  data: Record<string, unknown>,
  req: Parameters<CollectionBeforeChangeHook>[0]['req'],
) => {
  const profileID = relationshipID(data.profile)
  if (!profileID) throw new APIError('Select an Otter configuration.', 400)
  const profile = await req.payload.findByID({
    collection: 'otter-profiles',
    depth: 0,
    id: String(profileID),
    overrideAccess: false,
    req,
  })
  const siteID = relationshipID(profile.site)
  const scannerID = relationshipID(profile.scanner)
  if (!siteID || !scannerID)
    throw new APIError('The configuration must have a scanner and site.', 400)
  await requireOtterConfigAccess(req, siteID, true)
  const scanner = await req.payload.findByID({
    collection: 'otter-scanners',
    depth: 0,
    id: String(scannerID),
    overrideAccess: true,
    req,
  })
  if (String(relationshipID(scanner.site)) !== String(siteID))
    throw new APIError('Scanner and configuration must belong to the same site.', 400)
  return { site: siteID, scanner: scannerID }
}

const canCreateSchedule: Access = async ({ data, req }) => {
  // Payload evaluates create access without submitted form data when rendering
  // the create view. Defer profile-specific checks until the form is submitted.
  if (!relationshipID(data?.profile)) return canCreateOtter({ req })
  const scope = await scheduleProfile(data, req)
  return canCreateOtter({ data: { ...data, ...scope }, req })
}

const validateProfile: CollectionBeforeChangeHook = async ({
  data,
  operation,
  originalDoc,
  req,
}) => {
  if (req.context.otterSchedulerUpdate || req.context.otterCredentialWrite) return data
  const siteID = relationshipID(Object.hasOwn(data, 'site') ? data.site : originalDoc?.site)
  const scannerID = relationshipID(
    Object.hasOwn(data, 'scanner') ? data.scanner : originalDoc?.scanner,
  )
  if (!siteID || !scannerID) throw new APIError('Select a site and scanner.', 400)
  await requireOtterConfigAccess(req, siteID, true)
  const scanner = await req.payload.findByID({
    collection: 'otter-scanners',
    depth: 0,
    id: String(scannerID),
    overrideAccess: true,
    req,
  })
  if (String(relationshipID(scanner.site)) !== String(siteID))
    throw new APIError('The scanner must be bound to the selected site.', 400)

  const configuration = Object.hasOwn(data, 'configuration')
    ? data.configuration
    : originalDoc?.configuration
  const normalizedConfiguration =
    configuration && typeof configuration === 'object' && !Array.isArray(configuration)
      ? { ...configuration }
      : configuration
  if (normalizedConfiguration && typeof normalizedConfiguration === 'object')
    for (const key of ['interface', 'sourceMac'])
      if (
        normalizedConfiguration[key] === null ||
        normalizedConfiguration[key] === undefined ||
        normalizedConfiguration[key] === ''
      )
        delete normalizedConfiguration[key]
  data.configuration = validateOtterConfiguration(normalizedConfiguration)
  // After the initial default, credentials change only through the write-only endpoint.
  const previous =
    operation === 'update' && originalDoc?.id
      ? await req.payload.findByID({
          collection: 'otter-profiles',
          depth: 0,
          id: originalDoc.id,
          overrideAccess: true,
          req,
        })
      : undefined
  data.encryptedCredentials =
    operation === 'create'
      ? encryptOtterCredentials({ snmp: [{ version: '2c', community: 'public' }] })
      : previous?.encryptedCredentials || undefined
  data.credentialsConfigured = Boolean(data.encryptedCredentials)
  return data
}

const validateSchedule: CollectionBeforeChangeHook = async ({
  data,
  operation,
  originalDoc,
  req,
}) => {
  if (req.context.otterSchedulerUpdate) return data
  const merged = { ...originalDoc, ...data } as Record<string, unknown>
  const scope = await scheduleProfile(merged, req)
  Object.assign(data, scope)
  Object.assign(merged, scope)
  if (operation === 'create') {
    const schedules = await req.payload.count({
      collection: 'otter-schedules',
      overrideAccess: true,
      req,
      where: { scanner: { equals: relationshipID(merged.scanner) } },
    })
    if (schedules.totalDocs >= 50)
      throw new APIError('A scanner can have at most 50 schedules.', 400)
  }
  if (!merged.enabled) {
    data.nextRunAt = null
    return data
  }
  data.nextRunAt = validateScheduleInput({
    cron: typeof merged.cron === 'string' ? merged.cron : undefined,
    intervalMinutes:
      typeof merged.intervalMinutes === 'number' ? merged.intervalMinutes : undefined,
    runAt: typeof merged.runAt === 'string' ? merged.runAt : undefined,
    scheduleType: merged.scheduleType as 'once' | 'interval' | 'cron',
    timezone: typeof merged.timezone === 'string' ? merged.timezone : 'UTC',
  })
  data.lastRunAt = operation === 'create' ? null : originalDoc?.lastRunAt
  return data
}

const preventDeletingReferencedOtterConfig: CollectionBeforeDeleteHook = async ({
  id,
  collection,
  req,
}) => {
  const references = []
  if (collection.slug === 'otter-profiles') {
    references.push(
      await req.payload.count({
        collection: 'otter-schedules',
        overrideAccess: true,
        req,
        where: { profile: { equals: id } },
      }),
      await req.payload.count({
        collection: 'otter-runs',
        overrideAccess: true,
        req,
        where: { profile: { equals: id } },
      }),
    )
  } else {
    references.push(
      await req.payload.count({
        collection: 'otter-runs',
        overrideAccess: true,
        req,
        where: { schedule: { equals: id } },
      }),
    )
  }
  if (references.some((reference) => reference.totalDocs > 0))
    throw new APIError('Configuration referenced by scan history cannot be deleted.', 409)
}

export const OtterScanners: CollectionConfig = {
  slug: 'otter-scanners',
  labels: { singular: 'Otter scanner', plural: 'Otter scanners' },
  access: {
    create: () => false,
    delete: () => false,
    read: canReadOtter,
    update: canWriteOtter,
  },
  admin: {
    components: { beforeList: ['@/components/OtterEnrollment'] },
    defaultColumns: ['name', 'site', 'computerName', 'enabled', 'version', 'lastSeenAt'],
    description: 'Enrolled Otter scanner agents and their bound sites.',
    group: 'Otter',
    useAsTitle: 'name',
  },
  defaultSort: 'name',
  disableBulkDelete: true,
  disableBulkEdit: true,
  fields: [
    { name: 'name', type: 'text', required: true, maxLength: 120 },
    {
      name: 'site',
      type: 'relationship',
      filterOptions: filterWritableSites,
      index: true,
      maxDepth: 0,
      relationTo: 'sites',
      required: true,
      access: { create: () => false, update: () => false },
    },
    {
      name: 'scannerActions',
      type: 'ui',
      admin: { components: { Field: '@/components/OtterScannerActions' } },
    },
    {
      name: 'enabled',
      type: 'checkbox',
      defaultValue: true,
      access: serverReadOnly,
      admin: { readOnly: true },
    },
    { name: 'enrolledAt', type: 'date', access: serverReadOnly, admin: { readOnly: true } },
    { name: 'lastSeenAt', type: 'date', access: serverReadOnly, admin: { readOnly: true } },
    { name: 'version', type: 'text', access: serverReadOnly, admin: { readOnly: true } },
    { name: 'capabilities', type: 'json', access: serverReadOnly, admin: { readOnly: true } },
    { name: 'interfaces', type: 'json', access: serverReadOnly, admin: { readOnly: true } },
    { name: 'computerName', type: 'text', access: serverReadOnly, admin: { readOnly: true } },
    {
      name: 'inventoryReportedAt',
      type: 'date',
      access: serverReadOnly,
      admin: { readOnly: true },
    },
    {
      name: 'networkAdapters',
      type: 'array',
      access: serverReadOnly,
      admin: { readOnly: true },
      maxRows: 32,
      fields: [
        { name: 'name', type: 'text', required: true },
        { name: 'friendlyName', type: 'text', required: true },
        { name: 'description', type: 'text', required: true },
        { name: 'macAddress', type: 'text' },
        { name: 'ipAddresses', type: 'text', hasMany: true, maxRows: 16 },
      ],
    },
    {
      name: 'currentRun',
      type: 'relationship',
      relationTo: 'otter-runs',
      access: serverReadOnly,
      admin: { readOnly: true },
    },
    { name: 'enrollmentTokenHash', type: 'text', access: internal, admin: { hidden: true } },
    { name: 'enrollmentExpiresAt', type: 'date', access: internal, admin: { hidden: true } },
    { name: 'credentialHash', type: 'text', access: internal, admin: { hidden: true } },
    { name: 'credentialExpiresAt', type: 'date', access: internal, admin: { hidden: true } },
  ],
  indexes: [{ fields: ['site', 'enabled'] }],
  hooks: { beforeChange: [validateScannerSettings] },
  lockDocuments: false,
}

export const OtterProfiles: CollectionConfig = {
  slug: 'otter-profiles',
  labels: { singular: 'Otter configuration', plural: 'Otter configurations' },
  access: {
    create: canCreateOtter,
    delete: canWriteOtter,
    read: canReadOtter,
    update: canWriteOtter,
  },
  admin: {
    defaultColumns: ['name', 'scanner', 'site', 'credentialsConfigured', 'updatedAt'],
    description:
      'Central Otter settings. SNMP and OPC UA credentials are encrypted and write-only.',
    group: 'Otter',
    useAsTitle: 'name',
  },
  defaultSort: 'name',
  disableBulkDelete: true,
  disableBulkEdit: true,
  fields: [
    { name: 'name', type: 'text', required: true },
    {
      name: 'site',
      type: 'relationship',
      filterOptions: filterWritableSites,
      index: true,
      maxDepth: 0,
      relationTo: 'sites',
      required: true,
    },
    {
      name: 'scanner',
      type: 'relationship',
      filterOptions: async ({ req }) => {
        const auth = await getAuthorization(req)
        return auth.isAdmin ? true : { site: { in: auth.writableSiteIDs } }
      },
      index: true,
      maxDepth: 0,
      relationTo: 'otter-scanners',
      required: true,
    },
    {
      name: 'configuration',
      type: 'group',
      admin: {
        description:
          'Managed scan options. Site, controller URL, output path, and API credentials are managed by OTserver.',
      },
      fields: [
        {
          name: 'targets',
          type: 'text',
          hasMany: true,
          maxRows: 1024,
          minRows: 1,
          required: true,
          admin: {
            description: 'IPv4 addresses or CIDR ranges; maximum 65,536 addresses per scan.',
          },
        },
        {
          name: 'interface',
          type: 'text',
          admin: {
            components: { Field: '@/components/OtterInterfaceField' },
            description:
              'Select a reported adapter or enter its technical name. The scanner requires an explicit choice when multiple adapters are available.',
          },
        },
        {
          name: 'sourceMac',
          label: 'Source MAC address',
          type: 'text',
          admin: {
            description:
              'Optional expected sender MAC. Otter refreshes and uses the selected adapter’s actual MAC at scan start.',
          },
        },
        {
          type: 'collapsible',
          label: 'Discovery and protocols',
          admin: { initCollapsed: true },
          fields: [
            {
              name: 'noProtocols',
              type: 'checkbox',
              defaultValue: false,
              label: 'Disable native IP protocols',
              admin: {
                description:
                  'Disables S7, EtherNet/IP, BACnet, FINS, Fox, DNP3, IEC 61850, NetBIOS, SMB, RPC, and OPC UA. ARP, PROFINET, SNMP, and LLDP are controlled separately.',
              },
            },
            {
              name: 'noArp',
              type: 'checkbox',
              defaultValue: false,
              label: 'Disable ARP discovery',
            },
            {
              name: 'noProfinet',
              type: 'checkbox',
              defaultValue: false,
              label: 'Disable PROFINET discovery',
            },
            {
              name: 'allowDcpSource',
              type: 'checkbox',
              defaultValue: false,
              label: 'Use PROFINET DCP-reported addresses as scan sources',
            },
            { name: 'noS7', type: 'checkbox', defaultValue: false, label: 'Disable Siemens S7' },
            { name: 'noEnip', type: 'checkbox', defaultValue: false, label: 'Disable EtherNet/IP' },
            { name: 'noBacnet', type: 'checkbox', defaultValue: false, label: 'Disable BACnet' },
            { name: 'noFins', type: 'checkbox', defaultValue: false, label: 'Disable Omron FINS' },
            { name: 'noFox', type: 'checkbox', defaultValue: false, label: 'Disable Niagara Fox' },
            { name: 'noDnp3', type: 'checkbox', defaultValue: false, label: 'Disable DNP3' },
            {
              name: 'noIec61850',
              type: 'checkbox',
              defaultValue: false,
              label: 'Disable IEC 61850',
            },
            { name: 'noNetbios', type: 'checkbox', defaultValue: false, label: 'Disable NetBIOS' },
            {
              name: 'noSmb',
              type: 'checkbox',
              defaultValue: false,
              label: 'Disable SMB fingerprinting',
            },
            {
              name: 'noRpc',
              type: 'checkbox',
              defaultValue: false,
              label: 'Disable RPC fingerprinting',
            },
            { name: 'noOpcua', type: 'checkbox', defaultValue: false, label: 'Disable OPC UA' },
            { name: 'noSnmp', type: 'checkbox', defaultValue: false, label: 'Disable SNMP' },
            { name: 'noLldp', type: 'checkbox', defaultValue: false, label: 'Disable LLDP' },
            {
              name: 'opcuaPorts',
              label: 'OPC UA ports',
              type: 'number',
              hasMany: true,
              defaultValue: [],
              maxRows: 64,
              min: 1,
              max: 65535,
              admin: {
                description:
                  'OPC UA ports to probe. Leave empty to use Otter defaults: 4840, 4841, and 48400.',
              },
            },
          ],
        },
      ],
      required: true,
    },
    {
      name: 'managedSettings',
      type: 'ui',
      label: 'Managed settings',
      admin: { components: { Field: '@/components/OtterManagedSettingsField' } },
    },
    {
      name: 'assetOverrides',
      type: 'group',
      label: 'Apply to imported assets',
      admin: {
        description:
          'Optional human-quality overrides, applied to every imported asset. Saved with each run.',
      },
      fields: userSuppliedAssetFields.map(({ label, name, placeholder }) => ({
        name,
        label,
        type: 'text' as const,
        admin: { placeholder },
      })),
    },
    {
      name: 'customFieldOverrides',
      type: 'json',
      label: 'Custom field overrides',
      admin: { components: { Field: '@/components/CustomAssetFields' } },
    },
    {
      name: 'runActions',
      type: 'ui',
      admin: { components: { Field: '@/components/OtterScannerActions' } },
    },
    {
      name: 'credentialsConfigured',
      type: 'checkbox',
      admin: { readOnly: true },
      defaultValue: false,
    },
    {
      name: 'credentialSettings',
      type: 'ui',
      admin: { components: { Field: '@/components/OtterCredentialsField' } },
    },
    {
      name: 'encryptedCredentials',
      type: 'text',
      maxLength: 64_000,
      access: internal,
      admin: { hidden: true },
    },
  ],
  hooks: {
    beforeChange: [validateProfile, sanitizeCustomFieldValues],
    beforeDelete: [preventDeletingReferencedOtterConfig],
  },
  indexes: [{ fields: ['scanner', 'site'] }],
  lockDocuments: false,
}

export const OtterSchedules: CollectionConfig = {
  slug: 'otter-schedules',
  labels: { singular: 'Otter schedule', plural: 'Otter schedules' },
  access: {
    create: canCreateSchedule,
    delete: canWriteOtter,
    read: canReadOtter,
    update: canWriteOtter,
  },
  admin: {
    defaultColumns: ['name', 'scanner', 'scheduleType', 'timezone', 'enabled', 'nextRunAt'],
    description:
      'Select an Otter configuration; its site, scanner, scan options, and import overrides are used automatically. Offline schedules coalesce to their latest due run.',
    group: 'Otter',
    useAsTitle: 'name',
  },
  defaultSort: 'nextRunAt',
  disableBulkDelete: true,
  disableBulkEdit: true,
  fields: [
    { name: 'name', type: 'text', required: true },
    {
      name: 'site',
      type: 'relationship',
      filterOptions: filterWritableSites,
      index: true,
      maxDepth: 0,
      relationTo: 'sites',
      required: true,
      admin: { hidden: true },
    },
    {
      name: 'scanner',
      type: 'relationship',
      relationTo: 'otter-scanners',
      required: true,
      index: true,
      admin: { hidden: true },
    },
    {
      name: 'profile',
      label: 'Otter configuration',
      type: 'relationship',
      relationTo: 'otter-profiles',
      required: true,
      filterOptions: async ({ req }) => {
        if (req.context.otterSchedulerUpdate) return true
        const auth = await getAuthorization(req)
        return auth.isAdmin ? true : { site: { in: auth.writableSiteIDs } }
      },
    },
    {
      name: 'scheduleType',
      type: 'select',
      options: [
        { label: 'Run once', value: 'once' },
        { label: 'Repeat every interval', value: 'interval' },
        { label: 'Calendar schedule (cron)', value: 'cron' },
      ],
      required: true,
    },
    {
      name: 'runAt',
      type: 'date',
      admin: { condition: (_, siblingData) => siblingData?.scheduleType === 'once' },
    },
    {
      name: 'intervalMinutes',
      type: 'number',
      min: 5,
      max: 10_080,
      admin: { condition: (_, siblingData) => siblingData?.scheduleType === 'interval' },
    },
    {
      name: 'cron',
      type: 'text',
      admin: {
        condition: (_, siblingData) => siblingData?.scheduleType === 'cron',
        description: 'Five fields: minute hour day-of-month month day-of-week.',
        placeholder: '0 2 * * 1-5',
      },
    },
    {
      name: 'timezone',
      label: 'Time zone',
      type: 'text',
      defaultValue: 'UTC',
      admin: { description: 'IANA time zone, for example Europe/Berlin.' },
      required: true,
    },
    { name: 'enabled', type: 'checkbox', defaultValue: true },
    { name: 'nextRunAt', type: 'date', access: serverReadOnly, admin: { readOnly: true } },
    { name: 'lastRunAt', type: 'date', access: serverReadOnly, admin: { readOnly: true } },
  ],
  hooks: {
    beforeChange: [validateSchedule],
    beforeDelete: [preventDeletingReferencedOtterConfig],
  },
  indexes: [{ fields: ['scanner', 'enabled', 'nextRunAt'] }],
  lockDocuments: false,
}

export const OtterRuns: CollectionConfig = {
  slug: 'otter-runs',
  labels: { singular: 'Otter run', plural: 'Otter runs' },
  access: {
    create: () => false,
    delete: () => false,
    read: canReadOtter,
    update: () => false,
  },
  admin: {
    defaultColumns: [
      'name',
      'site',
      'scanner',
      'status',
      'message',
      'scheduledFor',
      'startedAt',
      'completedAt',
    ],
    description: 'Immutable scan assignments and outcomes.',
    group: 'Otter',
    useAsTitle: 'name',
  },
  defaultSort: '-createdAt',
  disableBulkDelete: true,
  disableBulkEdit: true,
  fields: [
    { name: 'name', type: 'text', required: true },
    { name: 'site', type: 'relationship', relationTo: 'sites', required: true, index: true },
    {
      name: 'scanner',
      type: 'relationship',
      relationTo: 'otter-scanners',
      required: true,
      index: true,
    },
    {
      name: 'profile',
      label: 'Otter configuration',
      type: 'relationship',
      relationTo: 'otter-profiles',
    },
    { name: 'schedule', type: 'relationship', relationTo: 'otter-schedules' },
    { name: 'scheduleOccurrenceKey', type: 'text', access: internal, admin: { hidden: true } },
    {
      name: 'status',
      type: 'select',
      options: [
        'queued',
        'assigned',
        'running',
        'completed',
        'partial',
        'failed',
        'cancel-requested',
        'cancelled',
        'expired',
      ],
      required: true,
      index: true,
    },
    { name: 'scheduledFor', type: 'date', index: true },
    { name: 'assignedAt', type: 'date' },
    { name: 'leaseExpiresAt', type: 'date' },
    { name: 'startedAt', type: 'date' },
    { name: 'completedAt', type: 'date' },
    { name: 'progress', type: 'number', min: 0, max: 100 },
    { name: 'message', type: 'textarea', maxLength: 4000 },
    { name: 'import', type: 'relationship', relationTo: 'asset-imports' },
    { name: 'configSnapshot', type: 'json', access: internal, admin: { hidden: true } },
    { name: 'importOverridesSnapshot', type: 'json', access: internal, admin: { hidden: true } },
    {
      name: 'encryptedCredentialsSnapshot',
      type: 'text',
      access: internal,
      admin: { hidden: true },
    },
  ],
  indexes: [{ fields: ['scanner', 'status', 'createdAt'] }],
  lockDocuments: false,
}

export const otterReadAccess = canReadOtter
export const otterWriteAccess = canWriteOtter
export const otterCreateAccess = canCreateOtter
