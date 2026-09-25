import {
  APIError,
  type CollectionConfig,
  type CollectionBeforeValidateHook,
  type CollectionAfterChangeHook,
  type CollectionBeforeChangeHook,
  type CollectionBeforeOperationHook,
} from 'payload'
import { isDeepStrictEqual } from 'node:util'
import {
  canCreateSiteDocument,
  canReadSiteDocuments,
  canWriteSiteDocuments,
  enforceWritableSite,
  filterWritableSites,
} from '../access/authorization'
import { userSuppliedAssetFields } from '../domain/assetFields'
import { sanitizeCustomFieldValues } from './AssetFields'
import { importSources } from '../importers/sources'
import { processImport } from '../application/processImport'
import {
  fileDigest,
  queueImport,
  queuedImportsEnabled,
  requireSiteWriter,
  retryImport,
} from '../application/queuedImports'
import { withRequestContext } from '../integrations/payload/context'
export { getAssetOverrides } from '../application/processImport'

const normalizeLegacyOtterSource: CollectionBeforeValidateHook = ({ data }) => {
  if (data?.source === 'otserver-scanner') data.source = 'otserver-otter'
  return data
}
const runImport: CollectionAfterChangeHook = async ({ context, doc, req, operation }) => {
  if (context.skipAssetImport || !req.file) return doc
  if (doc.executionMode === 'queued') return operation === 'create' ? queueImport(doc, req) : doc
  return withRequestContext(req, { importWrite: true }, () =>
    processImport({ doc, data: req.file!.data, req }),
  )
}

const managed = [
  'status',
  'jobID',
  'submittedBy',
  'executorID',
  'retriedBy',
  'fileDigest',
  'processingInput',
  'queuedAt',
  'startedAt',
  'completedAt',
  'attemptCount',
  'error',
  'appliedKey',
  'duplicateOf',
  'createdAssets',
  'updatedAssets',
  'skippedAssets',
  'projectName',
  'topologyName',
  'warnings',
  'scanMetadata',
  'unresolved',
]
const immutable = [
  'executionMode',
  'site',
  'source',
  'assetOverrides',
  'customFieldOverrides',
  'sourceVersion',
  'filename',
]
const internalFieldAccess = { create: () => false, read: () => false, update: () => false }
const protectProcessing: CollectionBeforeChangeHook = async ({
  data,
  originalDoc,
  operation,
  req,
  context,
}) => {
  if (context.importWrite) return data
  if (operation === 'update') {
    for (const field of managed)
      if (Object.hasOwn(data, field) && !isDeepStrictEqual(data[field], originalDoc?.[field]))
        throw new APIError('Processing state is managed by the server.', 400)
    if (originalDoc?.executionMode === 'queued') {
      for (const field of immutable)
        if (Object.hasOwn(data, field) && !isDeepStrictEqual(data[field], originalDoc[field]))
          throw new APIError('Queued processing inputs are immutable.', 409)
    } else if (data.executionMode === 'queued')
      throw new APIError('Select queued mode when creating the upload.', 400)
    return data
  }
  // Discard caller-supplied processing state, including through generic REST/GraphQL APIs.
  for (const field of managed) delete data[field]
  data.status = 'pending'
  data.attemptCount = 0
  if (data.executionMode === 'queued') {
    if (!queuedImportsEnabled()) throw new APIError('Queued imports are not enabled.', 503)
    await requireSiteWriter(data.site, req)
    if (!req.file) throw new APIError('A file is required for a queued import.', 400)
    data.submittedBy = data.executorID = String(req.user!.id)
    data.fileDigest = fileDigest(req.file.data)
    data.queuedAt = new Date().toISOString()
    data.processingInput = {
      version: 1,
      site: typeof data.site === 'object' ? data.site.id : data.site,
      source: data.source,
      assetOverrides: data.assetOverrides || {},
      customFieldOverrides: data.customFieldOverrides || {},
      sourceVersion: data.sourceVersion,
    }
  }
  return data
}

// Runs before Payload touches upload files. Hooks later in the operation are too late to protect bytes.
const protectUpload: CollectionBeforeOperationHook = async ({ args, operation, req }) => {
  if ((operation === 'update' || operation === 'delete') && !req.context.importWrite) {
    const ids = args as { id?: string; where?: import('payload').Where }
    const result = await req.payload.find({
      collection: 'asset-imports',
      depth: 0,
      limit: 1,
      overrideAccess: false,
      req,
      where: {
        and: [
          ids.id ? { id: { equals: ids.id } } : ids.where || {},
          { executionMode: { equals: 'queued' } },
          ...(operation === 'delete' ? [{ status: { in: ['pending', 'running'] } }] : []),
        ],
      },
    })
    if (result.docs.length && (operation === 'delete' || req.file))
      throw new APIError('Queued uploads cannot be replaced or deleted while active.', 409)
  }
  return args
}

export const AssetImports: CollectionConfig = {
  slug: 'asset-imports',
  endpoints: [{ path: '/:id/retry', method: 'post', handler: retryImport }],
  indexes: [{ fields: ['executionMode', 'status', 'queuedAt'] }],
  labels: {
    plural: 'Imports',
    singular: 'Import',
  },
  access: {
    create: canCreateSiteDocument,
    delete: canWriteSiteDocuments,
    read: canReadSiteDocuments,
    update: canWriteSiteDocuments,
  },
  admin: {
    defaultColumns: [
      'filename',
      'site',
      'source',
      'sourceVersion',
      'status',
      'createdAssets',
      'updatedAssets',
      'skippedAssets',
    ],
    description: 'Import physical identity and network evidence into a selected site.',
    group: 'OT Inventory',
    useAsTitle: 'filename',
  },
  fields: [
    {
      name: 'executionMode',
      type: 'select',
      defaultValue: 'sync',
      options: [
        { label: 'Synchronous', value: 'sync' },
        { label: 'Queued', value: 'queued' },
      ],
      admin: {
        description: 'Queued imports require OTSERVER_QUEUED_IMPORTS=on and a healthy worker.',
      },
    },
    {
      name: 'processingStatus',
      type: 'ui',
      admin: { components: { Field: '@/components/ImportStatus' } },
    },
    ...['jobID', 'submittedBy', 'executorID', 'retriedBy', 'fileDigest'].map((name) => ({
      name,
      type: 'text' as const,
      access: internalFieldAccess,
      admin: { readOnly: true, hidden: true },
    })),
    {
      name: 'processingInput',
      type: 'json',
      access: internalFieldAccess,
      admin: { hidden: true },
    },
    ...['queuedAt', 'startedAt', 'completedAt'].map((name) => ({
      name,
      type: 'date' as const,
      admin: { readOnly: true, position: 'sidebar' as const },
    })),
    {
      name: 'attemptCount',
      type: 'number',
      defaultValue: 0,
      admin: { readOnly: true, position: 'sidebar' },
    },
    {
      name: 'appliedKey',
      type: 'text',
      unique: true,
      access: { create: () => false, update: () => false },
      admin: { hidden: true },
    },
    {
      name: 'duplicateOf',
      type: 'relationship',
      relationTo: 'asset-imports',
      admin: { readOnly: true },
    },
    {
      name: 'site',
      type: 'relationship',
      admin: { description: 'Every asset in this file will be assigned to this site.' },
      filterOptions: filterWritableSites,
      index: true,
      relationTo: 'sites',
      required: true,
    },
    {
      name: 'source',
      type: 'select',
      defaultValue: 'otserver-otter',
      options: importSources.map(({ label, value }) => ({ label, value })),
      required: true,
    },
    {
      name: 'importInstructions',
      type: 'ui',
      admin: { components: { Field: '@/components/ImportInstructions' } },
    },
    {
      name: 'assetOverrides',
      type: 'group',
      admin: {
        description:
          'Optional values overwrite these fields on every new or existing asset in this import.',
      },
      fields: userSuppliedAssetFields.map(({ label, name, placeholder }) => ({
        name,
        type: 'text' as const,
        admin: { placeholder },
        label,
      })),
      label: 'Apply to imported assets',
    },
    {
      name: 'customFieldOverrides',
      type: 'json',
      admin: { components: { Field: '@/components/CustomAssetFields' } },
      label: 'Custom field overrides',
    },
    {
      name: 'sourceVersion',
      type: 'text',
      defaultValue: 'unknown',
      label: 'Otter version',
      required: true,
    },
    {
      name: 'status',
      type: 'select',
      admin: { position: 'sidebar', readOnly: true },
      defaultValue: 'pending',
      options: [
        { label: 'Pending', value: 'pending' },
        { label: 'Running', value: 'running' },
        { label: 'Completed', value: 'completed' },
        { label: 'Failed', value: 'failed' },
      ],
      required: true,
    },
    {
      type: 'row',
      fields: [
        {
          name: 'createdAssets',
          type: 'number',
          admin: { readOnly: true, width: '33.33%' },
          defaultValue: 0,
          label: 'Created',
        },
        {
          name: 'updatedAssets',
          type: 'number',
          admin: { readOnly: true, width: '33.33%' },
          defaultValue: 0,
          label: 'Updated',
        },
        {
          name: 'skippedAssets',
          type: 'number',
          admin: { readOnly: true, width: '33.33%' },
          defaultValue: 0,
          label: 'Skipped',
        },
      ],
    },
    {
      name: 'projectName',
      type: 'text',
      admin: { readOnly: true },
      label: 'Project name',
    },
    {
      name: 'topologyName',
      type: 'text',
      admin: { readOnly: true },
      label: 'Topology name',
    },
    {
      name: 'warnings',
      type: 'textarea',
      admin: { readOnly: true },
    },
    {
      name: 'scanMetadata',
      type: 'json',
      admin: { readOnly: true },
      label: 'Scan metadata',
    },
    {
      name: 'unresolved',
      type: 'json',
      admin: { readOnly: true },
      label: 'Unresolved observations',
    },
    {
      name: 'error',
      type: 'textarea',
      admin: { readOnly: true },
    },
  ],
  hooks: {
    beforeOperation: [protectUpload],
    afterChange: [runImport],
    beforeValidate: [normalizeLegacyOtterSource],
    beforeChange: [
      enforceWritableSite,
      sanitizeCustomFieldValues,
      protectProcessing,
      ({ data, context }) => {
        if (context.appliedImportKey) data.appliedKey = context.appliedImportKey
        return data
      },
    ],
  },
  upload: {
    // PRONETA and Nmap are XML; parsers still enforce size and structure limits.
    allowRestrictedFileTypes: true,
    bulkUpload: false,
    mimeTypes: ['application/json', 'application/xml', 'text/json', 'text/plain', 'text/xml'],
    pasteURL: false,
    staticDir: 'import-files',
  },
}
