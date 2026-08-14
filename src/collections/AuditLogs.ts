import { isDeepStrictEqual } from 'node:util'

import type {
  CollectionAfterChangeHook,
  CollectionAfterDeleteHook,
  CollectionAfterLoginHook,
  CollectionAfterLogoutHook,
  CollectionConfig,
  Access,
  PayloadRequest,
} from 'payload'

import { getAuthorization, hideFromNonAdmins } from '../access/authorization'
import { relationshipID } from '../access/authorization'

type AuditAction = 'create' | 'custom' | 'delete' | 'login' | 'logout' | 'update'
type Document = Record<string, unknown>

const ignoredFields = new Set(['collection', 'createdAt', 'id', 'updatedAt'])
const sensitiveField = /api[-_]?key|hash|password|salt|secret|session|token/i

const canReadAuditLogs: Access = async ({ req }) => {
  const authorization = await getAuthorization(req)
  return authorization.isAdmin
    ? true
    : { 'asset.site': { in: authorization.readableSiteIDs } }
}

const clean = (value: unknown): Document => {
  const json = JSON.stringify(value ?? {}, (key, item) =>
    sensitiveField.test(key) ? '[REDACTED]' : item,
  )
  return JSON.parse(json) as Document
}

export const getAuditChanges = (before: unknown, after: unknown) => {
  const previous = clean(before)
  const current = clean(after)
  const changes: Record<string, { after?: unknown; before?: unknown }> = {}

  for (const field of new Set([...Object.keys(previous), ...Object.keys(current)])) {
    if (ignoredFields.has(field) || isDeepStrictEqual(previous[field], current[field])) continue
    changes[field] = {
      ...(current[field] !== undefined ? { after: current[field] } : {}),
      ...(previous[field] !== undefined ? { before: previous[field] } : {}),
    }
  }

  return changes
}

const labelFor = (doc: Document) => {
  for (const field of ['name', 'title', 'label', 'email', 'filename']) {
    if (typeof doc[field] === 'string' && doc[field]) return doc[field]
  }
}

export const writeAudit = async ({
  action,
  after,
  before,
  req,
  targetCollection,
}: {
  action: AuditAction
  after?: unknown
  before?: unknown
  req: PayloadRequest
  targetCollection: string
}) => {
  const document = clean(after ?? before)
  const actor = clean(req.user)
  const documentID = document.id === undefined ? undefined : String(document.id)
  const documentLabel = labelFor(document)
  const relatedAsset = relationshipID(document.asset ?? document.localAsset)
  const assetID = targetCollection === 'assets' ? documentID : relatedAsset ? String(relatedAsset) : undefined
  const forwardedFor = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
  const requestPath = req.url ? new URL(req.url, 'http://local').pathname : undefined

  await req.payload.create({
    collection: 'audit-logs',
    data: {
      action,
      actorEmail: typeof actor.email === 'string' ? actor.email : undefined,
      actorID: actor.id === undefined ? undefined : String(actor.id),
      actorName: typeof actor.name === 'string' ? actor.name : undefined,
      actorType: req.user ? 'user' : 'system',
      ...(assetID ? { asset: assetID, assetID } : {}),
      changes: getAuditChanges(before, after),
      documentID,
      documentLabel,
      ipAddress: forwardedFor || req.headers.get('x-real-ip') || undefined,
      requestMethod: req.method,
      requestPath,
      summary: `${action} ${targetCollection}${documentLabel ? `: ${documentLabel}` : documentID ? ` ${documentID}` : ''}`,
      targetCollection,
    },
    overrideAccess: true,
    req,
  })
}

const afterChange: CollectionAfterChangeHook = async ({
  collection,
  doc,
  operation,
  previousDoc,
  req,
}) => {
  await writeAudit({
    action: operation,
    after: doc,
    before: operation === 'update' ? previousDoc : undefined,
    req,
    targetCollection: collection.slug,
  })
  return doc
}

const afterDelete: CollectionAfterDeleteHook = async ({ collection, doc, req }) => {
  await writeAudit({ action: 'delete', before: doc, req, targetCollection: collection.slug })
  return doc
}

const afterLogin: CollectionAfterLoginHook = async ({ collection, req, user }) => {
  await writeAudit({ action: 'login', after: user, req, targetCollection: collection.slug })
  return user
}

const afterLogout: CollectionAfterLogoutHook = async ({ collection, req }) => {
  await writeAudit({ action: 'logout', after: req.user, req, targetCollection: collection.slug })
}

export const withAudit = (collection: CollectionConfig): CollectionConfig => {
  if (collection.slug === 'audit-logs') return collection
  const hooks = collection.hooks || {}

  return {
    ...collection,
    hooks: {
      ...hooks,
      afterChange: [...(hooks.afterChange || []), afterChange],
      afterDelete: [...(hooks.afterDelete || []), afterDelete],
      ...(collection.auth
        ? {
            afterLogin: [...(hooks.afterLogin || []), afterLogin],
            afterLogout: [...(hooks.afterLogout || []), afterLogout],
          }
        : {}),
    },
  }
}

export const AuditLogs: CollectionConfig = {
  slug: 'audit-logs',
  labels: { plural: 'Audit Log', singular: 'Audit Entry' },
  access: {
    create: () => false,
    delete: () => false,
    read: canReadAuditLogs,
    update: () => false,
  },
  admin: {
    defaultColumns: [
      'createdAt',
      'action',
      'targetCollection',
      'documentLabel',
      'actorEmail',
    ],
    description: 'Immutable history of inventory, configuration, and authentication changes.',
    group: 'Audit',
    hidden: hideFromNonAdmins,
    listSearchableFields: ['summary', 'targetCollection', 'documentID', 'actorEmail'],
    useAsTitle: 'summary',
  },
  defaultSort: '-createdAt',
  disableBulkDelete: true,
  disableBulkEdit: true,
  fields: [
    { name: 'summary', type: 'text', required: true },
    {
      name: 'action',
      type: 'select',
      index: true,
      options: ['create', 'update', 'delete', 'login', 'logout', 'custom'],
      required: true,
    },
    { name: 'targetCollection', type: 'text', index: true, required: true },
    { name: 'documentID', type: 'text', index: true, label: 'Document ID' },
    { name: 'documentLabel', type: 'text', label: 'Document' },
    {
      name: 'asset',
      type: 'relationship',
      index: true,
      maxDepth: 0,
      relationTo: 'assets',
    },
    { name: 'assetID', type: 'text', index: true, label: 'Asset ID' },
    {
      name: 'actorType',
      type: 'select',
      index: true,
      options: ['user', 'system'],
      required: true,
    },
    { name: 'actorID', type: 'text', index: true, label: 'Actor ID' },
    { name: 'actorName', type: 'text', label: 'Actor name' },
    { name: 'actorEmail', type: 'email', index: true, label: 'Actor email' },
    { name: 'ipAddress', type: 'text', label: 'IP address' },
    { name: 'requestMethod', type: 'text', label: 'Request method' },
    { name: 'requestPath', type: 'text', label: 'Request path' },
    { name: 'changes', type: 'json' },
  ],
  indexes: [{ fields: ['targetCollection', 'documentID'] }, { fields: ['asset', 'action'] }],
  lockDocuments: false,
  timestamps: true,
}
