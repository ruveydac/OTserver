import { randomUUID } from 'node:crypto'
import {
  APIError,
  type CollectionBeforeChangeHook,
  type CollectionConfig,
  type Field,
  type Payload,
  type PayloadRequest,
  type Where,
} from 'payload'
import {
  adminOnly,
  getAuthorization,
  hideFromNonAdmins,
  relationshipID,
} from '../access/authorization'
import { mongoSession } from '../integrations/payload/mongo'

export const isa95Elements = [
  { label: 'Enterprise', value: 'enterprise' },
  { label: 'Site', value: 'site' },
  { label: 'Area', value: 'area' },
  { label: 'Work center', value: 'work-center' },
  { label: 'Work unit', value: 'work-unit' },
  { label: 'Production line', value: 'production-line' },
  { label: 'Work cell', value: 'work-cell' },
  { label: 'Process cell', value: 'process-cell' },
  { label: 'Unit', value: 'unit' },
  { label: 'Production unit', value: 'production-unit' },
  { label: 'Storage zone', value: 'storage-zone' },
  { label: 'Storage unit', value: 'storage-unit' },
] as const

export const defaultSiteTypes = [
  {
    key: 'to-be-changed',
    name: 'To be changed',
    category: 'custom',
    isa95Element: 'site',
    description:
      'Existing site awaiting classification. Mapped to Site until a specific type is selected.',
  },
  {
    key: 'continent',
    name: 'Continent',
    category: 'geographic',
    isa95Element: 'enterprise',
    blockImports: true,
  },
  {
    key: 'country',
    name: 'Country',
    category: 'geographic',
    isa95Element: 'area',
    blockImports: true,
  },
  {
    key: 'region',
    name: 'State / region',
    category: 'geographic',
    isa95Element: 'area',
  },
  {
    key: 'city',
    name: 'City',
    category: 'geographic',
    isa95Element: 'area',
    blockImports: true,
  },
  {
    key: 'enterprise',
    name: 'Enterprise',
    category: 'organizational',
    isa95Element: 'enterprise',
    blockImports: true,
  },
  {
    key: 'site',
    name: 'Site / plant',
    category: 'organizational',
    isa95Element: 'site',
    blockImports: true,
    description: 'A site or plant containing areas, production lines, and other child sites.',
  },
  { key: 'area', name: 'Area', category: 'production', isa95Element: 'area' },
  {
    key: 'work-center',
    name: 'Work center',
    category: 'production',
    isa95Element: 'work-center',
    description:
      'Generic grouping of scheduled equipment. Production lines, process cells, production units, and storage zones are alternatives.',
  },
  { key: 'work-unit', name: 'Work unit', category: 'production', isa95Element: 'work-unit' },
  {
    key: 'production-line',
    name: 'Production line',
    category: 'production',
    isa95Element: 'production-line',
    description:
      'Discrete manufacturing work center, typically within an area and containing work cells.',
  },
  { key: 'work-cell', name: 'Work cell', category: 'production', isa95Element: 'work-cell' },
  {
    key: 'process-cell',
    name: 'Process cell',
    category: 'production',
    isa95Element: 'process-cell',
    description: 'Batch manufacturing work center, typically containing units.',
  },
  {
    key: 'unit',
    name: 'Unit',
    category: 'production',
    isa95Element: 'unit',
    description: 'Functional unit within batch or continuous manufacturing.',
  },
  {
    key: 'production-unit',
    name: 'Production unit',
    category: 'production',
    isa95Element: 'production-unit',
    description: 'Continuous manufacturing work center.',
  },
  {
    key: 'storage-zone',
    name: 'Storage zone',
    category: 'production',
    isa95Element: 'storage-zone',
    description:
      'Material-handling work center, typically containing storage units. This is not a cybersecurity zone.',
  },
  {
    key: 'storage-unit',
    name: 'Storage unit',
    category: 'production',
    isa95Element: 'storage-unit',
  },
] as const

export const initializeSiteTypes = async (payload: Payload, req?: PayloadRequest) => {
  for (const definition of defaultSiteTypes) {
    const find = () =>
      payload.find({
        collection: 'site-types',
        depth: 0,
        limit: 1,
        pagination: false,
        overrideAccess: true,
        req,
        where: { key: { equals: definition.key } },
      })
    if ((await find()).docs.length) continue
    try {
      await payload.create({
        collection: 'site-types',
        data: { ...definition, active: true },
        overrideAccess: true,
        req,
      })
    } catch (error) {
      // Another web/worker startup may have created this unique seed concurrently.
      if (req || !(await find()).docs.length) throw error
    }
  }
}

export const siteTypeField: Field = {
  name: 'type',
  type: 'relationship',
  relationTo: 'site-types',
  label: 'Site type',
  required: true,
  index: true,
  maxDepth: 1,
  filterOptions: async ({ id, req }): Promise<Where> => {
    const current = id
      ? await req.payload.findByID({
          collection: 'sites',
          id,
          depth: 0,
          disableErrors: true,
          overrideAccess: !req.user,
          req,
        })
      : undefined
    const currentType = relationshipID(current?.type)
    return currentType
      ? { or: [{ active: { equals: true } }, { id: { equals: currentType } }] }
      : { active: { equals: true } }
  },
}

const lockSiteType = async (id: number | string, req: PayloadRequest) => {
  const session = await mongoSession(req)
  if (!session) throw new APIError('Site-type changes require a database transaction.', 503)
  const ObjectId = req.payload.db.connection.base.Types.ObjectId
  if (!ObjectId.isValid(id)) throw new APIError('Select an existing site type.', 400)
  // Serialize new references with retirement/deletion; the collection mutation supplies the audit.
  const result = await req.payload.db.collections['site-types'].collection.updateOne(
    { _id: new ObjectId(String(id)) },
    { $inc: { referenceRevision: 1 } },
    { session },
  )
  if (!result.matchedCount) throw new APIError('Select an existing site type.', 400)
}

export const enforceSiteType: CollectionBeforeChangeHook = async ({ data, originalDoc, req }) => {
  const id = relationshipID(data.type ?? originalDoc?.type)
  if (!id || String(id) === String(relationshipID(originalDoc?.type))) return data
  const type = await req.payload.findByID({
    collection: 'site-types',
    id,
    depth: 0,
    overrideAccess: !req.user,
    req,
  })
  await lockSiteType(id, req)
  if (!type.active) throw new APIError('Select an active site type.', 400)
  return data
}

export const SiteTypes: CollectionConfig = {
  slug: 'site-types',
  labels: { singular: 'Site type', plural: 'Site types' },
  access: {
    create: adminOnly,
    update: adminOnly,
    delete: adminOnly,
    read: async ({ req }) => {
      if (req.context.otterScannerSiteID) return false
      const authorization = await getAuthorization(req)
      return authorization.isAdmin || authorization.readableSiteIDs.length > 0
    },
  },
  admin: {
    group: 'OT inventory',
    useAsTitle: 'name',
    hidden: hideFromNonAdmins,
    defaultColumns: ['name', 'category', 'active', 'blockImports'],
    description:
      'Types for every level of the site hierarchy. Retire built-in types to remove them from new selections.',
  },
  defaultSort: 'name',
  fields: [
    { name: 'name', type: 'text', required: true, maxLength: 100, index: true },
    {
      name: 'normalizedName',
      type: 'text',
      unique: true,
      admin: { hidden: true },
      access: { create: () => false, update: () => false },
    },
    {
      name: 'key',
      type: 'text',
      required: true,
      unique: true,
      defaultValue: randomUUID,
      admin: { readOnly: true },
      access: { update: () => false },
    },
    { name: 'description', type: 'textarea' },
    {
      name: 'category',
      type: 'select',
      required: true,
      defaultValue: 'custom',
      options: ['geographic', 'organizational', 'production', 'custom'],
    },
    {
      name: 'isa95Element',
      label: 'ISA-95 element',
      type: 'select',
      options: isa95Elements.map(({ label, value }) => ({ label, value })),
    },
    { name: 'active', type: 'checkbox', defaultValue: true, required: true },
    {
      name: 'blockImports',
      type: 'checkbox',
      label: 'Block imports',
      defaultValue: false,
      admin: {
        description:
          'Block imports and Otter scans for sites assigned this type. Child sites follow their own types. Existing inventory and history remain accessible.',
      },
    },
    {
      name: 'referenceRevision',
      type: 'number',
      defaultValue: 0,
      admin: { hidden: true },
      access: { create: () => false, read: () => false, update: () => false },
    },
  ],
  hooks: {
    beforeValidate: [
      ({ data, originalDoc }) => {
        if (!data) return data
        const name = data.name ?? originalDoc?.name
        if (typeof name === 'string') {
          data.name = name.normalize('NFKC').trim().replace(/\s+/g, ' ')
          data.normalizedName = data.name.toLowerCase()
        }
        if (originalDoc?.id) data.key = originalDoc.key
        return data
      },
    ],
    beforeDelete: [
      async ({ id, req }) => {
        const type = await req.payload.findByID({
          collection: 'site-types',
          id,
          depth: 0,
          overrideAccess: true,
          req,
        })
        if (defaultSiteTypes.some(({ key }) => key === type.key))
          throw new APIError('Retire built-in site types instead of deleting them.', 400)
        await lockSiteType(id, req)
        const used = await req.payload.count({
          collection: 'sites',
          where: { type: { equals: id } },
          overrideAccess: true,
          req,
        })
        if (used.totalDocs)
          throw new APIError('Reassign sites before deleting this site type.', 400)
      },
    ],
  },
}
