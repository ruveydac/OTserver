import {
  APIError,
  type CollectionBeforeChangeHook,
  type CollectionBeforeDeleteHook,
  type CollectionConfig,
  type FilterOptionsProps,
  type Where,
} from 'payload'

import {
  canCreateSite,
  canReadSites,
  canWriteSites,
  enforceWritableParent,
  getAuthorization,
  getSiteAndDescendantIDs,
  relationshipID,
} from '../access/authorization'

export const filterSiteParents = async ({
  id,
  req,
}: Pick<FilterOptionsProps, 'id' | 'req'>): Promise<true | Where> => {
  const conditions: Where[] = []
  if (id) conditions.push({ id: { not_in: await getSiteAndDescendantIDs([id], req) } })

  if (req.user) {
    const authorization = await getAuthorization(req)
    if (!authorization.isAdmin) conditions.push({ id: { in: authorization.writableSiteIDs } })
  }

  return conditions.length ? { and: conditions } : true
}

const preventHierarchyCycles: CollectionBeforeChangeHook = async ({ data, originalDoc, req }) => {
  const siteID = relationshipID(originalDoc?.id)
  let parentID = relationshipID(Object.hasOwn(data, 'parent') ? data.parent : originalDoc?.parent)

  if (!siteID || !parentID) return data

  const visited = new Set([String(siteID)])
  while (parentID) {
    if (visited.has(String(parentID))) {
      throw new APIError('A site cannot be its own parent or descendant.', 400)
    }

    visited.add(String(parentID))
    const parent = await req.payload.findByID({
      collection: 'sites',
      depth: 0,
      id: parentID,
      overrideAccess: true,
      req,
    })
    parentID = relationshipID(parent.parent)
  }

  return data
}

const preventDeletingUsedSites: CollectionBeforeDeleteHook = async ({ id, req }) => {
  const [children, assets, imports, roles] = await Promise.all([
    req.payload.count({
      collection: 'sites',
      overrideAccess: true,
      req,
      where: { parent: { equals: id } },
    }),
    req.payload.count({
      collection: 'assets',
      overrideAccess: true,
      req,
      where: { site: { equals: id } },
    }),
    req.payload.count({
      collection: 'asset-imports',
      overrideAccess: true,
      req,
      where: { site: { equals: id } },
    }),
    req.payload.count({
      collection: 'user-roles',
      overrideAccess: true,
      req,
      where: { 'permissions.site': { equals: id } },
    }),
  ])

  if (children.totalDocs || assets.totalDocs || imports.totalDocs || roles.totalDocs) {
    throw new APIError(
      'Move or delete this site’s child sites, assets, imports, and role permissions before deleting it.',
      400,
    )
  }
}

export const Sites: CollectionConfig = {
  slug: 'sites',
  access: {
    create: canCreateSite,
    delete: canWriteSites,
    read: canReadSites,
    update: canWriteSites,
  },
  admin: {
    components: {
      views: { list: { Component: '@/components/SiteTreeView' } },
    },
    defaultColumns: ['name', 'type', 'parent', 'updatedAt'],
    description: 'Organize assets with your own site types and hierarchy.',
    group: 'OT Inventory',
    listSearchableFields: ['name', 'type', 'description'],
    useAsTitle: 'name',
  },
  defaultSort: 'name',
  fields: [
    {
      name: 'name',
      type: 'text',
      index: true,
      required: true,
    },
    {
      name: 'siteIDDisplay',
      type: 'ui',
      admin: { components: { Field: '@/components/SiteIDField' } },
    },
    {
      name: 'type',
      type: 'text',
      admin: { placeholder: 'Continent, country, plant, area…' },
      label: 'Site type',
      required: true,
    },
    {
      name: 'parent',
      type: 'relationship',
      admin: { description: 'Optional parent site; nesting can be as deep as needed.' },
      filterOptions: filterSiteParents,
      index: true,
      maxDepth: 1,
      relationTo: 'sites',
    },
    {
      name: 'description',
      type: 'textarea',
    },
  ],
  hooks: {
    beforeChange: [enforceWritableParent, preventHierarchyCycles],
    beforeDelete: [preventDeletingUsedSites],
  },
  timestamps: true,
}
