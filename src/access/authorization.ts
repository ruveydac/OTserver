import {
  APIError,
  type Access,
  type CollectionBeforeChangeHook,
  type FieldAccess,
  type FilterOptionsProps,
  type PayloadRequest,
  type Where,
} from 'payload'

type Authorization = {
  isAdmin: boolean
  readableSiteIDs: string[]
  writableSiteIDs: string[]
}

const noAuthorization: Authorization = {
  isAdmin: false,
  readableSiteIDs: [],
  writableSiteIDs: [],
}

export const relationshipID = (value: unknown): number | string | undefined => {
  if (typeof value === 'number' || typeof value === 'string') return value
  if (!value || typeof value !== 'object' || !('id' in value)) return undefined
  return relationshipID(value.id)
}

export const getSiteAndDescendantIDs = async (
  rootIDs: (number | string)[],
  req: PayloadRequest,
) => {
  const descendants = new Set(rootIDs.map(String))
  let parentIDs = [...rootIDs]

  while (parentIDs.length) {
    const children = await req.payload.find({
      collection: 'sites',
      depth: 0,
      overrideAccess: true,
      pagination: false,
      req,
      where: { parent: { in: parentIDs } },
    })
    parentIDs = []

    for (const child of children.docs) {
      if (!descendants.has(String(child.id))) {
        descendants.add(String(child.id))
        parentIDs.push(child.id)
      }
    }
  }

  return [...descendants]
}

export const getAuthorization = async (req: PayloadRequest): Promise<Authorization> => {
  if (!req.user) return noAuthorization

  const cached = req.context.siteAuthorization as Promise<Authorization> | undefined
  if (cached) return cached

  const authorization = (async () => {
    const roleID = relationshipID((req.user as { role?: unknown }).role)
    if (!roleID) return noAuthorization

    const roles = await req.payload.find({
      collection: 'user-roles',
      depth: 0,
      limit: 1,
      overrideAccess: true,
      req,
      where: { id: { equals: roleID } },
    })
    const role = roles.docs[0]
    if (!role) return noAuthorization
    if (role.isAdmin) return { ...noAuthorization, isAdmin: true }

    const readableRoots = new Set<string>()
    const writableRoots = new Set<string>()
    for (const permission of role.permissions || []) {
      const siteID = relationshipID(permission.site)
      if (!siteID) continue
      readableRoots.add(String(siteID))
      if (permission.access === 'read-write') writableRoots.add(String(siteID))
    }

    const [readableSiteIDs, writableSiteIDs] = await Promise.all([
      getSiteAndDescendantIDs([...readableRoots], req),
      getSiteAndDescendantIDs([...writableRoots], req),
    ])
    return { isAdmin: false, readableSiteIDs, writableSiteIDs }
  })()

  req.context.siteAuthorization = authorization
  return authorization
}

export const adminOnly: Access = async ({ req }) => (await getAuthorization(req)).isAdmin

export const hideFromNonAdmins = ({ user }: { user: unknown }) => {
  const role = (user as { role?: unknown } | null)?.role
  return typeof role !== 'object' || role === null || !('isAdmin' in role) || role.isAdmin !== true
}

export const canCreateUser: Access = async ({ req }) => {
  if (req.user) return (await getAuthorization(req)).isAdmin
  const users = await req.payload.count({ collection: 'users', overrideAccess: true, req })
  return users.totalDocs === 0
}

// The Payload first-user screen is unauthenticated. It must be able to load the
// one role that it assigns, but must not expose any other role before setup is
// complete.
export const canReadInitialAdminRole: Access = async ({ req }) => {
  if (req.user) return (await getAuthorization(req)).isAdmin
  const users = await req.payload.count({ collection: 'users', overrideAccess: true, req })
  return users.totalDocs === 0 ? { isAdmin: { equals: true } } : false
}

export const adminOrSelf: Access = async ({ req }) => {
  const authorization = await getAuthorization(req)
  if (authorization.isAdmin) return true
  return req.user ? { id: { equals: req.user.id } } : false
}

export const canAssignRoles: FieldAccess = async ({ req }) => {
  if (req.user) return (await getAuthorization(req)).isAdmin
  const users = await req.payload.count({ collection: 'users', overrideAccess: true, req })
  return users.totalDocs === 0
}

export const canReadSiteDocuments: Access = async ({ req }) => {
  const authorization = await getAuthorization(req)
  return authorization.isAdmin ? true : { site: { in: authorization.readableSiteIDs } }
}

export const canWriteSiteDocuments: Access = async ({ req }) => {
  const authorization = await getAuthorization(req)
  return authorization.isAdmin ? true : { site: { in: authorization.writableSiteIDs } }
}

export const canCreateSiteDocument: Access = async ({ data, req }) => {
  const authorization = await getAuthorization(req)
  if (authorization.isAdmin) return true
  if (!data) return authorization.writableSiteIDs.length > 0
  const siteID = relationshipID(data?.site)
  return Boolean(siteID && authorization.writableSiteIDs.includes(String(siteID)))
}

export const canReadSites: Access = async ({ req }) => {
  const authorization = await getAuthorization(req)
  return authorization.isAdmin ? true : { id: { in: authorization.readableSiteIDs } }
}

export const canWriteSites: Access = async ({ req }) => {
  const authorization = await getAuthorization(req)
  return authorization.isAdmin ? true : { id: { in: authorization.writableSiteIDs } }
}

export const canCreateSite: Access = async ({ data, req }) => {
  const authorization = await getAuthorization(req)
  if (authorization.isAdmin) return true
  if (!data) return authorization.writableSiteIDs.length > 0
  const parentID = relationshipID(data?.parent)
  return Boolean(parentID && authorization.writableSiteIDs.includes(String(parentID)))
}

export const filterWritableSites = async ({
  req,
}: Pick<FilterOptionsProps, 'req'>): Promise<true | Where> => {
  if (!req.user) return true
  const authorization = await getAuthorization(req)
  return authorization.isAdmin ? true : { id: { in: authorization.writableSiteIDs } }
}

export const enforceWritableSite: CollectionBeforeChangeHook = async ({
  data,
  originalDoc,
  req,
}) => {
  if (!req.user) return data
  const authorization = await getAuthorization(req)
  if (authorization.isAdmin) return data

  const siteID = relationshipID(Object.hasOwn(data, 'site') ? data.site : originalDoc?.site)
  if (!siteID || !authorization.writableSiteIDs.includes(String(siteID))) {
    throw new APIError('You do not have write access to this site.', 403)
  }
  return data
}

export const enforceWritableParent: CollectionBeforeChangeHook = async ({ data, req }) => {
  if (!req.user || !Object.hasOwn(data, 'parent')) return data
  const authorization = await getAuthorization(req)
  if (authorization.isAdmin) return data

  const parentID = relationshipID(data.parent)
  if (!parentID || !authorization.writableSiteIDs.includes(String(parentID))) {
    throw new APIError('You do not have write access to the selected parent site.', 403)
  }
  return data
}
