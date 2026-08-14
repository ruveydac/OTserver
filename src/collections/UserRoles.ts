import {
  APIError,
  type CollectionBeforeChangeHook,
  type CollectionBeforeDeleteHook,
  type CollectionConfig,
  type Payload,
  type PayloadRequest,
} from 'payload'

import { adminOnly, canReadInitialAdminRole, hideFromNonAdmins } from '../access/authorization'

const ADMIN_ROLE_NAME = 'Admin'

const protectAdminRole: CollectionBeforeChangeHook = ({ context, data, originalDoc }) => {
  if (context.ensureAdminRole || originalDoc?.isAdmin) {
    return { ...data, isAdmin: true, name: ADMIN_ROLE_NAME, permissions: [] }
  }
  return { ...data, isAdmin: false }
}

const preventDeletingAdminOrUsedRole: CollectionBeforeDeleteHook = async ({ id, req }) => {
  const role = await req.payload.findByID({
    collection: 'user-roles',
    depth: 0,
    id,
    overrideAccess: true,
    req,
  })
  if (role.isAdmin) throw new APIError('The Admin role cannot be deleted.', 400)

  const users = await req.payload.count({
    collection: 'users',
    overrideAccess: true,
    req,
    where: { role: { equals: id } },
  })
  if (users.totalDocs) throw new APIError('Assign affected users to another role first.', 400)
}

export const ensureAdminRole = async (payload: Payload, req?: PayloadRequest) => {
  const existing = await payload.find({
    collection: 'user-roles',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    req,
    where: {
      or: [{ isAdmin: { equals: true } }, { name: { equals: ADMIN_ROLE_NAME } }],
    },
  })
  const role = existing.docs[0]
  if (!role) {
    return payload.create({
      collection: 'user-roles',
      context: { ensureAdminRole: true },
      data: { isAdmin: true, name: ADMIN_ROLE_NAME, permissions: [] },
      overrideAccess: true,
      req,
    })
  }
  if (role.isAdmin && role.name === ADMIN_ROLE_NAME && !role.permissions?.length) return role

  return payload.update({
    collection: 'user-roles',
    context: { ensureAdminRole: true },
    data: { isAdmin: true, name: ADMIN_ROLE_NAME, permissions: [] },
    id: role.id,
    overrideAccess: true,
    req,
  })
}

export const initializeAuthorization = async (payload: Payload) => {
  const adminRole = await ensureAdminRole(payload)
  const users = await payload.find({
    collection: 'users',
    depth: 0,
    overrideAccess: true,
    pagination: false,
    where: { role: { exists: false } },
  })
  for (const user of users.docs) {
    await payload.update({
      collection: 'users',
      data: { role: adminRole.id },
      id: user.id,
      overrideAccess: true,
    })
  }
}

export const UserRoles: CollectionConfig = {
  slug: 'user-roles',
  labels: { plural: 'User Roles', singular: 'User Role' },
  access: {
    create: adminOnly,
    delete: adminOnly,
    read: canReadInitialAdminRole,
    update: adminOnly,
  },
  admin: {
    defaultColumns: ['name', 'isAdmin', 'updatedAt'],
    description: 'Assign read or write access to a site and every site underneath it.',
    group: 'Access Control',
    hidden: hideFromNonAdmins,
    useAsTitle: 'name',
  },
  defaultSort: 'name',
  fields: [
    {
      name: 'name',
      type: 'text',
      required: true,
      unique: true,
    },
    {
      name: 'isAdmin',
      type: 'checkbox',
      admin: {
        description: 'The permanent Admin role has unrestricted access.',
        position: 'sidebar',
        readOnly: true,
      },
      defaultValue: false,
      label: 'Administrator',
    },
    {
      name: 'permissions',
      type: 'array',
      admin: {
        condition: (data) => !data.isAdmin,
        description: 'Each permission applies to the selected site and all descendants.',
      },
      fields: [
        {
          name: 'site',
          type: 'relationship',
          relationTo: 'sites',
          required: true,
        },
        {
          name: 'access',
          type: 'select',
          defaultValue: 'read',
          options: [
            { label: 'Read only', value: 'read' },
            { label: 'Read / write', value: 'read-write' },
          ],
          required: true,
        },
      ],
      labels: { plural: 'Site permissions', singular: 'Site permission' },
    },
  ],
  hooks: {
    beforeChange: [protectAdminRole],
    beforeDelete: [preventDeletingAdminOrUsedRole],
  },
  timestamps: true,
}
