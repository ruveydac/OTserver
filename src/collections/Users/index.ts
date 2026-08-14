import type { CollectionBeforeValidateHook, CollectionConfig, PayloadRequest } from 'payload'

import {
  adminOnly,
  adminOrSelf,
  canAssignRoles,
  canCreateUser,
  hideFromNonAdmins,
} from '../../access/authorization'
import { ensureAdminRole } from '../UserRoles'

const assignFirstUserToAdmin: CollectionBeforeValidateHook = async ({ data, operation, req }) => {
  if (operation !== 'create' || data?.role) return data

  const users = await req.payload.count({ collection: 'users', overrideAccess: true, req })
  if (users.totalDocs) return data

  const adminRole = await ensureAdminRole(req.payload, req)
  return { ...data, role: adminRole.id }
}

const firstUserAdminRoleDefault = async ({ req }: { req: PayloadRequest }) => {
  if (req.user) return undefined

  const users = await req.payload.count({ collection: 'users', overrideAccess: true, req })
  if (users.totalDocs) return undefined

  return (await ensureAdminRole(req.payload, req)).id
}

export const Users: CollectionConfig = {
  slug: 'users',
  access: {
    admin: ({ req }) => Boolean(req.user),
    create: canCreateUser,
    delete: adminOnly,
    read: adminOrSelf,
    update: adminOrSelf,
  },
  admin: {
    defaultColumns: ['name', 'email', 'role'],
    group: 'Access Control',
    hidden: hideFromNonAdmins,
    useAsTitle: 'name',
  },
  auth: { useAPIKey: true },
  fields: [
    {
      name: 'name',
      type: 'text',
    },
    {
      name: 'role',
      type: 'relationship',
      access: {
        create: canAssignRoles,
        read: canAssignRoles,
        update: canAssignRoles,
      },
      defaultValue: firstUserAdminRoleDefault as never,
      relationTo: 'user-roles',
      required: true,
    },
  ],
  hooks: { beforeValidate: [assignFirstUserToAdmin] },
  timestamps: true,
}
