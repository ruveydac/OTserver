import type { CollectionConfig } from 'payload'
import { adminOnly, hideFromNonAdmins } from '../access/authorization'

const access = { create: () => false, delete: () => false, update: () => false, read: adminOnly }

export const WorkerLeases: CollectionConfig = {
  slug: 'worker-leases',
  access,
  admin: { group: 'Operations', hidden: hideFromNonAdmins, useAsTitle: 'queue' },
  fields: [
    { name: 'queue', type: 'text', required: true, unique: true },
    { name: 'owner', type: 'text', required: true },
    { name: 'revision', type: 'number', defaultValue: 0 },
    { name: 'lastSuccessAt', type: 'date' },
    { name: 'lastJobID', type: 'text' },
  ],
}

// Heartbeats are separate from the fence: renewing a lease must not invalidate an import transaction.
export const WorkerHeartbeats: CollectionConfig = {
  slug: 'worker-heartbeats',
  access,
  admin: { group: 'Operations', hidden: hideFromNonAdmins, useAsTitle: 'queue' },
  fields: [
    { name: 'queue', type: 'text', required: true, unique: true },
    { name: 'owner', type: 'text', required: true },
    { name: 'heartbeatAt', type: 'date', required: true },
    { name: 'expiresAt', type: 'date', required: true },
  ],
}
