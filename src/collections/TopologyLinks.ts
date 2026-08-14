import type { CollectionConfig } from 'payload'

import { canReadSiteDocuments } from '../access/authorization'

export const TopologyLinks: CollectionConfig = {
  slug: 'topology-links',
  access: {
    create: () => false,
    delete: () => false,
    read: canReadSiteDocuments,
    update: () => false,
  },
  admin: { hidden: true, useAsTitle: 'source' },
  defaultSort: '-observedAt',
  disableBulkDelete: true,
  disableBulkEdit: true,
  fields: [
    {
      name: 'site',
      type: 'relationship',
      index: true,
      maxDepth: 0,
      relationTo: 'sites',
      required: true,
    },
    {
      name: 'import',
      type: 'relationship',
      index: true,
      maxDepth: 0,
      relationTo: 'asset-imports',
      required: true,
    },
    { name: 'localAsset', type: 'relationship', index: true, maxDepth: 0, relationTo: 'assets' },
    { name: 'remoteAsset', type: 'relationship', index: true, maxDepth: 0, relationTo: 'assets' },
    { name: 'source', type: 'text', index: true, required: true },
    { name: 'observedAt', type: 'date', index: true, required: true },
    { name: 'local', type: 'json', required: true },
    { name: 'remote', type: 'json', required: true },
    { name: 'raw', type: 'json' },
  ],
  indexes: [{ fields: ['localAsset', 'observedAt'] }, { fields: ['remoteAsset', 'observedAt'] }],
  lockDocuments: false,
  timestamps: true,
}
