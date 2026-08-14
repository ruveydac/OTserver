import type { CollectionConfig } from 'payload'

import { canReadSiteDocuments } from '../access/authorization'

export const AssetObservations: CollectionConfig = {
  slug: 'asset-observations',
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
      name: 'asset',
      type: 'relationship',
      index: true,
      maxDepth: 0,
      relationTo: 'assets',
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
    { name: 'source', type: 'text', index: true, required: true },
    { name: 'quality', type: 'select', options: ['high', 'medium', 'low'], required: true },
    { name: 'observedAt', type: 'date', index: true, required: true },
    { name: 'fields', type: 'json', required: true },
    { name: 'interfaces', type: 'json' },
    { name: 'ports', type: 'json' },
    { name: 'raw', type: 'json' },
    { name: 'warnings', type: 'json' },
  ],
  indexes: [{ fields: ['asset', 'observedAt'] }],
  lockDocuments: false,
  timestamps: true,
}
