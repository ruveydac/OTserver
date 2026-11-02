import type { CollectionConfig } from 'payload'
import { adminOnly, hideFromNonAdmins } from '../access/authorization'
import { importMetadataEndpoint } from '../metadata/import'

export const DeviceCatalog: CollectionConfig = {
  slug: 'device-catalog',
  labels: { singular: 'Device catalog', plural: 'Device catalog' },
  access: { read: adminOnly, create: () => false, update: () => false, delete: () => false },
  admin: {
    group: 'Settings',
    hidden: hideFromNonAdmins,
    useAsTitle: 'revision',
    defaultColumns: ['revision', 'manufacturerCount', 'deviceCount', 'updatedAt'],
    components: { beforeList: ['@/components/DeviceCatalogImporter'] },
  },
  endpoints: [{ path: '/import', method: 'post', handler: importMetadataEndpoint }],
  fields: [
    { name: 'id', type: 'text', required: true },
    { name: 'revision', type: 'text', required: true, admin: { readOnly: true } },
    { name: 'manufacturerCount', type: 'number', required: true, admin: { readOnly: true } },
    { name: 'deviceCount', type: 'number', required: true, admin: { readOnly: true } },
    { name: 'catalog', type: 'json', required: true, admin: { hidden: true } },
    {
      name: 'catalogTables',
      type: 'ui',
      admin: { components: { Field: '@/components/DeviceCatalogTables' } },
    },
  ],
}
