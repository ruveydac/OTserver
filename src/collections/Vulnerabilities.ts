import type { CollectionConfig } from 'payload'

import { adminOnly, hideFromNonAdmins } from '../access/authorization'
import { checkOffline, feedControl, importOffline, refreshFeeds } from '../vulnerabilities/actions'

export const Vulnerabilities: CollectionConfig = {
  slug: 'vulnerabilities',
  access: {
    create: () => false,
    delete: () => false,
    read: ({ req }) => Boolean(req.user),
    update: () => false,
  },
  admin: {
    defaultColumns: ['cve', 'cvssSeverity', 'cvssScore', 'knownExploited', 'modified'],
    description:
      'Downloaded NVD, CSAF, CISA KEV, and ICS Advisory Project entries used for passive asset matching.',
    group: 'Vulnerabilities',
    hidden: true,
    listSearchableFields: ['cve', 'description', 'icsAdvisory'],
    useAsTitle: 'cve',
  },
  defaultSort: '-modified',
  disableBulkDelete: true,
  disableBulkEdit: true,
  fields: [
    { name: 'cve', type: 'text', index: true, label: 'CVE', required: true, unique: true },
    { name: 'description', type: 'textarea' },
    { name: 'cvssScore', type: 'number', label: 'CVSS score' },
    { name: 'cvssSeverity', type: 'text', index: true, label: 'CVSS severity' },
    { name: 'status', type: 'text', admin: { hidden: true }, label: 'NVD status' },
    { name: 'published', type: 'date' },
    { name: 'modified', type: 'date', index: true },
    { name: 'references', type: 'json' },
    { name: 'affected', type: 'json', label: 'Affected CPE matches' },
    { name: 'products', type: 'text', admin: { hidden: true }, hasMany: true, index: true },
    {
      name: 'productTokens',
      type: 'text',
      admin: { hidden: true },
      hasMany: true,
      index: true,
      label: 'Product tokens',
    },
    {
      name: 'knownExploited',
      type: 'checkbox',
      index: true,
      label: 'Known exploited (CISA KEV)',
    },
    { name: 'kevDateAdded', type: 'date', label: 'KEV date added' },
    { name: 'kevDueDate', type: 'date', label: 'KEV remediation due' },
    { name: 'kevName', type: 'text', label: 'KEV vulnerability name' },
    { name: 'kevProduct', type: 'text', label: 'KEV product' },
    { name: 'kevRequiredAction', type: 'textarea', label: 'KEV required action' },
    { name: 'kevRansomwareUse', type: 'text', label: 'KEV ransomware campaign use' },
    { name: 'kevVendor', type: 'text', label: 'KEV vendor/project' },
    {
      name: 'icsAdvisory',
      type: 'text',
      hasMany: true,
      index: true,
      label: 'CISA ICS advisory',
    },
    { name: 'icsSectors', type: 'text', hasMany: true, label: 'Critical infrastructure sectors' },
    { name: 'icsDistribution', type: 'text', label: 'ICS product distribution' },
    { name: 'icsHeadquarters', type: 'text', label: 'ICS vendor headquarters' },
  ],
  lockDocuments: false,
}

export const VulnerabilityFeeds: CollectionConfig = {
  slug: 'vulnerability-feeds',
  endpoints: [
    { path: '/control', method: 'get', handler: feedControl },
    { path: '/refresh', method: 'post', handler: refreshFeeds },
    { path: '/offline/check', method: 'post', handler: checkOffline },
    { path: '/offline/import', method: 'post', handler: importOffline },
  ],
  access: {
    create: () => false,
    delete: () => false,
    read: adminOnly,
    update: () => false,
  },
  admin: {
    components: { beforeList: ['@/components/VulnerabilityFeedActions'] },
    defaultColumns: ['source', 'status', 'lastSyncedAt', 'documentCount', 'error'],
    description:
      'Update the local vulnerability catalogs online or import original files transferred from a connected computer.',
    group: 'Vulnerabilities',
    hidden: hideFromNonAdmins,
    useAsTitle: 'source',
  },
  defaultSort: 'source',
  disableBulkDelete: true,
  disableBulkEdit: true,
  fields: [
    { name: 'source', type: 'text', index: true, required: true, unique: true },
    {
      name: 'status',
      type: 'select',
      defaultValue: 'idle',
      index: true,
      options: ['idle', 'queued', 'running', 'ready', 'partial', 'failed'],
      required: true,
    },
    { name: 'lastSyncedAt', type: 'date', label: 'Last synchronized' },
    { name: 'documentCount', type: 'number', label: 'Stored vulnerabilities' },
    { name: 'catalogVersion', type: 'text', label: 'Catalog version' },
    { name: 'dateReleased', type: 'date', label: 'Catalog released' },
    { name: 'error', type: 'textarea' },
    { name: 'state', type: 'json', admin: { hidden: true } },
    { name: 'jobID', type: 'text', admin: { readOnly: true } },
    {
      name: 'lastImportMethod',
      type: 'select',
      options: ['online', 'offline'],
      admin: { readOnly: true },
    },
    { name: 'operationRevision', type: 'number', admin: { hidden: true } },
  ],
  lockDocuments: false,
}
