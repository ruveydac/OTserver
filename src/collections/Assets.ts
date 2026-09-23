import { normalizeMAC, validateIPAddress, validateMACAddress } from '../domain/network'
export { normalizeMAC, validateIPAddress, validateMACAddress } from '../domain/network'

import type { CollectionBeforeChangeHook, CollectionConfig } from 'payload'

import {
  canCreateSiteDocument,
  canReadSiteDocuments,
  canWriteSiteDocuments,
  enforceWritableSite,
  filterWritableSites,
} from '../access/authorization'
import { applyAssetSearch } from '../search/assetLucene'
import { trackHumanAssetChanges } from '../importers/assetQuality'
import { assignDefaultAssetClass } from './AssetClasses'
import { exportAssetsCSV } from './AssetExport'
import { sanitizeCustomFieldValues } from './AssetFields'
import { assignVulnerabilityCount } from '../vulnerabilities/match'
import { randomUUID } from 'node:crypto'
import { protectAssetIdentity, syncManualEndpoint } from '../identity/relationships'
import { identityAction, migrateIdentity } from '../identity/actions'

import { userSuppliedAssetFields } from '../domain/assetFields'
export { userSuppliedAssetFields } from '../domain/assetFields'

const recordHumanChanges: CollectionBeforeChangeHook = ({ context, data, originalDoc, req }) => {
  if (
    context.assetImport ||
    context.assetClassMigration ||
    context.vulnerabilityCountSync ||
    context.networkProjection ||
    context.identityAction
  )
    return data

  const tracked = trackHumanAssetChanges(data, originalDoc)
  const ruleAssignment = context.assetClassRuleAssignment || req.context.assetClassRuleAssignment
  const defaultAssignment =
    context.assetClassDefaultAssignment || req.context.assetClassDefaultAssignment
  if (ruleAssignment || defaultAssignment) {
    const fieldProvenance =
      tracked.fieldProvenance &&
      typeof tracked.fieldProvenance === 'object' &&
      !Array.isArray(tracked.fieldProvenance)
        ? { ...(tracked.fieldProvenance as Record<string, unknown>) }
        : {}
    fieldProvenance.assetClass = ruleAssignment
      ? { quality: 'medium', source: 'asset-class-rule' }
      : { quality: 'low', source: 'default' }
    tracked.fieldProvenance = fieldProvenance
  }
  return tracked
}

export const Assets: CollectionConfig = {
  slug: 'assets',
  labels: {
    plural: 'Assets',
    singular: 'Asset',
  },
  trash: true,
  access: {
    create: canCreateSiteDocument,
    delete: canWriteSiteDocuments,
    read: canReadSiteDocuments,
    update: canWriteSiteDocuments,
  },
  admin: {
    components: {
      beforeListTable: ['@/components/AssetListInteractions'],
      views: {
        edit: {
          default: { Component: '@/components/AssetView' },
          edit: { Component: '@payloadcms/ui#DefaultEditView', path: '/edit' },
          vulnerabilities: {
            Component: '@/components/AssetVulnerabilitiesView',
            path: '/vulnerabilities',
          },
        },
      },
    },
    defaultColumns: ['name', 'site', 'status', 'ipAddress', 'macAddress', 'assetClass'],
    description: 'Industrial devices, network endpoints, and control-system equipment.',
    group: 'OT Inventory',
    listSearchableFields: [],
    useAsTitle: 'name',
  },
  defaultSort: 'name',
  endpoints: [
    { handler: identityAction, method: 'post', path: '/:id/identity' },
    { handler: migrateIdentity, method: 'post', path: '/migrate-identity' },
    {
      handler: exportAssetsCSV,
      method: 'get',
      path: '/export-csv',
    },
  ],
  fields: [
    {
      name: 'identityRevision',
      type: 'number',
      defaultValue: 0,
      admin: { hidden: true },
      access: { create: () => false, update: () => false },
    },
    {
      name: 'uuid',
      type: 'text',
      unique: true,
      index: true,
      defaultValue: randomUUID,
      access: { create: () => false, update: () => false },
      admin: { readOnly: true },
    },
    {
      name: 'physicalKind',
      type: 'select',
      defaultValue: 'unknown',
      options: ['unknown', 'device', 'chassis', 'module'],
    },
    { name: 'catalogNumber', type: 'text', label: 'Catalog / part number' },
    { name: 'slotCapacity', type: 'number', min: 0, max: 65536 },
    {
      name: 'lifecycle',
      type: 'select',
      defaultValue: 'active',
      options: ['active', 'retired', 'replaced', 'merged'],
      index: true,
      admin: { readOnly: true, position: 'sidebar' },
    },
    { name: 'baselined', type: 'checkbox', defaultValue: false, admin: { position: 'sidebar' } },
    { name: 'mergedInto', type: 'relationship', relationTo: 'assets', admin: { readOnly: true } },
    { name: 'replacedBy', type: 'relationship', relationTo: 'assets', admin: { readOnly: true } },
    {
      name: 'networkAddresses',
      type: 'array',
      admin: { hidden: true },
      fields: [{ name: 'address', type: 'text', index: true, required: true }],
    },
    {
      name: 'networkMACs',
      type: 'array',
      admin: { hidden: true },
      fields: [{ name: 'address', type: 'text', index: true, required: true }],
    },
    {
      name: 'name',
      type: 'text',
      required: true,
    },
    {
      name: 'description',
      type: 'textarea',
    },
    {
      name: 'site',
      type: 'relationship',
      admin: { description: 'The site or hierarchy node this asset belongs to.' },
      filterOptions: filterWritableSites,
      index: true,
      relationTo: 'sites',
      required: true,
    },
    {
      type: 'row',
      fields: [
        {
          name: 'assetClass',
          type: 'relationship',
          admin: { width: '33.33%' },
          index: true,
          label: 'Asset class',
          relationTo: 'asset-classes',
          required: true,
        },
        ...userSuppliedAssetFields.map(({ label, name, placeholder }) => ({
          name,
          type: 'text' as const,
          admin: { placeholder, width: '33.33%' },
          label,
        })),
      ],
    },
    {
      name: 'customFields',
      type: 'json',
      admin: {
        components: { Field: '@/components/CustomAssetFields' },
        disableListFilter: true,
      },
      label: 'Custom fields',
    },
    {
      name: 'fieldProvenance',
      type: 'json',
      admin: { hidden: true },
    },
    {
      name: 'assetType',
      type: 'text',
      admin: { hidden: true },
      label: 'Legacy asset type',
    },
    {
      type: 'row',
      fields: [
        {
          name: 'ipAddress',
          type: 'text',
          admin: {
            placeholder: '192.168.10.42',
            width: '50%',
          },
          hooks: {
            beforeValidate: [({ value }) => value?.trim()],
          },
          index: true,
          label: 'IP address',
          validate: validateIPAddress,
        },
        {
          name: 'macAddress',
          type: 'text',
          admin: {
            placeholder: '00:1A:2B:3C:4D:5E',
            width: '50%',
          },
          hooks: {
            beforeValidate: [({ value }) => (value ? normalizeMAC(value) : value)],
          },
          index: true,
          label: 'MAC address',
          validate: validateMACAddress,
        },
      ],
    },
    {
      type: 'row',
      fields: [
        {
          name: 'networkMask',
          type: 'text',
          admin: { width: '50%' },
          label: 'Network mask',
          validate: validateIPAddress,
        },
        {
          name: 'gatewayAddress',
          type: 'text',
          admin: { width: '50%' },
          label: 'Gateway address',
          validate: validateIPAddress,
        },
      ],
    },
    {
      type: 'row',
      fields: [
        {
          name: 'vendor',
          type: 'text',
          admin: { width: '33.33%' },
        },
        {
          name: 'model',
          type: 'text',
          admin: { width: '33.33%' },
        },
        {
          name: 'serialNumber',
          type: 'text',
          admin: { width: '33.33%' },
          label: 'Serial number',
        },
      ],
    },
    {
      name: 'operatingSystem',
      type: 'text',
      label: 'Operating system',
    },
    {
      name: 'osAccuracy',
      type: 'number',
      admin: { description: 'Confidence reported by the discovery source, from 0 to 100.' },
      label: 'OS detection confidence (%)',
      max: 100,
      min: 0,
    },
    {
      name: 'firmwareVersion',
      type: 'text',
      admin: { position: 'sidebar' },
      label: 'Firmware version',
    },
    {
      name: 'hardwareVersion',
      type: 'text',
      admin: { position: 'sidebar' },
      label: 'Hardware version',
    },
    {
      name: 'protocols',
      type: 'select',
      hasMany: true,
      options: [
        { label: 'BACnet', value: 'bacnet' },
        { label: 'DNP3', value: 'dnp3' },
        { label: 'EtherNet/IP', value: 'ethernet-ip' },
        { label: 'IEC 61850', value: 'iec61850' },
        { label: 'Modbus TCP', value: 'modbus-tcp' },
        { label: 'NetBIOS', value: 'netbios' },
        { label: 'Niagara Fox', value: 'niagara-fox' },
        { label: 'Omron FINS', value: 'omron-fins' },
        { label: 'PROFINET', value: 'profinet' },
        { label: 'OPC UA', value: 'opc-ua' },
        { label: 'S7', value: 's7' },
        { label: 'Other', value: 'other' },
      ],
    },
    {
      name: 'status',
      type: 'select',
      admin: { position: 'sidebar' },
      defaultValue: 'unknown',
      index: true,
      options: [
        { label: 'Online', value: 'online' },
        { label: 'Offline', value: 'offline' },
        { label: 'Maintenance', value: 'maintenance' },
        { label: 'Unknown', value: 'unknown' },
      ],
      required: true,
    },
    {
      name: 'criticality',
      type: 'select',
      admin: { position: 'sidebar' },
      defaultValue: 'medium',
      index: true,
      options: [
        { label: 'Low', value: 'low' },
        { label: 'Medium', value: 'medium' },
        { label: 'High', value: 'high' },
        { label: 'Critical', value: 'critical' },
      ],
      required: true,
    },
    {
      name: 'vulnerabilityCount',
      type: 'number',
      access: {
        create: () => false,
        update: () => false,
      },
      admin: {
        description:
          'Unvalidated catalog matches for the recorded vendor, model, and version data. Empty until the vulnerability catalog is loaded.',
        position: 'sidebar',
        readOnly: true,
      },
      index: true,
      label: 'Known vulnerabilities',
    },
    {
      name: 'lastSeen',
      type: 'date',
      admin: {
        date: { pickerAppearance: 'dayAndTime' },
        position: 'sidebar',
      },
      label: 'Last seen',
      index: true,
    },
    {
      name: 'importSource',
      type: 'text',
      admin: { position: 'sidebar' },
      label: 'Import source',
    },
    {
      name: 'sourceVersion',
      type: 'text',
      admin: { position: 'sidebar' },
      label: 'Source version',
    },
    {
      name: 'lastImportedAt',
      type: 'date',
      admin: {
        date: { pickerAppearance: 'dayAndTime' },
        position: 'sidebar',
      },
      label: 'Last imported',
    },
    {
      name: 'notes',
      type: 'textarea',
    },
  ],
  hooks: {
    beforeValidate: [assignDefaultAssetClass],
    // assignVulnerabilityCount runs last so the derived count never enters field provenance.
    beforeChange: [
      enforceWritableSite,
      protectAssetIdentity,
      sanitizeCustomFieldValues,
      recordHumanChanges,
      assignVulnerabilityCount,
    ],
    beforeOperation: [applyAssetSearch],
    afterChange: [syncManualEndpoint],
  },
  indexes: [{ fields: ['site', 'status'] }, { fields: ['site', 'assetClass'] }],
  timestamps: true,
}
