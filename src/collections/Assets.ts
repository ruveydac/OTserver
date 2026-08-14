import { isIP } from 'node:net'

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
import { sanitizeCustomFieldValues } from './AssetFields'

const macAddressPattern = /^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$/

export const normalizeMAC = (value: string): string =>
  value.trim().replaceAll('-', ':').toUpperCase()

export const validateIPAddress = (value: null | string | undefined): string | true =>
  !value || isIP(value.trim()) !== 0 || 'Enter a valid IPv4 or IPv6 address.'

export const validateMACAddress = (value: null | string | undefined): string | true =>
  !value || macAddressPattern.test(normalizeMAC(value)) || 'Enter a valid MAC address.'

export const userSuppliedAssetFields = [
  {
    label: 'Asset owner',
    name: 'assetOwner',
    placeholder: 'Operations team or responsible person',
  },
  {
    label: 'Physical location',
    name: 'location',
    placeholder: 'Building / room / cabinet',
  },
] as const

const recordHumanChanges: CollectionBeforeChangeHook = ({ context, data, originalDoc, req }) => {
  if (context.assetImport || context.assetClassMigration) return data

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
  fields: [
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
          required: true,
          unique: true,
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
      name: 'protocols',
      type: 'select',
      hasMany: true,
      options: [
        { label: 'BACnet', value: 'bacnet' },
        { label: 'EtherNet/IP', value: 'ethernet-ip' },
        { label: 'Modbus TCP', value: 'modbus-tcp' },
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
    beforeChange: [enforceWritableSite, sanitizeCustomFieldValues, recordHumanChanges],
    beforeOperation: [applyAssetSearch],
  },
  indexes: [{ fields: ['site', 'status'] }, { fields: ['site', 'assetClass'] }],
  timestamps: true,
}
