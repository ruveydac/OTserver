import type {
  CollectionAfterChangeHook,
  CollectionConfig,
  RequiredDataFromCollectionSlug,
} from 'payload'

import {
  canCreateSiteDocument,
  canReadSiteDocuments,
  canWriteSiteDocuments,
  enforceWritableSite,
  filterWritableSites,
} from '../access/authorization'
import { userSuppliedAssetFields } from './Assets'
import { sanitizeCustomFieldValues } from './AssetFields'
import { parseNmap } from '../importers/nmap'
import { parseOTserverScanner } from '../importers/otserverScanner'
import { parseProneta } from '../importers/proneta'
import { mergeAssetData, type FieldProvenance } from '../importers/assetQuality'
import type { ImportResult } from '../importers/types'
import { importSourceOptions, importSourceQuality, type ImportSource } from '../importers/sources'

const parsers = {
  nmap: parseNmap,
  'otserver-scanner': parseOTserverScanner,
  proneta: parseProneta,
} satisfies Record<ImportSource, (input: string) => ImportResult>

export const getAssetOverrides = (value: unknown) => {
  const overrides = value && typeof value === 'object' ? (value as Record<string, unknown>) : {}

  return Object.fromEntries(
    userSuppliedAssetFields.flatMap(({ name }) => {
      const fieldValue = overrides[name]
      return typeof fieldValue === 'string' && fieldValue.trim() ? [[name, fieldValue.trim()]] : []
    }),
  )
}

const runImport: CollectionAfterChangeHook = async ({ context, doc, req }) => {
  if (context.skipAssetImport || !req.file) return doc

  let created = 0
  let updated = 0

  try {
    const contents = req.file.data.toString('utf8')
    const topology = parsers[doc.source as ImportSource](contents)
    const importedAt = new Date().toISOString()
    const site = typeof doc.site === 'object' ? doc.site?.id : doc.site
    const sourceVersion = topology.sourceVersion || doc.sourceVersion || 'unknown'
    const assetOverrides = getAssetOverrides(doc.assetOverrides)
    const customFieldOverrides =
      doc.customFieldOverrides &&
      typeof doc.customFieldOverrides === 'object' &&
      !Array.isArray(doc.customFieldOverrides)
        ? doc.customFieldOverrides
        : {}

    if (!site) throw new Error('Select a site before importing assets.')

    const assetIDs = new Map<string, string>()

    // ponytail: imports run synchronously and can be partial; move this loop to a queued
    // transaction if large production files make atomic imports necessary.
    for (const asset of topology.assets) {
      const { observations, ...assetData } = asset
      const existing = await req.payload.find({
        collection: 'assets',
        depth: 0,
        limit: 1,
        overrideAccess: false,
        req,
        where: { macAddress: { equals: asset.macAddress } },
      })
      const current = existing.docs[0] as unknown as Record<string, unknown> | undefined
      const automaticData = {
        ...(doc.source === 'proneta' ? { protocols: ['profinet'] } : {}),
        ...assetData,
      }
      const automaticGroups = observations?.length
        ? observations.map(({ fields, quality, source }) => ({ data: fields, quality, source }))
        : [
            {
              data: automaticData,
              quality: importSourceQuality[doc.source as ImportSource],
              source: doc.source,
            },
          ]
      const merged = mergeAssetData(current || {}, [
        ...automaticGroups,
        {
          data: { customFields: customFieldOverrides, site, ...assetOverrides },
          quality: 'human',
          source: 'human',
        },
      ])
      let assetID: string

      if (current && merged.changed) {
        await req.payload.update({
          collection: 'assets',
          context: { assetImport: true },
          data: {
            ...merged.data,
            fieldProvenance: merged.fieldProvenance,
            importSource: doc.source,
            lastImportedAt: importedAt,
            sourceVersion,
          },
          id: String(current.id),
          overrideAccess: false,
          req,
        })
        assetID = String(current.id)
        updated++
      } else if (!current) {
        const defaultProvenance: FieldProvenance = {
          assetClass: { quality: 'low', source: 'default' },
          criticality: { quality: 'low', source: 'default' },
          status: { quality: 'low', source: 'default' },
        }
        const createdAsset = await req.payload.create({
          collection: 'assets',
          context: { assetImport: true },
          // Payload applies field defaults, but its generated create type still marks them required.
          data: {
            ...merged.data,
            fieldProvenance: { ...defaultProvenance, ...merged.fieldProvenance },
            importSource: doc.source,
            lastImportedAt: importedAt,
            sourceVersion,
          } as RequiredDataFromCollectionSlug<'assets'>,
          overrideAccess: false,
          req,
        })
        assetID = String(createdAsset.id)
        created++
      } else {
        assetID = String(current.id)
      }
      assetIDs.set(asset.macAddress, assetID)

      for (const observation of observations || []) {
        await req.payload.create({
          collection: 'asset-observations',
          data: {
            asset: assetID,
            fields: observation.fields,
            import: doc.id,
            interfaces: observation.interfaces,
            observedAt: observation.observedAt,
            ports: observation.ports,
            quality: observation.quality === 'human' ? 'high' : observation.quality,
            raw: observation.raw === undefined ? null : JSON.parse(JSON.stringify(observation.raw)),
            site,
            source: observation.source,
            warnings: observation.warnings,
          },
          overrideAccess: true,
          req,
        })
      }
    }

    const findAssetID = async (endpoint: Record<string, unknown>) => {
      const macAddress = typeof endpoint.macAddress === 'string' ? endpoint.macAddress : ''
      if (!macAddress) return undefined
      if (assetIDs.has(macAddress)) return assetIDs.get(macAddress)
      const result = await req.payload.find({
        collection: 'assets',
        depth: 0,
        limit: 1,
        overrideAccess: false,
        req,
        where: { and: [{ macAddress: { equals: macAddress } }, { site: { equals: site } }] },
      })
      return result.docs[0] ? String(result.docs[0].id) : undefined
    }

    for (const link of topology.links || []) {
      await req.payload.create({
        collection: 'topology-links',
        data: {
          import: doc.id,
          local: link.local,
          localAsset: await findAssetID(link.local),
          observedAt: link.observedAt,
          raw: link.raw === undefined ? null : JSON.parse(JSON.stringify(link.raw)),
          remote: link.remote,
          remoteAsset: await findAssetID(link.remote),
          site,
          source: link.source,
        },
        overrideAccess: true,
        req,
      })
    }

    context.skipAssetImport = true
    return req.payload.update({
      collection: 'asset-imports',
      data: {
        createdAssets: created,
        error: null,
        projectName: topology.projectName,
        scanMetadata: topology.scanMetadata,
        skippedAssets: topology.warnings.length + (topology.unresolved?.length || 0),
        sourceVersion,
        status: 'completed',
        topologyName: topology.topologyName,
        unresolved: topology.unresolved,
        updatedAssets: updated,
        warnings:
          [
            ...topology.warnings,
            ...(topology.unresolved?.length
              ? [
                  `${topology.unresolved.length} observation(s) could not be correlated by MAC address.`,
                ]
              : []),
          ].join('\n') || null,
      },
      id: doc.id,
      overrideAccess: false,
      req,
    })
  } catch (error) {
    context.skipAssetImport = true
    return req.payload.update({
      collection: 'asset-imports',
      data: {
        createdAssets: created,
        error: error instanceof Error ? error.message : 'Import failed.',
        status: 'failed',
        updatedAssets: updated,
      },
      id: doc.id,
      overrideAccess: false,
      req,
    })
  }
}

export const AssetImports: CollectionConfig = {
  slug: 'asset-imports',
  labels: {
    plural: 'Imports',
    singular: 'Import',
  },
  access: {
    create: canCreateSiteDocument,
    delete: canWriteSiteDocuments,
    read: canReadSiteDocuments,
    update: canWriteSiteDocuments,
  },
  admin: {
    defaultColumns: [
      'filename',
      'site',
      'source',
      'sourceVersion',
      'status',
      'createdAssets',
      'updatedAssets',
      'skippedAssets',
    ],
    description: 'Upload discovery files to create or update assets by MAC address.',
    group: 'OT Inventory',
    useAsTitle: 'filename',
  },
  fields: [
    {
      name: 'site',
      type: 'relationship',
      admin: { description: 'Every asset in this file will be assigned to this site.' },
      filterOptions: filterWritableSites,
      index: true,
      relationTo: 'sites',
      required: true,
    },
    {
      name: 'source',
      type: 'select',
      defaultValue: 'otserver-scanner',
      options: importSourceOptions,
      required: true,
    },
    {
      name: 'importInstructions',
      type: 'ui',
      admin: { components: { Field: '@/components/ImportInstructions' } },
    },
    {
      name: 'assetOverrides',
      type: 'group',
      admin: {
        description:
          'Optional values overwrite these fields on every new or existing asset in this import.',
      },
      fields: userSuppliedAssetFields.map(({ label, name, placeholder }) => ({
        name,
        type: 'text' as const,
        admin: { placeholder },
        label,
      })),
      label: 'Apply to imported assets',
    },
    {
      name: 'customFieldOverrides',
      type: 'json',
      admin: { components: { Field: '@/components/CustomAssetFields' } },
      label: 'Custom field overrides',
    },
    {
      name: 'sourceVersion',
      type: 'text',
      defaultValue: 'unknown',
      label: 'Scanner version',
      required: true,
    },
    {
      name: 'status',
      type: 'select',
      admin: { position: 'sidebar', readOnly: true },
      defaultValue: 'pending',
      options: [
        { label: 'Pending', value: 'pending' },
        { label: 'Completed', value: 'completed' },
        { label: 'Failed', value: 'failed' },
      ],
      required: true,
    },
    {
      type: 'row',
      fields: [
        {
          name: 'createdAssets',
          type: 'number',
          admin: { readOnly: true, width: '33.33%' },
          defaultValue: 0,
          label: 'Created',
        },
        {
          name: 'updatedAssets',
          type: 'number',
          admin: { readOnly: true, width: '33.33%' },
          defaultValue: 0,
          label: 'Updated',
        },
        {
          name: 'skippedAssets',
          type: 'number',
          admin: { readOnly: true, width: '33.33%' },
          defaultValue: 0,
          label: 'Skipped',
        },
      ],
    },
    {
      name: 'projectName',
      type: 'text',
      admin: { readOnly: true },
      label: 'Project name',
    },
    {
      name: 'topologyName',
      type: 'text',
      admin: { readOnly: true },
      label: 'Topology name',
    },
    {
      name: 'warnings',
      type: 'textarea',
      admin: { readOnly: true },
    },
    {
      name: 'scanMetadata',
      type: 'json',
      admin: { readOnly: true },
      label: 'Scan metadata',
    },
    {
      name: 'unresolved',
      type: 'json',
      admin: { readOnly: true },
      label: 'Unresolved observations',
    },
    {
      name: 'error',
      type: 'textarea',
      admin: { readOnly: true },
    },
  ],
  hooks: {
    afterChange: [runImport],
    beforeChange: [enforceWritableSite, sanitizeCustomFieldValues],
  },
  upload: {
    bulkUpload: false,
    mimeTypes: ['application/json', 'application/xml', 'text/json', 'text/plain', 'text/xml'],
    pasteURL: false,
    staticDir: 'import-files',
  },
}
