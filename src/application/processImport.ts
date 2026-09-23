import type { PayloadRequest, RequiredDataFromCollectionSlug } from 'payload'
import type { AssetImport } from '../payload-types'

import { userSuppliedAssetFields } from '../domain/assetFields'
import { parseNmap } from '../importers/nmap'
import { parseOTserverOtter } from '../importers/otserverOtter'
import { parseProneta } from '../importers/proneta'
import { mergeAssetData, type FieldProvenance } from '../importers/assetQuality'
import type { ImportResult } from '../importers/types'
import { importSources, type ImportSource } from '../importers/sources'
import { createHash } from 'node:crypto'
import { idOf, requireTransaction } from '../identity/access'
import {
  bindImportedIdentity,
  descriptiveFields,
  importObservedAt,
  recordContainment,
  resolveImportedIdentity,
  suggestAdjacentInterfaces,
  suggestAttachmentChange,
} from '../identity/reconcile'
import { scopedKey } from '../identity/keys'

const parsers = {
  nmap: parseNmap,
  'otserver-otter': parseOTserverOtter,
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

export const processImport = async ({
  doc,
  data,
  req,
  throwValidationErrors = false,
}: {
  doc: AssetImport
  data: Buffer
  req: PayloadRequest
  throwValidationErrors?: boolean
}): Promise<AssetImport> => {
  const context = req.context

  const startedAt = Date.now()
  let created = 0
  let updated = 0
  let mutating = false

  try {
    const contents = data.toString('utf8')
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
    if (topology.assets.length + (topology.links?.length || 0) > 2000)
      throw new Error(
        'Identity imports are limited to 2000 device/component/link records per transaction. Split this file into smaller scans.',
      )
    await requireTransaction(req)
    mutating = true
    req.context.assetImport = true
    req.context.identityImportSource = doc.source
    const appliedKey = scopedKey(
      'import-v1',
      site,
      doc.source,
      createHash('sha256').update(contents).digest('hex'),
      assetOverrides,
      customFieldOverrides,
    )
    const replay = await req.payload.find({
      collection: 'asset-imports',
      depth: 0,
      limit: 1,
      where: { appliedKey: { equals: appliedKey } },
      // The key contains the exact site and immutable processing inputs. It is concealed from API
      // readers, so this narrowly scoped internal lookup must bypass field query visibility.
      overrideAccess: true,
      req,
    })
    if (replay.docs[0]) {
      context.skipAssetImport = true
      return req.payload.update({
        collection: 'asset-imports',
        id: doc.id,
        overrideAccess: false,
        req,
        context: { skipAssetImport: true },
        data: {
          status: 'completed',
          duplicateOf: replay.docs[0].id,
          createdAssets: 0,
          updatedAssets: 0,
          warnings: 'This exact import and its overrides were already applied.',
        },
      })
    }

    const assetIDs = new Map<string, string>()
    const componentIDs = new Map<string, string>()

    // Keep each synchronous or queued import in one bounded transaction.
    for (const asset of topology.assets) {
      const { observations, ...assetData } = asset
      const resolution = await resolveImportedIdentity(asset, String(site), req)
      const current = resolution.current
      const observedAt = importObservedAt(asset, importedAt)
      if (resolution.unresolved) {
        topology.unresolved ||= []
        topology.unresolved.push({ reason: 'Identity requires reconciliation', observations })
        continue
      }
      const automaticData = {
        ...(doc.source === 'proneta' ? { protocols: ['profinet'] } : {}),
        ...assetData,
      }
      const automaticGroups = observations?.length
        ? observations.map(({ fields, mergeFields, quality, source }) => ({
            data: descriptiveFields(mergeFields || fields),
            quality,
            source,
          }))
        : [
            {
              data: descriptiveFields(automaticData),
              quality: importSources.find((s) => s.value === doc.source)?.quality || 'low',
              source: doc.source,
            },
          ]
      const stale = Boolean(current?.lastSeen && observedAt < current.lastSeen)
      const merged = mergeAssetData((current || {}) as unknown as Record<string, unknown>, [
        ...(resolution.suppressFields
          ? []
          : automaticGroups.map((group) => ({
              ...group,
              data: stale
                ? Object.fromEntries(
                    Object.entries(group.data).filter(
                      ([key]) =>
                        key === 'protocols' ||
                        !(current as unknown as Record<string, unknown>)[key],
                    ),
                  )
                : group.data,
            }))),
        {
          data: {
            customFields: customFieldOverrides,
            ...(!current ? { site } : {}),
            ...assetOverrides,
          },
          quality: 'human',
          source: 'human',
        },
      ])
      if (!current) merged.data.name ||= asset.name || asset.identity?.serial
      if (!current?.lastSeen || observedAt > current.lastSeen) {
        merged.data.lastSeen = observedAt
        merged.changed = true
      }
      if (asset.identity && !current) {
        merged.data.physicalKind =
          asset.identity.scope === 'chassis'
            ? 'chassis'
            : asset.observedViaMAC
              ? 'module'
              : 'device'
        merged.data.serialNumber = asset.identity.serial
      }
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
      const resolved = await req.payload.findByID({
        collection: 'assets',
        id: assetID,
        depth: 0,
        overrideAccess: false,
        req,
      })
      const endpoints = await bindImportedIdentity(
        asset,
        resolved,
        String(site),
        observedAt,
        resolution.blocked || stale,
        resolution.endpointAsset,
        req,
      )
      if (asset.macAddress && !resolution.blocked) assetIDs.set(asset.macAddress, assetID)
      if (asset.componentRef) componentIDs.set(asset.componentRef, assetID)
      if (!current && asset.macAddress && !asset.identity)
        await suggestAdjacentInterfaces(resolved, asset.macAddress, req)

      for (const observation of observations || []) {
        await req.payload.create({
          collection: 'asset-observations',
          data: {
            asset: assetID,
            endpoint: endpoints[0]?.id,
            identityEvidence: asset.identity,
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

    for (const asset of topology.assets) {
      const id = asset.componentRef && componentIDs.get(asset.componentRef)
      const parent = asset.parentComponentRef && componentIDs.get(asset.parentComponentRef)
      if (id && parent)
        await recordContainment(
          asset,
          id,
          parent,
          String(site),
          importObservedAt(asset, importedAt),
          req,
        )
    }

    const findAssetID = async (endpoint: Record<string, unknown>) => {
      const macAddress = typeof endpoint.macAddress === 'string' ? endpoint.macAddress : ''
      if (!macAddress) return undefined
      if (assetIDs.has(macAddress)) return assetIDs.get(macAddress)
      const result = await req.payload.find({
        collection: 'network-endpoints',
        depth: 0,
        limit: 1,
        overrideAccess: false,
        req,
        where: {
          and: [
            { macAddress: { equals: macAddress } },
            { site: { equals: site } },
            { endedAt: { exists: false } },
          ],
        },
      })
      return idOf(result.docs[0]?.asset) || undefined
    }

    for (const link of topology.links || []) {
      const localAsset = await findAssetID(link.local)
      const remoteAsset = await findAssetID(link.remote)
      if (localAsset && remoteAsset && typeof link.local.portId === 'string')
        await suggestAttachmentChange(
          String(site),
          localAsset,
          remoteAsset,
          link.local.portId,
          link.observedAt,
          req,
        )
      await req.payload.create({
        collection: 'topology-links',
        data: {
          import: doc.id,
          local: link.local,
          localAsset,
          observedAt: link.observedAt,
          raw: link.raw === undefined ? null : JSON.parse(JSON.stringify(link.raw)),
          remote: link.remote,
          remoteAsset,
          site,
          source: link.source,
        },
        overrideAccess: true,
        req,
      })
    }

    const durationSeconds = (Date.now() - startedAt) / 1000
    const warnings = [
      ...topology.warnings,
      ...(topology.unresolved?.length
        ? [`${topology.unresolved.length} observation(s) require identity reconciliation.`]
        : []),
      ...(durationSeconds > 30 ? [`Import took ${durationSeconds.toFixed(1)} seconds.`] : []),
    ]

    if (durationSeconds > 30) {
      console.warn(`Import ${doc.id} took ${durationSeconds.toFixed(1)} seconds.`)
    }

    context.skipAssetImport = true
    context.appliedImportKey = appliedKey
    return req.payload.update({
      collection: 'asset-imports',
      context: { skipAssetImport: true, appliedImportKey: appliedKey },
      data: {
        createdAssets: created,
        appliedKey,
        error: null,
        projectName: topology.projectName,
        scanMetadata: topology.scanMetadata,
        skippedAssets:
          topology.warnings.length +
          (doc.source === 'otserver-otter' ? topology.unresolved?.length || 0 : 0),
        sourceVersion,
        status: 'completed',
        topologyName: topology.topologyName,
        unresolved: topology.unresolved,
        updatedAssets: updated,
        warnings: warnings.join('\n') || null,
      },
      id: doc.id,
      overrideAccess: false,
      req,
    })
  } catch (error) {
    if (!throwValidationErrors) req.payload.logger.error(error)
    // A write failure must escape the hook so Payload rolls back the entire inventory transaction.
    if (mutating || throwValidationErrors) throw error
    context.skipAssetImport = true
    return req.payload.update({
      collection: 'asset-imports',
      context: { skipAssetImport: true },
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
