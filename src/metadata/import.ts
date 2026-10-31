import { isDeepStrictEqual } from 'node:util'
import { APIError, type PayloadHandler, type PayloadRequest } from 'payload'
import Ajv2020 from 'ajv/dist/2020'
import addFormats from 'ajv-formats'
import manufacturersSchema from '../data/device-metadata/schema/ot-manufacturers.schema.json'
import devicesSchema from '../data/device-metadata/schema/ot-devices.schema.json'
import groupsSchema from '../data/device-metadata/schema/ot-device-types.schema.json'
import { getAuthorization } from '../access/authorization'
import { inTransaction } from '../integrations/payload/transactions'
import { createCatalogMatcher, type Catalog } from './catalog'
import { activeCatalog, catalogRevision } from './runtime'

export const MAX_METADATA_BYTES = 8 * 1024 * 1024
const ajv = new Ajv2020({ allErrors: false })
addFormats(ajv)
ajv.addSchema(groupsSchema)
const validateManufacturers = ajv.compile(manufacturersSchema)
const validateDevices = ajv.compile(devicesSchema)
const object = (value: unknown): value is Record<string, unknown> =>
  Boolean(value && typeof value === 'object' && !Array.isArray(value))
const isManagementRuleExport = (value: unknown) =>
  object(value) &&
  value.version === 1 &&
  Array.isArray(value.classes) &&
  object(value.coverage) &&
  Array.isArray(value.coverage.included) &&
  Array.isArray(value.coverage.skipped) &&
  typeof value.catalogSha256 === 'string'

const isManagementRuleExportFile = (name: string, content: unknown) =>
  name.split(/[\\/]/).at(-1)?.toLowerCase() === 'management-asset-class-rules.json' ||
  isManagementRuleExport(content)

export const mergeMetadataFiles = (current: Catalog, input: unknown) => {
  if (!Array.isArray(input) || !input.length || input.length > 50)
    throw new APIError('Select between 1 and 50 JSON files.', 400)
  if (Buffer.byteLength(JSON.stringify(input)) > MAX_METADATA_BYTES)
    throw new APIError('Selected JSON exceeds 8 MiB.', 413)
  const additions: Catalog = { manufacturers: [], devices: [], groups: current.groups }
  for (const file of input) {
    if (!object(file) || typeof file.name !== 'string' || file.name.length > 255)
      throw new APIError('Each file needs a name and JSON content.', 400)
    if (isManagementRuleExportFile(file.name, file.content))
      throw new APIError(
        `${file.name}: this is a separate Asset class rule export, not manufacturer/device catalog data. This importer does not apply it; select only manufacturer and device catalog JSON files. No records were changed.`,
        400,
      )
    const entries = Array.isArray(file.content) ? file.content : [file.content]
    if (!entries.length) throw new APIError(`${file.name}: no records found.`, 400)
    for (const entry of entries) {
      const device = object(entry) && Object.hasOwn(entry, 'manufacturer_id')
      const validate = device ? validateDevices : validateManufacturers
      if (!validate([entry]))
        throw new APIError(`${file.name}: ${ajv.errorsText(validate.errors)}.`, 400)
      const row = structuredClone(entry) as Catalog['devices'][number] &
        Catalog['manufacturers'][number]
      row.id = row.id.toLowerCase()
      if (device) {
        row.manufacturer_id = row.manufacturer_id.toLowerCase()
        row.device_type_id = row.device_type_id.toLowerCase()
      }
      const target = device ? additions.devices : additions.manufacturers
      const duplicate = target.find(({ id }) => id === row.id)
      if (duplicate && !isDeepStrictEqual(duplicate, row))
        throw new APIError(`${file.name}: conflicting duplicate ID ${row.id}.`, 400)
      if (!duplicate) target.push(row)
    }
  }
  const counts = {
    manufacturers: { added: 0, updated: 0, unchanged: 0 },
    devices: { added: 0, updated: 0, unchanged: 0 },
  }
  const merge = <T extends { id: string }>(
    rows: T[],
    incoming: T[],
    totals: typeof counts.devices,
  ) => {
    const merged = new Map(rows.map((row) => [row.id.toLowerCase(), row]))
    for (const row of incoming) {
      const before = merged.get(row.id)
      if (!before) totals.added++
      else if (isDeepStrictEqual(before, row)) {
        totals.unchanged++
        continue
      } else totals.updated++
      merged.set(row.id, row)
    }
    return [...merged.values()]
  }
  const catalog: Catalog = {
    manufacturers: merge(current.manufacturers, additions.manufacturers, counts.manufacturers),
    devices: merge(current.devices, additions.devices, counts.devices),
    groups: current.groups,
  }
  // shortcut: a 6 MiB snapshot keeps before/after audit records below MongoDB's limit; split storage if it outgrows this.
  if (Buffer.byteLength(JSON.stringify(catalog)) > 6 * 1024 * 1024)
    throw new APIError('The resulting catalog exceeds the 6 MiB storage limit.', 413)
  try {
    createCatalogMatcher(catalog, 'validation')
  } catch (error) {
    throw new APIError(
      `Invalid combined catalog: ${error instanceof Error ? error.message.split('\n')[0] : 'invalid recognition rules'}`,
      400,
    )
  }
  return { catalog, counts }
}

export const importMetadata = async (req: PayloadRequest, files: unknown) => {
  if (!(await getAuthorization(req)).isAdmin)
    throw new APIError('Administrator access required.', 403)
  try {
    return await inTransaction(req, async () => {
      const current = await activeCatalog(req.payload, req)
      const merged = mergeMetadataFiles(current.catalog, files)
      const changed = Object.values(merged.counts).some(({ added, updated }) => added || updated)
      if (!changed) return { ...merged.counts, revision: current.revision, changed: false }
      const revision = catalogRevision(merged.catalog)
      const data = {
        revision,
        catalog: merged.catalog,
        manufacturerCount: merged.catalog.manufacturers.length,
        deviceCount: merged.catalog.devices.length,
      }
      const existing = await req.payload.find({
        collection: 'device-catalog',
        where: { id: { equals: 'active' } },
        limit: 1,
        depth: 0,
        overrideAccess: true,
        req,
      })
      // Generic catalog mutations are denied; only this validated administrator action writes it.
      if (existing.docs.length)
        await req.payload.update({
          collection: 'device-catalog',
          id: 'active',
          data,
          overrideAccess: true,
          req,
        })
      else
        await req.payload.create({
          collection: 'device-catalog',
          data: { id: 'active', ...data },
          overrideAccess: true,
          req,
        })
      await req.payload.jobs.queue({
        task: 'reapply-asset-classes-v1',
        queue: 'maintenance',
        req,
        input: { version: 1, assetClassID: 'device-catalog', catalogRevision: revision },
      })
      return { ...merged.counts, revision, changed: true }
    })
  } catch (error) {
    if ((error as { code?: number }).code === 11000 || (error as { code?: number }).code === 112)
      throw new APIError(
        'The catalog changed during import. Retry your files against the latest catalog.',
        409,
      )
    throw error
  }
}

export const importMetadataEndpoint: PayloadHandler = async (req) => {
  if (!(await getAuthorization(req)).isAdmin)
    throw new APIError('Administrator access required.', 403)
  if (req.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json')
    throw new APIError('Send the selected files as application/json.', 415)
  const reader = (req as Request).body?.getReader()
  if (!reader) throw new APIError('A JSON request body is required.', 400)
  const chunks: Uint8Array[] = []
  let bytes = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    bytes += value.byteLength
    if (bytes > MAX_METADATA_BYTES + 64 * 1024) {
      await reader.cancel()
      throw new APIError('Selected JSON exceeds 8 MiB.', 413)
    }
    chunks.push(value)
  }
  let data: unknown
  try {
    data = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    throw new APIError('Invalid JSON request.', 400)
  }
  return Response.json(await importMetadata(req, object(data) ? data.files : undefined), {
    headers: { 'Cache-Control': 'no-store' },
  })
}
