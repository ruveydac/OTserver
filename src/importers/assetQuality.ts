import { isDeepStrictEqual } from 'node:util'

export type DataQuality = 'high' | 'human' | 'low' | 'medium'
export type FieldProvenance = Record<string, { quality: DataQuality; source: string }>

export type IncomingAssetData = {
  data: Record<string, unknown>
  quality: DataQuality
  source: string
}

const rank: Record<DataQuality, number> = { low: 0, medium: 1, high: 2, human: 3 }
const qualities = new Set<DataQuality>(['low', 'medium', 'high', 'human'])

const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}

const provenance = (value: unknown): FieldProvenance =>
  Object.fromEntries(
    Object.entries(record(value)).flatMap(([field, origin]) => {
      const item = record(origin)
      return typeof item.source === 'string' && qualities.has(item.quality as DataQuality)
        ? [[field, { quality: item.quality as DataQuality, source: item.source }]]
        : []
    }),
  )

const empty = (value: unknown) =>
  value === null || value === undefined || value === '' || (Array.isArray(value) && !value.length)

export const mergeAssetData = (
  existing: Record<string, unknown>,
  incoming: IncomingAssetData[],
) => {
  const originalProvenance = provenance(existing.fieldProvenance)
  const fieldProvenance = { ...originalProvenance }
  const current = { ...existing }
  const data: Record<string, unknown> = {}

  const merge = (
    field: string,
    value: unknown,
    source: string,
    quality: DataQuality,
    set: (value: unknown) => void,
  ) => {
    if (empty(value)) return

    const currentValue = field.startsWith('customFields.')
      ? record(current.customFields)[field.slice('customFields.'.length)]
      : current[field]
    const origin = fieldProvenance[field]
    const currentRank = empty(currentValue) ? -1 : rank[origin?.quality || 'human']

    const combinesEvidence =
      field === 'protocols' && Array.isArray(currentValue) && Array.isArray(value)
    if (rank[quality] < currentRank && !combinesEvidence) return

    const nextValue = combinesEvidence ? [...new Set([...currentValue, ...value])] : value
    const valueChanged = !isDeepStrictEqual(currentValue, nextValue)
    const qualityImproved = rank[quality] > currentRank
    if (valueChanged) set(nextValue)
    if (qualityImproved || (valueChanged && rank[quality] >= currentRank))
      fieldProvenance[field] = { quality, source }
  }

  for (const input of incoming) {
    for (const [field, value] of Object.entries(input.data)) {
      if (field === 'customFields') {
        for (const [id, customValue] of Object.entries(record(value))) {
          merge(`customFields.${id}`, customValue, input.source, input.quality, (next) => {
            current.customFields = { ...record(current.customFields), [id]: next }
            data.customFields = current.customFields
          })
        }
      } else {
        merge(field, value, input.source, input.quality, (next) => {
          current[field] = next
          data[field] = next
        })
      }
    }
  }

  return {
    changed:
      Object.keys(data).length > 0 || !isDeepStrictEqual(originalProvenance, fieldProvenance),
    data,
    fieldProvenance,
  }
}

export const trackHumanAssetChanges = (
  data: Record<string, unknown>,
  originalDoc?: Record<string, unknown>,
) => {
  const next = { ...data }
  delete next.fieldProvenance

  const fieldProvenance = provenance(originalDoc?.fieldProvenance)
  let changed = false

  for (const [field, value] of Object.entries(next)) {
    if (field === 'customFields') {
      const before = record(originalDoc?.customFields)
      const after = record(value)
      for (const id of new Set([...Object.keys(before), ...Object.keys(after)])) {
        if (isDeepStrictEqual(before[id], after[id])) continue
        fieldProvenance[`customFields.${id}`] = { quality: 'human', source: 'human' }
        changed = true
      }
    } else if (!isDeepStrictEqual(originalDoc?.[field], value)) {
      fieldProvenance[field] = { quality: 'human', source: 'human' }
      changed = true
    }
  }

  if (changed) next.fieldProvenance = fieldProvenance
  return next
}
