import {
  APIError,
  type CollectionAfterChangeHook,
  type CollectionBeforeDeleteHook,
  type CollectionBeforeValidateHook,
  type CollectionConfig,
  type Payload,
  type PayloadRequest,
} from 'payload'
import { relationship as validateRelationship } from 'payload/shared'
import { isDeepStrictEqual } from 'node:util'

import { adminOnly, relationshipID } from '../access/authorization'
import defaultRuleSeed from '../data/default-asset-class-rules.json'

const assignmentFields = {
  assetOwner: 'Asset owner',
  catalogNumber: 'Catalog / part number',
  description: 'Description',
  firmwareVersion: 'Firmware version',
  hardwareVersion: 'Hardware version',
  location: 'Physical location',
  model: 'Model',
  name: 'Name',
  operatingSystem: 'Operating system',
  physicalKind: 'Physical kind',
  protocols: 'Protocols',
  serialNumber: 'Serial number',
  vendor: 'Vendor / manufacturer',
} as const

type AssignmentCondition = {
  field: keyof typeof assignmentFields | 'customField'
  customField?: string
  regex: string
}
type AssignmentRule = {
  conditions?: AssignmentCondition[]
  manufacturerRegex?: string
  modelRegex?: string
}

type RuleSeed = {
  classes: Array<{
    classKey: string
    priority: number
    rules: AssignmentRule[]
  }>
  version: number
}

const ruleSeed = defaultRuleSeed as RuleSeed
const MAX_REGEX_LENGTH = 256
const MAX_MATCH_VALUE_LENGTH = 512

const seedClass = (key: string) => ruleSeed.classes.find(({ classKey }) => classKey === key)

export const validateAssignmentRegex = (value: null | string | undefined): string | true => {
  if (!value) return 'Enter a regular expression.'
  if (value.length > MAX_REGEX_LENGTH) {
    return `Regular expressions are limited to ${MAX_REGEX_LENGTH} characters.`
  }
  if (/\\[1-9]/.test(value)) return 'Backreferences are not supported in assignment rules.'
  if (
    /\((?:[^()]|\\.)*(?:[*+]|\{\d+(?:,\d*)?\})(?:[^()]|\\.)*\)(?:[*+]|\{\d+(?:,\d*)?\})/.test(value)
  ) {
    return 'Nested quantified groups are not supported in assignment rules.'
  }
  try {
    new RegExp(value, 'i')
    return true
  } catch {
    return 'Enter a valid regular expression.'
  }
}

export const findMatchingAssetClass = async (
  payload: Payload,
  asset: Record<string, unknown>,
  req?: PayloadRequest,
) => {
  type Matcher = {
    assetClass: Awaited<ReturnType<Payload['find']>>['docs'][number]
    conditions: Array<{ field: string; regex: RegExp }>
    legacy?: { manufacturer: RegExp; model: RegExp }
  }
  let matchers = req?.context.assetClassRuleMatchers as Matcher[] | undefined
  if (!matchers) {
    const classes = await payload.find({
      collection: 'asset-classes',
      depth: 0,
      overrideAccess: true,
      pagination: false,
      req,
      sort: ['assignmentPriority', 'name'],
    })
    const definitions = await payload.find({
      collection: 'asset-fields',
      depth: 0,
      overrideAccess: true,
      pagination: false,
      req,
      where: { type: { in: ['text', 'textarea'] } },
    })
    const customFieldIDs = new Set(definitions.docs.map(({ id }) => String(id)))
    matchers = classes.docs.flatMap((assetClass) =>
      ((assetClass.assignmentRules || []) as unknown as AssignmentRule[]).map((rule) => ({
        assetClass,
        conditions: (rule.conditions || []).map(({ customField, field, regex }) => {
          const customID = relationshipID(customField)
          if (customID) {
            return {
              field: customFieldIDs.has(String(customID))
                ? `customFields.${customID}`
                : '\u0000invalid',
              regex: new RegExp(regex, 'i'),
            }
          }
          return {
            field: field && field in assignmentFields ? field : '\u0000invalid',
            regex: new RegExp(regex, 'i'),
          }
        }),
        ...(!rule.conditions?.length && rule.manufacturerRegex && rule.modelRegex
          ? {
              legacy: {
                manufacturer: new RegExp(rule.manufacturerRegex, 'i'),
                model: new RegExp(rule.modelRegex, 'i'),
              },
            }
          : {}),
      })),
    )
    if (req) req.context.assetClassRuleMatchers = matchers
  }

  const fieldValue = (field: string): string[] => {
    const value = field.startsWith('customFields.')
      ? (asset.customFields as Record<string, unknown> | undefined)?.[field.slice(13)]
      : asset[field]
    return (Array.isArray(value) ? value : [value])
      .filter(
        (item): item is string | number => typeof item === 'string' || typeof item === 'number',
      )
      .map((item) => String(item).slice(0, MAX_MATCH_VALUE_LENGTH))
      .filter((item) => item.trim().length > 0)
  }
  return matchers.find((matcher) => {
    const legacy = matcher.legacy
    if (legacy) {
      return (
        fieldValue('vendor').some((value) => legacy.manufacturer.test(value)) &&
        fieldValue('model').some((value) => legacy.model.test(value))
      )
    }
    return (
      matcher.conditions.length > 0 &&
      matcher.conditions.every(({ field, regex }) =>
        fieldValue(field).some((value) => regex.test(value)),
      )
    )
  })?.assetClass
}

export const defaultAssetClasses = [
  { key: 'plc', name: 'PLC' },
  { key: 'hmi', name: 'HMI' },
  { key: 'scada-server', name: 'SCADA server' },
  { key: 'rtu', name: 'RTU' },
  { key: 'network-device', name: 'Network device' },
  { key: 'engineering-workstation', name: 'Engineering workstation' },
  { key: 'sensor-actuator', name: 'Sensor / actuator' },
  { key: 'other', name: 'Other' },
] as const

const classByKey = new Map(defaultAssetClasses.map((item) => [item.key, item]))
type DefaultAssetClassKey = (typeof defaultAssetClasses)[number]['key']

export const ensureAssetClass = async (payload: Payload, key: string, req?: PayloadRequest) => {
  const definition = classByKey.get(key as DefaultAssetClassKey) || classByKey.get('other')!
  const seed = seedClass(definition.key)
  const existing = await payload.find({
    collection: 'asset-classes',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    pagination: false,
    req,
    where: { legacyKey: { equals: definition.key } },
  })
  if (existing.docs[0]) return existing.docs[0]

  return payload.create({
    collection: 'asset-classes',
    context: { assetClassRuleSeed: true },
    data: {
      assignmentPriority: seed?.priority ?? 100,
      assignmentRules: seed?.rules,
      legacyKey: definition.key,
      name: definition.name,
      ruleSeedVersion: ruleSeed.version,
    },
    overrideAccess: true,
    req,
  })
}

export const initializeAssetClasses = async (payload: Payload) => {
  const classes = await payload.count({ collection: 'asset-classes', overrideAccess: true })
  if (!classes.totalDocs) {
    for (const definition of defaultAssetClasses) {
      await ensureAssetClass(payload, definition.key)
    }
  }

  for (const seededClass of ruleSeed.classes) {
    const existing = await payload.find({
      collection: 'asset-classes',
      depth: 0,
      limit: 1,
      overrideAccess: true,
      where: { legacyKey: { equals: seededClass.classKey } },
    })
    const assetClass = existing.docs[0]
    if (!assetClass || (assetClass.ruleSeedVersion || 0) >= ruleSeed.version) continue

    await payload.update({
      collection: 'asset-classes',
      context: { assetClassRuleSeed: true },
      data: {
        assignmentPriority: seededClass.priority,
        assignmentRules: assetClass.assignmentRules?.length
          ? ((assetClass.assignmentRules as unknown as AssignmentRule[]).map((rule) =>
              rule.conditions?.length || !rule.manufacturerRegex || !rule.modelRegex
                ? rule
                : {
                    conditions: [
                      { field: 'vendor', regex: rule.manufacturerRegex },
                      { field: 'model', regex: rule.modelRegex },
                    ],
                  },
            ) as never)
          : (seededClass.rules as never),
        ruleSeedVersion: ruleSeed.version,
      },
      id: assetClass.id,
      overrideAccess: true,
    })
  }
}

export const assignDefaultAssetClass: CollectionBeforeValidateHook = async ({
  context,
  data,
  originalDoc,
  req,
}) => {
  const nextData = data || {}
  if (Object.hasOwn(nextData, 'assetClass') && relationshipID(nextData.assetClass)) return nextData

  const existingClass = relationshipID(originalDoc?.assetClass)
  const provenance =
    originalDoc?.fieldProvenance &&
    typeof originalDoc.fieldProvenance === 'object' &&
    !Array.isArray(originalDoc.fieldProvenance)
      ? (originalDoc.fieldProvenance as Record<string, { quality?: string }>)
      : {}
  const assignmentData = { ...originalDoc, ...nextData }
  const withProvenance = (
    assetClass: number | string,
    origin: { quality: 'low' | 'medium'; source: 'asset-class-rule' | 'default' },
  ) => {
    const currentProvenance = Object.hasOwn(nextData, 'fieldProvenance')
      ? nextData.fieldProvenance
      : originalDoc?.fieldProvenance
    const fieldProvenance =
      currentProvenance &&
      typeof currentProvenance === 'object' &&
      !Array.isArray(currentProvenance)
        ? { ...(currentProvenance as Record<string, unknown>) }
        : {}
    fieldProvenance.assetClass = origin
    return { ...nextData, assetClass, fieldProvenance }
  }

  if (!existingClass || provenance.assetClass?.quality !== 'human') {
    const matchedClass = await findMatchingAssetClass(req.payload, assignmentData, req)
    if (matchedClass && String(matchedClass.id) !== String(existingClass || '')) {
      context.assetClassRuleAssignment = true
      req.context.assetClassRuleAssignment = true
      return withProvenance(matchedClass.id, {
        quality: 'medium',
        source: 'asset-class-rule',
      })
    }
  }

  if (existingClass) return nextData

  const legacyType = typeof nextData.assetType === 'string' ? nextData.assetType : 'other'
  const assetClass = await ensureAssetClass(req.payload, legacyType, req)
  context.assetClassDefaultAssignment = true
  req.context.assetClassDefaultAssignment = true
  return {
    ...withProvenance(assetClass.id, { quality: 'low', source: 'default' }),
    assetType: null,
  }
}

export const reapplyAssetClassRules = async (req: PayloadRequest) => {
  const fallback = await ensureAssetClass(req.payload, 'other', req)
  delete req.context.assetClassRuleMatchers
  let page = 1
  let scanned = 0
  let updated = 0

  for (;;) {
    const assets = await req.payload.find({
      collection: 'assets',
      depth: 0,
      limit: 100,
      overrideAccess: true,
      page,
      req,
      select: {
        assetClass: true,
        assetOwner: true,
        catalogNumber: true,
        customFields: true,
        description: true,
        fieldProvenance: true,
        firmwareVersion: true,
        hardwareVersion: true,
        location: true,
        model: true,
        name: true,
        operatingSystem: true,
        physicalKind: true,
        protocols: true,
        serialNumber: true,
        vendor: true,
      },
      sort: 'id',
    })
    scanned += assets.docs.length

    for (const asset of assets.docs) {
      const fieldProvenance =
        asset.fieldProvenance &&
        typeof asset.fieldProvenance === 'object' &&
        !Array.isArray(asset.fieldProvenance)
          ? { ...(asset.fieldProvenance as Record<string, unknown>) }
          : {}
      const currentOrigin = fieldProvenance.assetClass as
        { quality?: unknown; source?: unknown } | undefined
      if (currentOrigin?.quality === 'human') continue

      const matched = await findMatchingAssetClass(req.payload, asset, req)
      const target = matched || fallback
      const origin = matched
        ? { quality: 'medium' as const, source: 'asset-class-rule' as const }
        : { quality: 'low' as const, source: 'default' as const }
      if (
        String(relationshipID(asset.assetClass)) === String(target.id) &&
        currentOrigin?.quality === origin.quality &&
        currentOrigin.source === origin.source
      )
        continue

      fieldProvenance.assetClass = origin
      await req.payload.update({
        collection: 'assets',
        context: { assetClassReclassification: true },
        data: { assetClass: target.id, fieldProvenance },
        id: asset.id,
        overrideAccess: true,
        req,
      })
      updated++
    }

    if (!assets.hasNextPage) break
    page++
  }

  return { scanned, updated }
}

const queueAssetClassReapply: CollectionAfterChangeHook = async ({
  context,
  doc,
  operation,
  previousDoc,
  req,
}) => {
  if (context.assetClassRuleSeed) return doc
  const rulesChanged = !isDeepStrictEqual(doc.assignmentRules, previousDoc?.assignmentRules)
  const priorityChanged = doc.assignmentPriority !== previousDoc?.assignmentPriority
  if (
    (operation === 'create' && !doc.assignmentRules?.length) ||
    (!rulesChanged && !priorityChanged)
  )
    return doc

  await req.payload.jobs.queue({
    task: 'reapply-asset-classes-v1',
    queue: 'maintenance',
    input: { version: 1, assetClassID: String(doc.id) },
    req,
  })
  return doc
}

const preventDeletingUsedClass: CollectionBeforeDeleteHook = async ({ id, req }) => {
  const assets = await req.payload.count({
    collection: 'assets',
    overrideAccess: true,
    req,
    where: { assetClass: { equals: id } },
  })
  if (assets.totalDocs) {
    throw new APIError('Reassign affected assets before deleting this asset class.', 400)
  }
}

export const AssetClasses: CollectionConfig = {
  slug: 'asset-classes',
  labels: { singular: 'Asset class', plural: 'Asset classes' },
  access: {
    create: adminOnly,
    delete: adminOnly,
    read: ({ req }) => Boolean(req.user),
    update: adminOnly,
  },
  admin: {
    components: {
      views: { list: { Component: '@/components/AssetClassListView' } },
    },
    defaultColumns: [
      'name',
      'description',
      'assignmentRules',
      'assignmentPriority',
      'assetsLink',
      'updatedAt',
    ],
    description: 'Define the classes assigned to OT assets.',
    group: 'OT inventory',
    listSearchableFields: ['name', 'description'],
    useAsTitle: 'name',
  },
  defaultSort: 'name',
  fields: [
    {
      name: 'assetsLink',
      type: 'ui',
      label: 'Assets',
      admin: { components: { Cell: '@/components/AssetClassAssetsCell' } },
    },
    { name: 'name', type: 'text', index: true, required: true, unique: true },
    { name: 'description', type: 'textarea' },
    {
      name: 'assignmentPriority',
      type: 'number',
      admin: {
        description:
          'Lower numbers are evaluated first when rules from multiple classes match an asset.',
      },
      defaultValue: 100,
      index: true,
      label: 'Rule priority',
      min: 0,
      required: true,
    },
    {
      name: 'assignmentRules',
      type: 'array',
      admin: {
        description:
          'Every condition in a rule must match. Rules are checked in order, and the first matching class at the highest priority is assigned.',
      },
      fields: [
        {
          name: 'conditions',
          type: 'array',
          minRows: 1,
          labels: { plural: 'Conditions', singular: 'Condition' },
          fields: [
            {
              name: 'field',
              type: 'select',
              options: [
                ...Object.entries(assignmentFields).map(([value, label]) => ({ label, value })),
                { label: 'Custom field', value: 'customField' },
              ],
              required: true,
            },
            {
              name: 'customField',
              type: 'relationship',
              relationTo: 'asset-fields',
              filterOptions: { type: { in: ['text', 'textarea'] } },
              admin: { condition: (_, siblingData) => siblingData?.field === 'customField' },
              validate: async (
                value: unknown,
                args: Parameters<typeof validateRelationship>[1],
              ) => {
                const valid = await validateRelationship(value as never, args)
                if (valid !== true) return valid
                return (args.siblingData as { field?: string } | undefined)?.field ===
                  'customField' && !value
                  ? 'Select a custom asset field.'
                  : true
              },
            },
            {
              name: 'regex',
              type: 'text',
              admin: { placeholder: '.*' },
              maxLength: MAX_REGEX_LENGTH,
              required: true,
              validate: validateAssignmentRegex,
            },
          ],
        },
      ],
      label: 'Automatic assignment rules',
      labels: { plural: 'Rules', singular: 'Rule' },
    },
    { name: 'legacyKey', type: 'text', admin: { hidden: true }, unique: true },
    { name: 'ruleSeedVersion', type: 'number', admin: { hidden: true } },
  ],
  hooks: {
    afterChange: [queueAssetClassReapply],
    beforeDelete: [preventDeletingUsedClass],
  },
}
