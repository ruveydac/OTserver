import {
  APIError,
  type CollectionBeforeDeleteHook,
  type CollectionBeforeValidateHook,
  type CollectionConfig,
  type Payload,
  type PayloadRequest,
} from 'payload'

import { adminOnly, relationshipID } from '../access/authorization'
import defaultRuleSeed from '../data/default-asset-class-rules.json'

type AssignmentRule = {
  manufacturerRegex: string
  modelRegex: string
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
  manufacturer: unknown,
  model: unknown,
  req?: PayloadRequest,
) => {
  if (typeof manufacturer !== 'string' || typeof model !== 'string') return undefined
  if (!manufacturer.trim() || !model.trim()) return undefined

  type Matcher = {
    assetClass: Awaited<ReturnType<Payload['find']>>['docs'][number]
    manufacturer: RegExp
    model: RegExp
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
    matchers = classes.docs.flatMap((assetClass) =>
      (assetClass.assignmentRules || []).map((rule) => ({
        assetClass,
        manufacturer: new RegExp(rule.manufacturerRegex, 'i'),
        model: new RegExp(rule.modelRegex, 'i'),
      })),
    )
    if (req) req.context.assetClassRuleMatchers = matchers
  }

  const manufacturerValue = manufacturer.slice(0, MAX_MATCH_VALUE_LENGTH)
  const modelValue = model.slice(0, MAX_MATCH_VALUE_LENGTH)
  return matchers.find(
    (matcher) => matcher.manufacturer.test(manufacturerValue) && matcher.model.test(modelValue),
  )?.assetClass
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
    req,
    where: { legacyKey: { equals: definition.key } },
  })
  if (existing.docs[0]) return existing.docs[0]

  return payload.create({
    collection: 'asset-classes',
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
          ? assetClass.assignmentRules
          : seededClass.rules,
        ruleSeedVersion: ruleSeed.version,
      },
      id: assetClass.id,
      overrideAccess: true,
    })
  }

  const assets = await payload.find({
    collection: 'assets',
    depth: 0,
    overrideAccess: true,
    pagination: false,
    where: { assetClass: { exists: false } },
  })
  for (const asset of assets.docs) {
    const legacyType = (asset as { assetType?: unknown }).assetType
    const key = typeof legacyType === 'string' ? legacyType : 'other'
    const assetClass = await ensureAssetClass(payload, key)
    const existingProvenance = asset.fieldProvenance
    const fieldProvenance: Record<string, unknown> =
      existingProvenance &&
      typeof existingProvenance === 'object' &&
      !Array.isArray(existingProvenance)
        ? { ...(existingProvenance as Record<string, unknown>) }
        : {}
    if (fieldProvenance.assetType && !fieldProvenance.assetClass) {
      fieldProvenance.assetClass = fieldProvenance.assetType
    }
    delete fieldProvenance.assetType

    await payload.update({
      collection: 'assets',
      context: { assetClassMigration: true },
      data: { assetClass: assetClass.id, assetType: null, fieldProvenance },
      id: asset.id,
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
  const manufacturer = Object.hasOwn(nextData, 'vendor') ? nextData.vendor : originalDoc?.vendor
  const model = Object.hasOwn(nextData, 'model') ? nextData.model : originalDoc?.model
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
    const matchedClass = await findMatchingAssetClass(req.payload, manufacturer, model, req)
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
  labels: { plural: 'Asset Classes', singular: 'Asset Class' },
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
    defaultColumns: ['name', 'description', 'updatedAt'],
    description: 'Define the classes assigned to OT assets.',
    group: 'OT Inventory',
    listSearchableFields: ['name', 'description'],
    useAsTitle: 'name',
  },
  defaultSort: 'name',
  fields: [
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
          'Both case-insensitive regular expressions must match. Rules are evaluated in their displayed order.',
      },
      fields: [
        {
          name: 'manufacturerRegex',
          type: 'text',
          admin: { placeholder: 'Siemens(?: AG)?' },
          label: 'Manufacturer regex',
          maxLength: MAX_REGEX_LENGTH,
          required: true,
          validate: validateAssignmentRegex,
        },
        {
          name: 'modelRegex',
          type: 'text',
          admin: { placeholder: '.*S7-1500.*' },
          label: 'Model regex',
          maxLength: MAX_REGEX_LENGTH,
          required: true,
          validate: validateAssignmentRegex,
        },
      ],
      label: 'Automatic assignment rules',
      labels: { plural: 'Rules', singular: 'Rule' },
    },
    { name: 'legacyKey', type: 'text', admin: { hidden: true }, unique: true },
    { name: 'ruleSeedVersion', type: 'number', admin: { hidden: true } },
  ],
  hooks: { beforeDelete: [preventDeletingUsedClass] },
  timestamps: true,
}
