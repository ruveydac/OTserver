import {
  APIError,
  type CollectionAfterChangeHook,
  type CollectionBeforeDeleteHook,
  type CollectionBeforeValidateHook,
  type CollectionConfig,
  type Payload,
  type PayloadRequest,
} from 'payload'
import { isDeepStrictEqual } from 'node:util'

import { adminOnly, hideFromNonAdmins } from '../access/authorization'
import { queueAssetTagReapply } from '../tags/assign'
import { validateTagRules } from '../tags/rules'

const ensureTagGroup = async (
  payload: Payload,
  key: string,
  name: string,
  req?: PayloadRequest,
) => {
  const existing = await payload.find({
    collection: 'tag-groups',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    pagination: false,
    req,
    where: { systemKey: { equals: key } },
  })
  if (existing.docs[0]) return existing.docs[0]
  return payload.create({
    collection: 'tag-groups',
    context: { assetTagSeed: true },
    data: { name, systemKey: key },
    overrideAccess: true,
    req,
  })
}

const ensureTag = async (payload: Payload, data: Record<string, unknown>, req?: PayloadRequest) => {
  const existing = await payload.find({
    collection: 'tags',
    depth: 0,
    limit: 1,
    overrideAccess: true,
    pagination: false,
    req,
    where: { systemKey: { equals: data.systemKey as string } },
  })
  if (existing.docs[0]) return existing.docs[0]
  return payload.create({
    collection: 'tags',
    context: { assetTagSeed: true },
    data: data as never,
    overrideAccess: true,
    req,
  })
}

export const initializeAssetTags = async (payload: Payload, req?: PayloadRequest) => {
  const criticality = await ensureTagGroup(payload, 'criticality', 'Criticality', req)
  const operations = await ensureTagGroup(payload, 'operations', 'Operations', req)
  for (const [key, name, color] of [
    ['criticality-low', 'Low', '#64748B'],
    ['criticality-medium', 'Medium', '#B45309'],
    ['criticality-high', 'High', '#C2410C'],
    ['criticality-critical', 'Critical', '#B91C1C'],
  ]) {
    await ensureTag(
      payload,
      { name, color, group: criticality.id, manual: true, systemKey: key },
      req,
    )
  }
  await ensureTag(
    payload,
    {
      name: 'Outdated Firmware',
      color: '#9A3412',
      group: operations.id,
      manual: false,
      rules: [
        {
          conditions: [
            {
              field: 'asset.firmwareVersion',
              operator: 'version_less_than_field',
              compareField: 'connected.firmwareVersion',
            },
          ],
        },
      ],
      systemKey: 'outdated-firmware',
    },
    req,
  )
  await ensureTag(
    payload,
    {
      name: 'Long offline',
      color: '#475569',
      group: operations.id,
      manual: false,
      rules: [
        {
          conditions: [{ field: 'asset.lastSeen', operator: 'older_than_days', value: '60' }],
        },
      ],
      systemKey: 'long-offline',
    },
    req,
  )
}

const tagGroupInUse: CollectionBeforeDeleteHook = async ({ id, req }) => {
  const tags = await req.payload.count({
    collection: 'tags',
    overrideAccess: true,
    req,
    where: { group: { equals: id } },
  })
  if (tags.totalDocs)
    throw new APIError('Move or remove tags in this group before deleting it.', 400)
}

const tagInUse: CollectionBeforeDeleteHook = async ({ id, req }) => {
  for (const field of ['manualTags', 'automaticTags', 'tags']) {
    const assets = await req.payload.count({
      collection: 'assets',
      overrideAccess: true,
      req,
      where: { [field]: { equals: id } },
    })
    if (assets.totalDocs)
      throw new APIError('Remove this tag from affected assets before deleting it.', 400)
  }
}

const validateTag: CollectionBeforeValidateHook = async ({ data, originalDoc, req }) => {
  const next = { ...originalDoc, ...data }
  if (typeof next.name !== 'string' || !next.name.trim() || next.name.trim().length > 63)
    throw new APIError('Tag names must contain between 1 and 63 characters.', 400)
  if (typeof next.color !== 'string' || !/^#[\da-f]{6}$/i.test(next.color))
    throw new APIError('Choose a six-digit hexadecimal color.', 400)
  if (next.manual === true && Array.isArray(next.rules) && next.rules.length) {
    if (data) data.rules = []
    next.rules = []
  }
  const definitions = await req.payload.find({
    collection: 'asset-fields',
    depth: 0,
    limit: 1000,
    overrideAccess: true,
    pagination: false,
    req,
  })
  const valid = validateTagRules(
    next.rules,
    next.manual === true,
    new Set(definitions.docs.map(({ id }) => String(id))),
  )
  if (valid !== true) throw new APIError(valid, 400)
  return data
}

const queueTagReapply: CollectionAfterChangeHook = async ({
  context,
  doc,
  operation,
  previousDoc,
  req,
}) => {
  if (context.assetTagSeed) return doc
  const changed =
    operation === 'create'
      ? doc.manual !== true && Boolean(doc.rules?.length)
      : doc.name !== previousDoc?.name ||
        doc.manual !== previousDoc?.manual ||
        !isDeepStrictEqual(doc.rules, previousDoc?.rules)
  if (changed) await queueAssetTagReapply(req)
  return doc
}

export const TagGroups: CollectionConfig = {
  slug: 'tag-groups',
  labels: { singular: 'Tag group', plural: 'Tag groups' },
  access: {
    create: adminOnly,
    delete: adminOnly,
    read: ({ req }) => Boolean(req.user),
    update: adminOnly,
  },
  admin: {
    defaultColumns: ['name', 'description', 'updatedAt'],
    description: 'Organize tags for administration. Groups do not affect tag matching.',
    group: 'OT inventory',
    hidden: true,
    useAsTitle: 'name',
  },
  fields: [
    { name: 'name', type: 'text', required: true, unique: true, maxLength: 63 },
    { name: 'description', type: 'textarea' },
    { name: 'systemKey', type: 'text', unique: true, admin: { hidden: true } },
  ],
  hooks: { beforeDelete: [tagGroupInUse] },
}

export const Tags: CollectionConfig = {
  slug: 'tags',
  labels: { singular: 'Tag', plural: 'Tags' },
  access: {
    create: adminOnly,
    delete: adminOnly,
    read: ({ req }) => Boolean(req.user),
    update: adminOnly,
  },
  admin: {
    components: { beforeList: ['@/components/TagListGroupTabs'] },
    defaultColumns: ['name', 'group', 'manual', 'color', 'updatedAt'],
    description: 'Create manual tags or rules that automatically match assets.',
    group: 'OT inventory',
    hidden: hideFromNonAdmins,
    useAsTitle: 'name',
  },
  fields: [
    { name: 'name', type: 'text', required: true, unique: true, maxLength: 63 },
    { name: 'description', type: 'textarea' },
    {
      name: 'group',
      type: 'relationship',
      relationTo: 'tag-groups',
      index: true,
      maxDepth: 1,
      admin: { allowCreate: true, allowEdit: true },
    },
    {
      name: 'color',
      type: 'text',
      required: true,
      defaultValue: '#64748B',
      admin: { description: 'Six-digit hexadecimal color, for example #64748B.' },
    },
    {
      name: 'manual',
      type: 'checkbox',
      defaultValue: true,
      label: 'Manual tag',
      admin: {
        description: 'Manual tags are assigned by people. Other tags are assigned by rules.',
      },
    },
    {
      name: 'rules',
      type: 'array',
      label: 'Automatic rules',
      labels: { singular: 'Rule', plural: 'Rules' },
      admin: {
        condition: (_, siblingData) => siblingData?.manual !== true,
        description:
          'Any enabled rule can match. All conditions inside that rule must match. Choose from asset, custom asset, connected catalog, and confirmed vulnerability fields. Version comparisons require a single unambiguous numeric version on each side.',
      },
      fields: [
        { name: 'enabled', type: 'checkbox', defaultValue: true, label: 'Enabled' },
        {
          name: 'conditions',
          type: 'array',
          minRows: 1,
          labels: { singular: 'Condition', plural: 'Conditions' },
          fields: [
            {
              name: 'field',
              type: 'text',
              required: true,
              admin: {
                components: { Field: '@/components/TagRuleField' },
                description:
                  'Choose an asset field, custom asset field, connected catalog field, or confirmed vulnerability field.',
              },
            },
            {
              name: 'operator',
              type: 'select',
              defaultValue: 'equals',
              required: true,
              options: [
                { label: 'Equals', value: 'equals' },
                { label: 'Contains', value: 'contains' },
                { label: 'Matches regular expression', value: 'regex' },
                { label: 'Greater than (number)', value: 'greater_than' },
                { label: 'Less than (number)', value: 'less_than' },
                { label: 'Older than (days)', value: 'older_than_days' },
                { label: 'Exists', value: 'exists' },
                { label: 'Version is less than another field', value: 'version_less_than_field' },
                {
                  label: 'Version is greater than another field',
                  value: 'version_greater_than_field',
                },
              ],
            },
            {
              name: 'value',
              type: 'text',
              maxLength: 512,
              admin: {
                condition: (_, siblingData) =>
                  siblingData?.operator !== 'exists' &&
                  !String(siblingData?.operator || '').startsWith('version_'),
              },
            },
            {
              name: 'compareField',
              type: 'text',
              admin: {
                components: { Field: '@/components/TagRuleField' },
                description: 'Choose the field to compare against.',
                condition: (_, siblingData) =>
                  String(siblingData?.operator || '').startsWith('version_'),
              },
            },
          ],
        },
      ],
    },
    { name: 'systemKey', type: 'text', unique: true, admin: { hidden: true } },
  ],
  hooks: {
    beforeValidate: [validateTag],
    afterChange: [queueTagReapply],
    beforeDelete: [tagInUse],
  },
}
