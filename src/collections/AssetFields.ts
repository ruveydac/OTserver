import { APIError, type CollectionBeforeChangeHook, type CollectionConfig } from 'payload'

import { adminOnly, hideFromNonAdmins } from '../access/authorization'

export type AssetFieldDefinition = {
  id: number | string
  type: 'checkbox' | 'date' | 'number' | 'text' | 'textarea'
}

export const cleanCustomFieldValues = (
  value: unknown,
  definitions: AssetFieldDefinition[],
): Record<string, boolean | number | string> => {
  if (value === null || value === undefined) return {}
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new APIError('Custom fields must be an object.', 400)
  }

  const fields = new Map(definitions.map((field) => [String(field.id), field.type]))
  const cleaned: Record<string, boolean | number | string> = {}

  for (const [id, fieldValue] of Object.entries(value)) {
    const type = fields.get(id)
    if (!type) continue

    const valid =
      (type === 'checkbox' && typeof fieldValue === 'boolean') ||
      (type === 'number' && typeof fieldValue === 'number' && Number.isFinite(fieldValue)) ||
      ((type === 'text' || type === 'textarea') && typeof fieldValue === 'string') ||
      (type === 'date' &&
        typeof fieldValue === 'string' &&
        /^\d{4}-\d{2}-\d{2}$/.test(fieldValue) &&
        !Number.isNaN(Date.parse(`${fieldValue}T00:00:00Z`)) &&
        new Date(`${fieldValue}T00:00:00Z`).toISOString().startsWith(fieldValue))

    if (!valid) throw new APIError(`Invalid value for custom field ${id}.`, 400)
    cleaned[id] = fieldValue as boolean | number | string
  }

  return cleaned
}

export const sanitizeCustomFieldValues: CollectionBeforeChangeHook = async ({ data, req }) => {
  for (const name of ['customFields', 'customFieldOverrides'] as const) {
    if (!Object.hasOwn(data, name)) continue

    const definitions = await req.payload.find({
      collection: 'asset-fields',
      depth: 0,
      overrideAccess: true,
      pagination: false,
      req,
    })
    data[name] = cleanCustomFieldValues(data[name], definitions.docs)
  }
  return data
}

const keepTypeStable: CollectionBeforeChangeHook = ({ data, originalDoc }) => {
  if (originalDoc?.type && data.type && data.type !== originalDoc.type) {
    throw new APIError('The field type cannot be changed after creation.', 400)
  }
  return data
}

export const AssetFields: CollectionConfig = {
  slug: 'asset-fields',
  labels: { plural: 'Asset Fields', singular: 'Asset Field' },
  access: {
    create: adminOnly,
    delete: adminOnly,
    read: ({ req }) => Boolean(req.user),
    update: adminOnly,
  },
  admin: {
    defaultColumns: ['label', 'type', 'updatedAt'],
    description: 'Define optional fields that appear on every asset and import.',
    group: 'Configuration',
    hidden: hideFromNonAdmins,
    useAsTitle: 'label',
  },
  defaultSort: 'label',
  fields: [
    {
      name: 'label',
      type: 'text',
      required: true,
      unique: true,
    },
    {
      name: 'type',
      type: 'select',
      admin: { description: 'The type is fixed after this field is created.' },
      options: [
        { label: 'Text', value: 'text' },
        { label: 'Multi-line text', value: 'textarea' },
        { label: 'Number', value: 'number' },
        { label: 'Yes / no', value: 'checkbox' },
        { label: 'Date', value: 'date' },
      ],
      required: true,
    },
    {
      name: 'description',
      type: 'textarea',
    },
  ],
  hooks: { beforeChange: [keepTypeStable] },
  timestamps: true,
}
