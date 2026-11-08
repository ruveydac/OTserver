import config from '@/payload.config'
import {
  createLocalReq,
  getPayload,
  type Payload,
  type RequiredDataFromCollectionSlug,
} from 'payload'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

import { initializeAssetTags, TagGroups, Tags } from '../../src/collections/Tags'
import {
  assignAssetTagsBeforeChange,
  reapplyAssetTags,
  scheduleAssetTagReapply,
} from '../../src/tags/assign'
import { tagRuleFieldOptions } from '../../src/tags/fields'
import { filterTagsByGroup, groupTags, selectedTagGroup } from '../../src/tags/grouping'
import {
  compareNumericVersions,
  matchesTagRules,
  tagRuleUsesVulnerabilities,
  validateTagRules,
} from '../../src/tags/rules'
import { siteTypeID } from '../siteType'

let payload: Payload

beforeAll(async () => {
  payload = await getPayload({ config })
})

afterAll(async () => {
  await payload.destroy()
})

describe('asset tags', () => {
  it('uses the field selector for rule fields and version comparison fields', () => {
    type Field = {
      admin?: { components?: { Field?: string } }
      fields?: Field[]
      name: string
    }
    const findField = (fields: Field[], name: string) => fields.find((field) => field.name === name)
    const rules = findField(Tags.fields as unknown as Field[], 'rules')
    const conditions = findField(rules?.fields || [], 'conditions')
    const field = findField(conditions?.fields || [], 'field')
    const compareField = findField(conditions?.fields || [], 'compareField')

    expect(field?.admin?.components?.Field).toBe('@/components/TagRuleField')
    expect(compareField?.admin?.components?.Field).toBe('@/components/TagRuleField')
  })

  it('organizes the tag list by group without a separate group collection view', () => {
    expect(TagGroups.admin?.hidden).toBe(true)
    expect(Tags.admin?.components?.beforeList).toContain('@/components/TagListGroupTabs')
    const groupField = Tags.fields.find((field) => 'name' in field && field.name === 'group')
    expect(groupField?.admin).toMatchObject({ allowCreate: true, allowEdit: true })
  })

  it('validates tag writes, protects in-use tags and groups, and queues changed rules', async () => {
    const validate = Tags.hooks?.beforeValidate?.[0]
    const validateTag = (data: Record<string, unknown>, originalDoc = {}) =>
      validate?.({
        data,
        originalDoc,
        req: { payload: { find: vi.fn(async () => ({ docs: [] })) } },
      } as never)

    await expect(validateTag({ name: ' ', color: '#334455' })).rejects.toThrow(
      'Tag names must contain between 1 and 63 characters.',
    )
    await expect(validateTag({ name: 'x'.repeat(64), color: '#334455' })).rejects.toThrow(
      'Tag names must contain between 1 and 63 characters.',
    )
    await expect(validateTag({ name: 'Valid', color: 'red' })).rejects.toThrow(
      'Choose a six-digit hexadecimal color.',
    )
    await expect(
      validateTag({ name: 'Automatic', color: '#334455', manual: false, rules: [{}] }),
    ).rejects.toThrow('Each rule needs up to 32 conditions.')

    const manualData = {
      name: 'Manual tag',
      color: '#334455',
      manual: true,
      rules: [{ conditions: [{ field: 'asset.vendor', operator: 'exists' }] }],
    }
    await expect(validateTag(manualData)).resolves.toBe(manualData)
    expect(manualData.rules).toEqual([])
    await expect(
      validateTag(
        { name: 'Updated', manual: false },
        { name: 'Existing', color: '#334455', manual: false },
      ),
    ).resolves.toEqual({ name: 'Updated', manual: false })

    const deleteGroup = TagGroups.hooks?.beforeDelete?.[0]
    await expect(
      deleteGroup?.({
        id: 'group',
        req: { payload: { count: vi.fn(async () => ({ totalDocs: 1 })) } },
      } as never),
    ).rejects.toThrow('Move or remove tags in this group before deleting it.')
    await expect(
      deleteGroup?.({
        id: 'empty-group',
        req: { payload: { count: vi.fn(async () => ({ totalDocs: 0 })) } },
      } as never),
    ).resolves.toBeUndefined()

    const deleteTag = Tags.hooks?.beforeDelete?.[0]
    for (const field of ['manualTags', 'automaticTags', 'tags']) {
      const count = vi.fn(async ({ where }: { where: Record<string, unknown> }) => ({
        totalDocs: field in where ? 1 : 0,
      }))
      await expect(
        deleteTag?.({ id: 'tag', req: { payload: { count } } } as never),
      ).rejects.toThrow('Remove this tag from affected assets before deleting it.')
      expect(count).toHaveBeenCalledTimes(
        ['manualTags', 'automaticTags', 'tags'].indexOf(field) + 1,
      )
    }
    await expect(
      deleteTag?.({
        id: 'unused-tag',
        req: { payload: { count: vi.fn(async () => ({ totalDocs: 0 })) } },
      } as never),
    ).resolves.toBeUndefined()

    const queue = vi.fn(async () => ({}))
    const afterChange = Tags.hooks?.afterChange?.[0]
    const request = { payload: { jobs: { queue } } }
    const rule = [{ conditions: [{ field: 'asset.vendor', operator: 'exists' }] }]
    const doc = { id: 'tag', name: 'Automatic', manual: false, rules: rule }
    await afterChange?.({
      context: { assetTagSeed: true },
      doc,
      operation: 'create',
      req: request,
    } as never)
    await afterChange?.({
      context: {},
      doc: { ...doc, manual: true, rules: [] },
      operation: 'create',
      req: request,
    } as never)
    await afterChange?.({ context: {}, doc, operation: 'create', req: request } as never)
    await afterChange?.({
      context: {},
      doc,
      operation: 'update',
      previousDoc: { ...doc },
      req: request,
    } as never)
    await afterChange?.({
      context: {},
      doc,
      operation: 'update',
      previousDoc: { ...doc, name: 'Old name' },
      req: request,
    } as never)
    await afterChange?.({
      context: {},
      doc,
      operation: 'update',
      previousDoc: { ...doc, manual: true },
      req: request,
    } as never)
    await afterChange?.({
      context: {},
      doc,
      operation: 'update',
      previousDoc: { ...doc, rules: [{ conditions: [] }] },
      req: request,
    } as never)
    await afterChange?.({
      context: {},
      doc,
      operation: 'update',
      previousDoc: { ...doc },
      req: request,
    } as never)
    expect(queue).toHaveBeenCalledTimes(4)
  })

  it('seeds tags idempotently without rewriting existing administrator data', async () => {
    const find = vi.fn(async () => ({ docs: [{ id: 'existing' }] }))
    const create = vi.fn()
    await initializeAssetTags({ find, create } as never)
    expect(find).toHaveBeenCalledTimes(8)
    expect(create).not.toHaveBeenCalled()
  })

  it('assigns cached manual, custom-field, and connected-catalog rule matches', async () => {
    const tags = [
      { id: 'manual', name: 'Manual', manual: true },
      {
        id: 'outdated',
        name: 'Outdated firmware',
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
      },
      {
        id: 'baseline',
        name: 'Baseline',
        manual: false,
        rules: [
          {
            conditions: [{ field: 'customFields.baseline', operator: 'equals', value: '3.0.0' }],
          },
        ],
      },
    ]
    const runtime = {
      tags,
      tagByID: new Map(tags.map((tag) => [tag.id, tag])),
      customFieldIDs: new Set<string>(),
      catalog: {
        revision: 'catalog-revision',
        catalog: {
          devices: [
            {
              id: 'device-1',
              data: {
                releases_json: [{ version: '3.0.0', version_kind: 'firmware', is_latest: true }],
              },
            },
          ],
        },
      },
    }
    const find = vi.fn()
    const req = { context: { assetTagRuntime: runtime }, payload: { find } }
    const originalDoc = {
      id: 'asset-1',
      manualTags: [{ id: 'manual' }, { id: 'outdated' }, { id: 'missing' }],
      metadataMatch: {
        catalogRevision: 'catalog-revision',
        status: 'matched',
        products: [{ id: 'device-1' }],
      },
    }
    const data = { firmwareVersion: '2.8.0', customFields: { baseline: '3.0.0' } }
    const assigned = (await assignAssetTagsBeforeChange({
      context: {},
      data,
      originalDoc,
      req,
    } as never)) as {
      manualTags: string[]
      automaticTags: string[]
      tags: string[]
      tagNames: string[]
    }

    expect(assigned).toMatchObject({
      manualTags: ['manual'],
      automaticTags: ['outdated', 'baseline'],
      tags: ['manual', 'outdated', 'baseline'],
      tagNames: ['Manual', 'Outdated firmware', 'Baseline'],
    })
    expect(find).not.toHaveBeenCalled()

    for (const metadataMatch of [
      { catalogRevision: 'old-revision', status: 'matched', products: [{ id: 'device-1' }] },
      { catalogRevision: 'catalog-revision', status: 'unmatched', products: [{ id: 'device-1' }] },
      { catalogRevision: 'catalog-revision', status: 'matched', products: null },
    ]) {
      const result = (await assignAssetTagsBeforeChange({
        context: {},
        data,
        originalDoc: { ...originalDoc, metadataMatch },
        req,
      } as never)) as { automaticTags: string[] }
      expect(result.automaticTags).toEqual(['baseline'])
    }

    await expect(
      assignAssetTagsBeforeChange({
        context: {},
        data: { manualTags: ['outdated'] },
        originalDoc,
        req,
      } as never),
    ).rejects.toThrow('Only existing manual tags can be assigned to an asset.')
    const refreshData = { name: 'unchanged' }
    await expect(
      assignAssetTagsBeforeChange({
        context: { assetTagRefresh: true },
        data: refreshData,
        req: {},
      } as never),
    ).resolves.toBe(refreshData)
  })

  it('uses confirmed vulnerability evidence when applying vulnerability rules', async () => {
    const vulnerabilityTag = {
      id: 'critical-finding',
      name: 'Critical finding',
      manual: false,
      rules: [
        {
          conditions: [
            { field: 'vulnerability.cvssSeverity', operator: 'equals', value: 'CRITICAL' },
          ],
        },
      ],
    }
    const find = vi
      .fn()
      .mockResolvedValueOnce({
        docs: [
          {
            status: 'confirmed',
            evidence: { match: { cvssSeverity: 'CRITICAL' } },
          },
          { status: 'dismissed', evidence: { match: { cvssSeverity: 'CRITICAL' } } },
        ],
        hasNextPage: true,
      })
      .mockResolvedValueOnce({
        docs: [{ status: 'confirmed', evidence: { match: {} } }],
        hasNextPage: false,
      })
    const req = {
      context: {
        assetTagRuntime: {
          tags: [vulnerabilityTag],
          tagByID: new Map([[vulnerabilityTag.id, vulnerabilityTag]]),
          customFieldIDs: new Set<string>(),
          catalog: { revision: 'unloaded', catalog: { devices: [] } },
        },
      },
      payload: { find },
    }

    const result = (await assignAssetTagsBeforeChange({
      context: {},
      data: {},
      originalDoc: { id: 'asset-1' },
      req,
    } as never)) as { automaticTags: string[] }

    expect(result.automaticTags).toEqual(['critical-finding'])
    expect(find).toHaveBeenCalledTimes(2)
    expect(find.mock.calls[1]?.[0]).toMatchObject({ page: 2 })
  })

  it('does not schedule duplicate tag-reapply jobs while one is pending or recent', async () => {
    const pendingFind = vi.fn(async () => ({ docs: [{ id: 'pending-job' }] }))
    await scheduleAssetTagReapply({ find: pendingFind } as never)
    expect(pendingFind).toHaveBeenCalledOnce()

    const recentFind = vi
      .fn()
      .mockResolvedValueOnce({ docs: [] })
      .mockResolvedValueOnce({ docs: [{ createdAt: new Date().toISOString() }] })
    await scheduleAssetTagReapply({ find: recentFind } as never)
    expect(recentFind).toHaveBeenCalledTimes(2)
  })

  it('groups tag choices and keeps other list filters when switching groups', () => {
    expect(
      groupTags([
        { id: 'low', group: { id: 'criticality', name: 'Criticality' } },
        { id: 'high', group: { id: 'criticality', name: 'Criticality' } },
        { id: 'misc' },
      ]),
    ).toEqual([
      {
        id: 'criticality',
        name: 'Criticality',
        tags: [
          { id: 'low', group: { id: 'criticality', name: 'Criticality' } },
          { id: 'high', group: { id: 'criticality', name: 'Criticality' } },
        ],
      },
      { id: 'ungrouped', name: 'Ungrouped', tags: [{ id: 'misc' }] },
    ])

    const where = { manual: { equals: true }, group: { equals: 'old-group' } }
    expect(filterTagsByGroup(where, 'new-group')).toEqual({
      and: [{ manual: { equals: true } }, { group: { equals: 'new-group' } }],
    })
    expect(selectedTagGroup(filterTagsByGroup(where, 'new-group'))).toBe('new-group')
    expect(filterTagsByGroup(where, 'ungrouped')).toEqual({
      and: [{ manual: { equals: true } }, { group: { exists: false } }],
    })
  })

  it('handles nested group filters and all, grouped, and ungrouped selections', () => {
    expect(groupTags([])).toEqual([])
    expect(selectedTagGroup()).toBe('all')
    expect(selectedTagGroup({ and: [{ group: { exists: false } }] })).toBe('ungrouped')
    expect(
      selectedTagGroup({ or: [{ status: { equals: 'active' } }, { group: { equals: 42 } }] }),
    ).toBe('42')
    expect(
      selectedTagGroup({
        and: [
          { group: [{ name: { equals: 'ignored' } }] },
          { or: [{ group: { equals: 'nested' } }] },
        ],
      }),
    ).toBe('nested')
    expect(filterTagsByGroup(undefined, 'all')).toBeUndefined()
    expect(filterTagsByGroup({ group: { equals: 'old' } }, 'all')).toBeUndefined()
    expect(filterTagsByGroup(undefined, 'ungrouped')).toEqual({ group: { exists: false } })
    expect(filterTagsByGroup(undefined, 'criticality')).toEqual({
      group: { equals: 'criticality' },
    })
    expect(
      filterTagsByGroup(
        {
          and: [
            { group: { equals: 'old' } },
            { status: { equals: 'active' } },
            { or: [{ group: { exists: false } }, { name: { contains: 'safety' } }] },
          ],
        },
        'all',
      ),
    ).toEqual({
      and: [{ status: { equals: 'active' } }, { or: [{ name: { contains: 'safety' } }] }],
    })
  })

  it('offers connected and custom fields while optionally excluding vulnerability fields', () => {
    const all = tagRuleFieldOptions([{ id: 17, label: 'Firmware baseline' }])
    const withoutVulnerabilities = tagRuleFieldOptions([{ id: 'owner', label: 'Owner' }], false)

    expect(all.map(({ value }) => value)).toContain('customFields.17')
    expect(all.map(({ value }) => value)).toContain('connected.releases_json.version')
    expect(all.map(({ value }) => value)).toContain('vulnerability.cvssSeverity')
    expect(withoutVulnerabilities.map(({ value }) => value)).toContain('customFields.owner')
    expect(withoutVulnerabilities.some(({ value }) => value.startsWith('vulnerability.'))).toBe(
      false,
    )
  })

  it('compares only unambiguous numeric firmware versions', () => {
    expect(compareNumericVersions('V2.8.0', '3.0.0')).toBe(-1)
    expect(compareNumericVersions('3.0', 'V3.0.0')).toBe(0)
    expect(compareNumericVersions('3.0-beta', '3.0')).toBeUndefined()
    const rule = [
      {
        conditions: [
          {
            field: 'asset.firmwareVersion',
            operator: 'version_less_than_field',
            compareField: 'connected.firmwareVersion',
          },
        ],
      },
    ]
    const connected = [
      {
        data: {
          releases_json: [
            { version: '3.0', version_kind: 'firmware', is_latest: true },
            { version: '2.9', version_kind: 'firmware' },
          ],
        },
      },
    ]
    expect(matchesTagRules(rule, { firmwareVersion: 'V2.8' }, connected, [])).toBe(true)
    expect(matchesTagRules(rule, { firmwareVersion: '3.0-beta' }, connected, [])).toBe(false)
    expect(
      matchesTagRules(
        rule,
        { firmwareVersion: '2.8' },
        [connected[0]!, { data: { version_kind: 'firmware', version: '4.0' } }],
        [],
      ),
    ).toBe(false)
  })

  it('validates tag rules and their field-specific constraints', () => {
    const customFields = new Set(['firmware-baseline'])
    const valid = (condition: Record<string, unknown>) =>
      validateTagRules([{ conditions: [condition] }], false, customFields)

    expect(validateTagRules(undefined, false)).toBe(true)
    expect(validateTagRules(null, false)).toBe(true)
    expect(validateTagRules([], true)).toBe(true)
    expect(validateTagRules([{}], true)).toBe('Manual tags cannot have rules.')
    expect(validateTagRules({}, false)).toBe('A tag can contain at most 64 rules.')
    expect(validateTagRules(Array(65).fill({ conditions: [] }), false)).toBe(
      'A tag can contain at most 64 rules.',
    )
    expect(validateTagRules([null], false)).toBe('Invalid tag rule.')
    expect(validateTagRules([{ conditions: Array(33).fill({}) }], false)).toBe(
      'Each rule needs up to 32 conditions.',
    )
    expect(validateTagRules([{ conditions: [null] }], false)).toBe('Invalid tag rule condition.')
    expect(valid({ field: 1, operator: 'equals' })).toBe('Invalid tag rule condition.')
    expect(valid({ field: 'asset.vendor', operator: 'unknown' })).toBe(
      'Invalid tag rule condition.',
    )
    expect(valid({ field: 'asset.vendor', operator: 'equals', value: 'x'.repeat(513) })).toBe(
      'Invalid tag rule condition.',
    )
    expect(valid({ field: 'asset.unknown', operator: 'exists' })).toBe(
      'Unsupported asset field: asset.unknown.',
    )
    expect(valid({ field: 'customFields.missing', operator: 'exists' })).toBe(
      'Unknown custom asset field: customFields.missing.',
    )
    expect(valid({ field: 'customFields.', operator: 'exists' })).toBe(
      'Unknown custom asset field: customFields..',
    )
    expect(valid({ field: 'connected.__proto__', operator: 'exists' })).toBe(
      'Invalid connected field: connected.__proto__.',
    )
    expect(valid({ field: `connected.${'a'.repeat(129)}`, operator: 'exists' })).toContain(
      'Invalid connected field:',
    )
    expect(valid({ field: 'connected.a.b.c.d.e', operator: 'exists' })).toContain(
      'Invalid connected field:',
    )
    expect(valid({ field: 'connected.bad-name', operator: 'exists' })).toContain(
      'Invalid connected field:',
    )
    expect(valid({ field: 'vulnerability.unknown', operator: 'exists' })).toContain(
      'Unsupported vulnerability field:',
    )
    expect(valid({ field: 'asset.vendor.extra', operator: 'exists' })).toBe(
      'Unsupported asset field: asset.vendor.extra.',
    )
    expect(valid({ field: 'asset.vendor', operator: 'regex', value: '(' })).not.toBe(true)
    expect(valid({ field: 'asset.lastSeen', operator: 'older_than_days', value: '0' })).toBe(
      'Older-than rules need a positive day count and the asset.lastSeen field.',
    )
    expect(valid({ field: 'asset.vendor', operator: 'older_than_days', value: '2' })).toBe(
      'Older-than rules need a positive day count and the asset.lastSeen field.',
    )
    expect(valid({ field: 'asset.vendor', operator: 'greater_than' })).toBe(
      'Numeric comparisons need a number.',
    )
    expect(valid({ field: 'asset.vendor', operator: 'less_than', value: 'NaN' })).toBe(
      'Numeric comparisons need a number.',
    )
    expect(valid({ field: 'asset.firmwareVersion', operator: 'version_less_than_field' })).toBe(
      'Version comparisons need an asset, custom, or connected comparison field.',
    )
    expect(
      valid({
        field: 'asset.firmwareVersion',
        operator: 'version_less_than_field',
        compareField: 'vulnerability.cve',
      }),
    ).toBe('Version comparisons need an asset, custom, or connected comparison field.')
    expect(
      valid({
        field: 'asset.firmwareVersion',
        operator: 'version_less_than_field',
        compareField: 'connected.__proto__',
      }),
    ).toContain('Invalid connected field:')
    expect(
      valid({
        field: 'asset.firmwareVersion',
        operator: 'version_less_than_field',
        compareField: 'asset.unknown',
      }),
    ).toContain('Unsupported asset field:')
    expect(
      valid({
        field: 'asset.firmwareVersion',
        operator: 'version_less_than_field',
        compareField: 'customFields.missing',
      }),
    ).toContain('Unknown custom asset field:')
    expect(valid({ field: 'asset.vendor', operator: 'contains' })).toBe(
      'This tag rule condition needs a value.',
    )
    expect(
      valid({
        field: 'asset.firmwareVersion',
        operator: 'version_less_than_field',
        compareField: 'customFields.firmware-baseline',
      }),
    ).toBe(true)
  })

  it('matches supported rule operators against asset, connected, custom, and confirmed fields', () => {
    const now = Date.parse('2026-11-08T00:00:00.000Z')
    const asset = {
      vendor: 'Acme Controls',
      firmwareVersion: '2.8.0',
      lastSeen: new Date(now - 61 * 86_400_000),
      slotCapacity: 4,
      customFields: { baseline: '3.0.0' },
      details: [{ name: 'controller' }, { name: 'switch' }],
      unsupported: { nested: null },
    }
    const connected = [
      {
        data: {
          releases_json: [
            { version: '3.0.0', version_kind: 'firmware', is_latest: true },
            { version: '2.9.0', version_kind: 'firmware' },
          ],
          device: { name: 'PLC-1' },
        },
      },
    ]
    const matches = (field: string, operator: string, value?: string, compareField?: string) =>
      matchesTagRules(
        [{ conditions: [{ field, operator, value, compareField }] }],
        asset,
        connected,
        [{ cvssSeverity: 'CRITICAL' }],
        now,
      )

    expect(matchesTagRules(undefined, asset, connected, [])).toBe(false)
    expect(
      matchesTagRules(
        [{ enabled: false, conditions: [{ field: 'asset.vendor', operator: 'exists' }] }],
        asset,
        connected,
        [],
      ),
    ).toBe(false)
    expect(matchesTagRules([{ conditions: [] }], asset, connected, [])).toBe(false)
    expect(matches('asset.vendor', 'exists')).toBe(true)
    expect(matches('asset.unsupported', 'exists')).toBe(false)
    expect(matches('asset.vendor', 'regex', '^acme')).toBe(true)
    expect(matches('asset.slotCapacity', 'regex', '^4$')).toBe(true)
    expect(matches('asset.vendor', 'contains', 'CONTROLS')).toBe(true)
    expect(matches('asset.vendor', 'equals', 'acme controls')).toBe(true)
    expect(matches('asset.slotCapacity', 'greater_than', '3')).toBe(true)
    expect(matches('asset.slotCapacity', 'less_than', '5')).toBe(true)
    expect(matches('asset.lastSeen', 'older_than_days', '60')).toBe(true)
    expect(
      matches(
        'asset.firmwareVersion',
        'version_less_than_field',
        undefined,
        'connected.firmwareVersion',
      ),
    ).toBe(true)
    expect(
      matches(
        'connected.firmwareVersion',
        'version_greater_than_field',
        undefined,
        'asset.firmwareVersion',
      ),
    ).toBe(true)
    expect(matches('customFields.baseline', 'equals', '3.0.0')).toBe(true)
    expect(matches('connected.device.name', 'equals', 'plc-1')).toBe(true)
    expect(matches('vulnerability.cvssSeverity', 'equals', 'critical')).toBe(true)
    expect(
      tagRuleUsesVulnerabilities([
        { conditions: [{ field: 'vulnerability.cve', operator: 'exists' }] },
      ]),
    ).toBe(true)
    expect(
      tagRuleUsesVulnerabilities([{ conditions: [{ field: 'asset.vendor', operator: 'exists' }] }]),
    ).toBe(false)
    expect(tagRuleUsesVulnerabilities(undefined)).toBe(false)

    expect(
      matchesTagRules(
        [{ conditions: [{ field: 'asset.details.name', operator: 'equals', value: 'switch' }] }],
        asset,
        [],
        [],
        now,
      ),
    ).toBe(true)
    expect(
      matchesTagRules(
        [{ conditions: [{ field: 'asset.details.name', operator: 'version_less_than_field' }] }],
        asset,
        [],
        [],
        now,
      ),
    ).toBe(false)
    expect(
      matchesTagRules(
        [{ conditions: [{ field: 'asset.vendor', operator: 'unknown' }] }],
        asset,
        [],
        [],
        now,
      ),
    ).toBe(false)
  })

  it('preserves manual tags while recalculating offline and confirmed-vulnerability tags', async () => {
    const site = await payload.create({
      collection: 'sites',
      data: { name: `Tag test ${Date.now()}`, type: await siteTypeID(payload) },
    })
    const manual = (
      await payload.find({
        collection: 'tags',
        depth: 0,
        limit: 1,
        where: { systemKey: { equals: 'criticality-high' } },
      })
    ).docs[0]!
    const vulnerabilityTag = await payload.create({
      collection: 'tags',
      context: { assetTagSeed: true },
      data: {
        name: `Confirmed CVE ${Date.now()}`,
        color: '#334155',
        manual: false,
        rules: [
          {
            conditions: [
              { field: 'vulnerability.cvssSeverity', operator: 'equals', value: 'CRITICAL' },
            ],
          },
        ],
      },
    })
    const asset = await payload.create({
      collection: 'assets',
      data: {
        firmwareVersion: '2.8',
        lastSeen: new Date(Date.now() - 61 * 86_400_000).toISOString(),
        manualTags: [manual.id],
        name: `Tag test asset ${Date.now()}`,
        site: site.id,
      } as RequiredDataFromCollectionSlug<'assets'>,
    })
    const reviewID: string[] = []

    try {
      let current = await payload.findByID({
        collection: 'assets',
        id: asset.id,
        depth: 0,
        overrideAccess: true,
      })
      const automatic = (current.automaticTags || []).map(String)
      expect(automatic).toContain(
        (
          await payload.find({
            collection: 'tags',
            depth: 0,
            limit: 1,
            where: { systemKey: { equals: 'long-offline' } },
          })
        ).docs[0]!.id,
      )
      expect((current.manualTags || []).map(String)).toContain(manual.id)

      const review = await payload.create({
        collection: 'asset-vulnerability-reviews',
        data: {
          asset: asset.id,
          site: site.id,
          cve: 'CVE-2099-9999',
          status: 'confirmed',
          revision: 1,
          decidedAt: new Date().toISOString(),
          reviewerID: 'tag-test',
          evidence: { match: { cve: 'CVE-2099-9999', cvssSeverity: 'CRITICAL' } },
        },
        overrideAccess: true,
      })
      reviewID.push(review.id)
      current = await payload.findByID({
        collection: 'assets',
        id: asset.id,
        depth: 0,
        overrideAccess: true,
      })
      expect((current.automaticTags || []).map(String)).toContain(vulnerabilityTag.id)

      await reapplyAssetTags(await createLocalReq({}, payload))
      current = await payload.findByID({
        collection: 'assets',
        id: asset.id,
        depth: 0,
        overrideAccess: true,
      })
      expect((current.manualTags || []).map(String)).toContain(manual.id)
      expect((current.tags || []).map(String)).toEqual(
        expect.arrayContaining([manual.id, vulnerabilityTag.id]),
      )
    } finally {
      for (const id of reviewID)
        await payload.db.collections['asset-vulnerability-reviews'].deleteOne({ _id: id })
      await payload.delete({ collection: 'assets', id: asset.id }).catch(() => {})
      await payload.delete({ collection: 'tags', id: vulnerabilityTag.id }).catch(() => {})
      await payload.delete({ collection: 'sites', id: site.id }).catch(() => {})
    }
  })
})
