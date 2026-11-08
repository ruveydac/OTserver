import config from '@/payload.config'
import {
  createLocalReq,
  getPayload,
  type Payload,
  type RequiredDataFromCollectionSlug,
} from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { TagGroups, Tags } from '../../src/collections/Tags'
import { reapplyAssetTags } from '../../src/tags/assign'
import { filterTagsByGroup, groupTags, selectedTagGroup } from '../../src/tags/grouping'
import { compareNumericVersions, matchesTagRules } from '../../src/tags/rules'
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
