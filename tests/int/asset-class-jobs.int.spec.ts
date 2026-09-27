import config from '@/payload.config'
import { randomUUID } from 'node:crypto'
import { describe, expect, it, vi } from 'vitest'
import { getPayload, type Payload, type RequiredDataFromCollectionSlug } from 'payload'

import { AssetClasses, reapplyAssetClassRules } from '../../src/collections/AssetClasses'
import { acquireWorker, renewWorker } from '../../src/jobs/ownership'
import { withWorkerFence } from '../../src/integrations/payload/workerContext'

const queuedReapply = async (payload: Payload, assetClassID: string) => {
  const jobs = await payload.find({
    collection: 'payload-jobs',
    depth: 0,
    limit: 20,
    sort: '-createdAt',
    where: {
      and: [
        { taskSlug: { equals: 'reapply-asset-classes-v1' } },
        { completedAt: { exists: false } },
      ],
    },
  })
  return jobs.docs.find(
    (job) =>
      job.input &&
      typeof job.input === 'object' &&
      !Array.isArray(job.input) &&
      job.input.assetClassID === assetClassID,
  )
}

describe('asset-class rule jobs', () => {
  it('does not queue work for unrelated asset-class edits', async () => {
    const queue = vi.fn()
    const hook = AssetClasses.hooks!.afterChange![0]
    if (typeof hook !== 'function') throw new Error('Expected an asset-class afterChange hook.')

    await hook({
      context: {},
      doc: { assignmentPriority: 1, id: 'class-1' },
      operation: 'update',
      previousDoc: { assignmentPriority: 1, id: 'class-1' },
      req: { payload: { jobs: { queue } } },
    } as never)
    expect(queue).not.toHaveBeenCalled()
  })

  it('pages through assets without rewriting human or current assignments', async () => {
    const update = vi.fn()
    const payload = {
      find: vi.fn(async ({ collection, page, where }) => {
        if (collection === 'asset-classes') {
          if (where?.legacyKey) return { docs: [{ id: 'other' }] }
          return {
            docs: [
              {
                assignmentRules: [{ manufacturerRegex: '^Acme$', modelRegex: '^Drive$' }],
                id: 'drive',
              },
            ],
          }
        }
        if (page === 1)
          return {
            docs: [
              {
                assetClass: 'other',
                fieldProvenance: { assetClass: { quality: 'human', source: 'human' } },
                id: 'human',
                model: 'Drive',
                vendor: 'Acme',
              },
              {
                assetClass: 'drive',
                fieldProvenance: {
                  assetClass: { quality: 'medium', source: 'asset-class-rule' },
                },
                id: 'current',
                model: 'Drive',
                vendor: 'Acme',
              },
            ],
            hasNextPage: true,
          }
        return {
          docs: [{ assetClass: 'drive', fieldProvenance: 'invalid', id: 'fallback' }],
          hasNextPage: false,
        }
      }),
      update,
    }

    await expect(reapplyAssetClassRules({ context: {}, payload } as never)).resolves.toEqual({
      scanned: 3,
      updated: 1,
    })
    expect(update).toHaveBeenCalledTimes(1)
    expect(update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: {
          assetClass: 'other',
          fieldProvenance: { assetClass: { quality: 'low', source: 'default' } },
        },
        id: 'fallback',
      }),
    )
  })

  it('reclassifies all automatic assignments and preserves human choices', async () => {
    const payload = await getPayload({ config })
    const other = (
      await payload.find({
        collection: 'asset-classes',
        depth: 0,
        limit: 1,
        where: { legacyKey: { equals: 'other' } },
      })
    ).docs[0]!
    const assetClass = await payload.create({
      collection: 'asset-classes',
      data: { assignmentPriority: 1, name: `Drive ${randomUUID()}` },
    })
    const site = await payload.create({
      collection: 'sites',
      data: { name: `Rule job ${randomUUID()}`, type: 'Test' },
    })
    const automatic = await payload.create({
      collection: 'assets',
      data: {
        name: 'Automatically classified drive',
        site: site.id,
        vendor: 'Acme Controls',
        model: 'Drive-9000',
      } as RequiredDataFromCollectionSlug<'assets'>,
    })
    const human = await payload.create({
      collection: 'assets',
      data: {
        assetClass: other.id,
        name: 'Human classified drive',
        site: site.id,
        vendor: 'Acme Controls',
        model: 'Drive-9001',
      } as RequiredDataFromCollectionSlug<'assets'>,
    })
    const jobIDs: string[] = []
    let fence: Awaited<ReturnType<typeof acquireWorker>> = null

    try {
      await payload.update({
        collection: 'asset-classes',
        id: assetClass.id,
        data: {
          assignmentRules: [{ manufacturerRegex: '^Acme Controls$', modelRegex: '^Drive-.*$' }],
        },
      })
      const firstJob = await queuedReapply(payload, assetClass.id)
      expect(firstJob).toBeDefined()
      jobIDs.push(firstJob!.id)

      fence = await acquireWorker(payload, 'maintenance')
      expect(fence).not.toBeNull()
      await withWorkerFence(fence!, () => payload.jobs.runByID({ id: firstJob!.id, silent: true }))

      expect(
        await payload.findByID({ collection: 'assets', id: automatic.id, depth: 0 }),
      ).toMatchObject({
        assetClass: assetClass.id,
        fieldProvenance: {
          assetClass: { quality: 'medium', source: 'asset-class-rule' },
        },
      })
      expect(
        await payload.findByID({ collection: 'assets', id: human.id, depth: 0 }),
      ).toMatchObject({
        assetClass: other.id,
        fieldProvenance: { assetClass: { quality: 'human', source: 'human' } },
      })

      await payload.update({
        collection: 'asset-classes',
        id: assetClass.id,
        data: {
          assignmentRules: [{ manufacturerRegex: '^Other Vendor$', modelRegex: '^Other Model$' }],
        },
      })
      const secondJob = await queuedReapply(payload, assetClass.id)
      expect(secondJob).toBeDefined()
      jobIDs.push(secondJob!.id)
      await withWorkerFence(fence!, () => payload.jobs.runByID({ id: secondJob!.id, silent: true }))

      expect(
        await payload.findByID({ collection: 'assets', id: automatic.id, depth: 0 }),
      ).toMatchObject({
        assetClass: other.id,
        fieldProvenance: { assetClass: { quality: 'low', source: 'default' } },
      })
      expect(
        await payload.findByID({ collection: 'assets', id: human.id, depth: 0 }),
      ).toMatchObject({
        assetClass: other.id,
        fieldProvenance: { assetClass: { quality: 'human', source: 'human' } },
      })
    } finally {
      if (fence) await renewWorker(payload, fence, true).catch(() => {})
      await payload.delete({ collection: 'assets', id: automatic.id }).catch(() => {})
      await payload.delete({ collection: 'assets', id: human.id }).catch(() => {})
      await payload.delete({ collection: 'asset-classes', id: assetClass.id }).catch(() => {})
      await payload.delete({ collection: 'sites', id: site.id }).catch(() => {})
      for (const id of jobIDs)
        await payload.delete({ collection: 'payload-jobs', id }).catch(() => {})
    }
  })
})
