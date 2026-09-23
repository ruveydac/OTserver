import config from '@/payload.config'
import { randomBytes, randomUUID } from 'node:crypto'
import { rm, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { describe, expect, it } from 'vitest'
import { getPayload, type Payload } from 'payload'

import { ensureAdminRole } from '../../src/collections/UserRoles'
import { acquireWorker, renewWorker } from '../../src/jobs/ownership'
import { recoverQueue } from '../../src/jobs/worker'
import { withWorkerFence } from '../../src/integrations/payload/workerContext'
import type { AssetImport } from '../../src/payload-types'
import { retryImport } from '../../src/application/queuedImports'
import { principalRequest } from '../../src/integrations/payload/requests'

const nmap = (mac: string) =>
  Buffer.from(`<!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
    <host endtime="1700000000"><status state="up" reason="arp-response" reason_ttl="0" />
    <address addr="192.0.2.42" addrtype="ipv4" /><address addr="${mac}" addrtype="mac" vendor="Test Vendor" />
    <hostnames><hostname name="queued-plc" type="user" /></hostnames></host></nmaprun>`)

const createFixture = async (payload: Payload) => {
  const role = await ensureAdminRole(payload)
  const user = await payload.create({
    collection: 'users',
    data: {
      email: `queued-${randomUUID()}@example.test`,
      name: 'Queued import test',
      password: randomUUID(),
      role: role.id,
    },
  })
  const site = await payload.create({
    collection: 'sites',
    data: { name: `Queued site ${randomUUID()}`, type: 'Test' },
    overrideAccess: false,
    user,
  })
  return { site, user }
}

describe('durable workers and queued imports', () => {
  it('commits once across redelivery after inventory commit and before acknowledgement', async () => {
    process.env.OTSERVER_QUEUED_IMPORTS = 'on'
    const payload = await getPayload({ config })
    const { site, user } = await createFixture(payload)
    const mac = `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)!.join(':')}`
    const data = nmap(mac)
    let importID: string | undefined
    let jobID: string | undefined
    let fence: Awaited<ReturnType<typeof acquireWorker>> = null

    try {
      const imported = await payload.create({
        collection: 'asset-imports',
        data: {
          executionMode: 'queued',
          site: site.id,
          source: 'nmap',
          sourceVersion: 'unknown',
          status: 'pending',
        },
        file: {
          data,
          mimetype: 'application/xml',
          name: `queued-${randomUUID()}.xml`,
          size: data.length,
        },
        overrideAccess: false,
        user,
      })
      importID = imported.id
      const stored = await payload.findByID({ collection: 'asset-imports', id: imported.id })
      jobID = stored.jobID!
      expect(stored).toMatchObject({
        jobID: expect.any(String),
        executorID: user.id,
        fileDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
        processingInput: { version: 1, site: site.id, source: 'nmap' },
      })
      expect(imported).toMatchObject({
        executionMode: 'queued',
        status: 'pending',
        attemptCount: 0,
      })
      expect(imported.jobID).toBeUndefined()
      expect(imported.fileDigest).toBeUndefined()

      fence = await acquireWorker(payload, 'imports')
      expect(fence).not.toBeNull()
      expect(await acquireWorker(payload, 'imports')).toBeNull()
      await recoverQueue(payload, fence!)
      await withWorkerFence(fence!, () =>
        payload.jobs.run({ queue: 'imports', limit: 1, sequential: true, silent: true }),
      )

      let completed = await payload.findByID({ collection: 'asset-imports', id: importID })
      expect(completed.status).toBe('completed')
      expect(completed.attemptCount).toBe(1)
      const observations = await payload.count({
        collection: 'asset-observations',
        where: { import: { equals: importID } },
      })

      // Recreate the exact state left by a process killed after commit and before Payload's job ack.
      await payload.update({
        collection: 'payload-jobs',
        id: jobID,
        data: { completedAt: null, processing: true, hasError: false, error: null },
      })
      await recoverQueue(payload, fence!)
      await withWorkerFence(fence!, () =>
        payload.jobs.run({ queue: 'imports', limit: 1, sequential: true, silent: true }),
      )
      completed = await payload.findByID({ collection: 'asset-imports', id: importID })
      expect(completed.status).toBe('completed')
      expect(
        await payload.count({
          collection: 'asset-observations',
          where: { import: { equals: importID } },
        }),
      ).toMatchObject({
        totalDocs: observations.totalDocs,
      })
      expect(
        (await payload.find({ collection: 'assets', where: { macAddress: { equals: mac } } }))
          .totalDocs,
      ).toBe(1)
    } finally {
      if (fence) await renewWorker(payload, fence, true).catch(() => {})
      await payload.delete({ collection: 'assets', where: { site: { equals: site.id } } })
      if (importID) await payload.delete({ collection: 'asset-imports', id: importID })
      if (jobID) await payload.delete({ collection: 'payload-jobs', id: jobID })
      await payload.delete({ collection: 'sites', id: site.id })
      await payload.delete({ collection: 'users', id: user.id })
    }
  })

  it('fails closed when the submitting user disappears before execution', async () => {
    process.env.OTSERVER_QUEUED_IMPORTS = 'on'
    const payload = await getPayload({ config })
    const { site, user } = await createFixture(payload)
    const data = nmap('02:00:00:00:99:01')
    let importID: string | undefined
    let jobID: string | undefined
    let fence: Awaited<ReturnType<typeof acquireWorker>> = null

    try {
      const imported = await payload.create({
        collection: 'asset-imports',
        data: {
          executionMode: 'queued',
          site: site.id,
          source: 'nmap',
          sourceVersion: 'unknown',
          status: 'pending',
        },
        file: {
          data,
          mimetype: 'application/xml',
          name: `missing-user-${randomUUID()}.xml`,
          size: data.length,
        },
        overrideAccess: false,
        user,
      })
      importID = imported.id
      jobID = (await payload.findByID({ collection: 'asset-imports', id: imported.id })).jobID!
      await payload.delete({ collection: 'users', id: user.id })
      fence = await acquireWorker(payload, 'imports')
      await recoverQueue(payload, fence!)
      await withWorkerFence(fence!, () =>
        payload.jobs.run({ queue: 'imports', limit: 1, sequential: true, silent: true }),
      )
      const failed = await payload.findByID({ collection: 'asset-imports', id: importID })
      expect(failed).toMatchObject({
        status: 'failed',
        error: 'The executing user no longer has write permission for this site.',
      })
      expect(
        (await payload.count({ collection: 'assets', where: { site: { equals: site.id } } }))
          .totalDocs,
      ).toBe(0)
    } finally {
      if (fence) await renewWorker(payload, fence, true).catch(() => {})
      if (importID) await payload.delete({ collection: 'asset-imports', id: importID })
      if (jobID) await payload.delete({ collection: 'payload-jobs', id: jobID })
      await payload.delete({ collection: 'sites', id: site.id })
      await payload.delete({ collection: 'users', id: user.id }).catch(() => {})
    }
  })

  it.each(['digest mismatch', 'missing upload'] as const)(
    'rejects a %s without inventory writes',
    async (failure) => {
      process.env.OTSERVER_QUEUED_IMPORTS = 'on'
      const payload = await getPayload({ config })
      const { site, user } = await createFixture(payload)
      const data = nmap(`02:00:00:00:9A:${failure === 'digest mismatch' ? '01' : '02'}`)
      let imported: AssetImport | undefined
      let fence: Awaited<ReturnType<typeof acquireWorker>> = null
      let storedPath: string | undefined
      const jobIDs: string[] = []

      try {
        const accepted = await payload.create({
          collection: 'asset-imports',
          data: {
            executionMode: 'queued',
            site: site.id,
            source: 'nmap',
            sourceVersion: 'unknown',
            status: 'pending',
          },
          file: {
            data,
            mimetype: 'application/xml',
            name: `integrity-${randomUUID()}.xml`,
            size: data.length,
          },
          overrideAccess: false,
          user,
        })
        imported = await payload.findByID({ collection: 'asset-imports', id: accepted.id })
        jobIDs.push(imported.jobID!)
        storedPath = path.resolve(
          payload.collections['asset-imports'].config.upload.staticDir!,
          imported.filename!,
        )
        if (failure === 'digest mismatch') await writeFile(storedPath, Buffer.from('changed'))
        else await rm(storedPath)

        fence = await acquireWorker(payload, 'imports')
        await recoverQueue(payload, fence!)
        await withWorkerFence(fence!, () =>
          payload.jobs.run({ queue: 'imports', limit: 1, sequential: true, silent: true }),
        )
        expect(
          await payload.findByID({ collection: 'asset-imports', id: imported.id }),
        ).toMatchObject({
          status: 'failed',
          error:
            'Processing failed validation or an integrity check. Check the file, site, and processing inputs.',
        })
        expect(
          (await payload.count({ collection: 'assets', where: { site: { equals: site.id } } }))
            .totalDocs,
        ).toBe(0)

        if (failure === 'digest mismatch') {
          await writeFile(storedPath, data)
          const retryReq = await principalRequest(payload, user)
          retryReq.routeParams = { id: imported.id }
          const retryResponse = await retryImport(retryReq)
          expect(retryResponse.status).toBe(200)
          expect((await retryResponse.json()).doc).toMatchObject({ status: 'pending' })
          const retried = await payload.findByID({ collection: 'asset-imports', id: imported.id })
          jobIDs.push(retried.jobID!)
          await withWorkerFence(fence!, () =>
            payload.jobs.run({ queue: 'imports', limit: 1, sequential: true, silent: true }),
          )
          expect(
            await payload.findByID({ collection: 'asset-imports', id: imported.id }),
          ).toMatchObject({ status: 'completed', attemptCount: 2, retriedBy: user.id })
          await expect(retryImport(retryReq)).rejects.toThrow(
            'Only failed queued imports can be retried.',
          )
        }
      } finally {
        if (fence) await renewWorker(payload, fence, true).catch(() => {})
        if (storedPath) await writeFile(storedPath, data).catch(() => {})
        await payload.delete({ collection: 'assets', where: { site: { equals: site.id } } })
        if (imported) {
          for (const id of jobIDs)
            await payload.delete({ collection: 'payload-jobs', id }).catch(() => {})
          await payload.delete({ collection: 'asset-imports', id: imported.id }).catch(() => {})
        }
        await payload.delete({ collection: 'sites', id: site.id })
        await payload.delete({ collection: 'users', id: user.id })
      }
    },
  )

  it('rechecks revoked site-write permission before an attempt', async () => {
    process.env.OTSERVER_QUEUED_IMPORTS = 'on'
    const payload = await getPayload({ config })
    const { site, user } = await createFixture(payload)
    const data = nmap('02:00:00:00:9B:01')
    let importID: string | undefined
    let jobID: string | undefined
    let readerRoleID: string | undefined
    let fence: Awaited<ReturnType<typeof acquireWorker>> = null

    try {
      const imported = await payload.create({
        collection: 'asset-imports',
        data: {
          executionMode: 'queued',
          site: site.id,
          source: 'nmap',
          sourceVersion: 'unknown',
          status: 'pending',
        },
        file: {
          data,
          mimetype: 'application/xml',
          name: `revoked-${randomUUID()}.xml`,
          size: data.length,
        },
        overrideAccess: false,
        user,
      })
      importID = imported.id
      jobID = (await payload.findByID({ collection: 'asset-imports', id: imported.id })).jobID!
      const readerRole = await payload.create({
        collection: 'user-roles',
        data: {
          name: `Queued reader ${randomUUID()}`,
          permissions: [{ access: 'read', site: site.id }],
        },
      })
      readerRoleID = readerRole.id
      await payload.update({ collection: 'users', id: user.id, data: { role: readerRole.id } })

      fence = await acquireWorker(payload, 'imports')
      await recoverQueue(payload, fence!)
      await withWorkerFence(fence!, () =>
        payload.jobs.run({ queue: 'imports', limit: 1, sequential: true, silent: true }),
      )
      expect(await payload.findByID({ collection: 'asset-imports', id: importID })).toMatchObject({
        status: 'failed',
        error: 'The executing user no longer has write permission for this site.',
      })
    } finally {
      if (fence) await renewWorker(payload, fence, true).catch(() => {})
      if (importID) await payload.delete({ collection: 'asset-imports', id: importID })
      if (jobID) await payload.delete({ collection: 'payload-jobs', id: jobID })
      await payload.delete({ collection: 'users', id: user.id })
      if (readerRoleID) await payload.delete({ collection: 'user-roles', id: readerRoleID })
      await payload.delete({ collection: 'sites', id: site.id })
    }
  })

  it('deduplicates two accepted queued submissions through the shared replay key', async () => {
    process.env.OTSERVER_QUEUED_IMPORTS = 'on'
    const payload = await getPayload({ config })
    const { site, user } = await createFixture(payload)
    const data = nmap('02:00:00:00:9C:01')
    const imports: { id: string; jobID?: string | null }[] = []
    let fence: Awaited<ReturnType<typeof acquireWorker>> = null

    try {
      for (let index = 0; index < 2; index += 1) {
        const accepted = await payload.create({
          collection: 'asset-imports',
          data: {
            executionMode: 'queued',
            site: site.id,
            source: 'nmap',
            sourceVersion: 'unknown',
            status: 'pending',
          },
          file: {
            data,
            mimetype: 'application/xml',
            name: `duplicate-${index}-${randomUUID()}.xml`,
            size: data.length,
          },
          overrideAccess: false,
          user,
        })
        imports.push(await payload.findByID({ collection: 'asset-imports', id: accepted.id }))
      }
      fence = await acquireWorker(payload, 'imports')
      await recoverQueue(payload, fence!)
      await withWorkerFence(fence!, async () => {
        await payload.jobs.run({ queue: 'imports', limit: 1, sequential: true, silent: true })
        await payload.jobs.run({ queue: 'imports', limit: 1, sequential: true, silent: true })
      })
      const completed = await Promise.all(
        imports.map(({ id }) => payload.findByID({ collection: 'asset-imports', id })),
      )
      expect(completed.map(({ status }) => status)).toEqual(['completed', 'completed'])
      expect(completed.filter(({ duplicateOf }) => duplicateOf)).toHaveLength(1)
      expect(
        (await payload.count({ collection: 'assets', where: { site: { equals: site.id } } }))
          .totalDocs,
      ).toBe(1)
    } finally {
      if (fence) await renewWorker(payload, fence, true).catch(() => {})
      await payload.delete({ collection: 'assets', where: { site: { equals: site.id } } })
      for (const imported of imports) {
        await payload.delete({ collection: 'asset-imports', id: imported.id })
        if (imported.jobID) await payload.delete({ collection: 'payload-jobs', id: imported.jobID })
      }
      await payload.delete({ collection: 'sites', id: site.id })
      await payload.delete({ collection: 'users', id: user.id })
    }
  })
})
