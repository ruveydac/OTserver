import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import config from '@/payload.config'
import { createLocalReq, getPayload } from 'payload'
import { randomUUID } from 'node:crypto'
import { ApplicationSettings } from '../../src/globals/ApplicationSettings'
import { ensureAdminRole } from '../../src/collections/UserRoles'
import {
  configuredControllerURL,
  queuedImportsEnabled,
  validateControllerURL,
} from '../../src/application/settings'

const invoke = (hook: unknown, args: unknown) => (hook as (value: never) => unknown)(args as never)

describe('administrator application settings', () => {
  beforeEach(() => {
    vi.stubEnv('OTSERVER_PUBLIC_URL', '')
    vi.stubEnv('OTSERVER_QUEUED_IMPORTS', 'off')
  })

  afterEach(() => vi.unstubAllEnvs())

  it('uses saved settings before deployment defaults and leaves unset values on the deployment defaults', async () => {
    let settings: Record<string, unknown> = {
      controllerURL: ' https://saved.example/ ',
      queuedImports: 'enabled',
    }
    const payload = { findGlobal: vi.fn(async () => settings) }

    process.env.OTSERVER_PUBLIC_URL = 'https://environment.example'
    process.env.OTSERVER_QUEUED_IMPORTS = 'on'
    await expect(configuredControllerURL(payload as never)).resolves.toBe('https://saved.example/')
    await expect(queuedImportsEnabled(payload as never)).resolves.toBe(true)

    settings = { controllerURL: '', queuedImports: 'disabled' }
    await expect(configuredControllerURL(payload as never)).resolves.toBe(
      'https://environment.example',
    )
    await expect(queuedImportsEnabled(payload as never)).resolves.toBe(false)

    settings = { queuedImports: 'deployment' }
    await expect(queuedImportsEnabled(payload as never)).resolves.toBe(true)
    process.env.OTSERVER_QUEUED_IMPORTS = 'off'
    await expect(queuedImportsEnabled(payload as never)).resolves.toBe(false)
  })

  it('accepts secure remote and loopback URLs, and rejects unsafe controller URLs', () => {
    for (const value of [
      '',
      'https://otserver.example/base',
      'http://localhost:3000',
      'http://[::1]:3000',
    ])
      expect(validateControllerURL(value)).toBe(true)

    for (const value of [
      'not a URL',
      'http://scanner.example',
      'ftp://localhost',
      'https://user:pass@otserver.example',
      'https://otserver.example?query=1',
      'https://otserver.example#fragment',
      `https://otserver.example/${'a'.repeat(2048)}`,
    ])
      expect(validateControllerURL(value)).not.toBe(true)
  })

  it('restricts settings reads and updates to administrators', async () => {
    const accessRequest = (isAdmin: boolean) => ({
      context: {},
      payload: {
        find: vi.fn(async () => ({ docs: [{ isAdmin, otterConfig: false, permissions: [] }] })),
      },
      user: { id: 'user-1', role: 'role-1' },
    })
    const read = ApplicationSettings.access!.read!
    const update = ApplicationSettings.access!.update!

    for (const access of [read, update]) {
      await expect(invoke(access, { req: accessRequest(true) })).resolves.toBe(true)
      await expect(invoke(access, { req: accessRequest(false) })).resolves.toBe(false)
      await expect(invoke(access, { req: { context: {} } })).resolves.toBe(false)
    }
  })

  it('starts an audited transaction for settings changes and records the administrator', async () => {
    const payload = {
      create: vi.fn(async () => ({ id: 'audit-1' })),
      find: vi.fn(async () => ({ docs: [] })),
    }
    const req = {
      context: {},
      headers: new Headers({ 'x-forwarded-for': '192.0.2.10' }),
      method: 'PATCH',
      payload,
      transactionID: Promise.resolve('transaction-1'),
      url: 'https://otserver.test/admin/globals/application-settings',
      user: { email: 'admin@example.test', id: 'admin-1', name: 'Admin' },
    }
    const args = { data: { queuedImports: 'enabled' } }
    const startTransaction = ApplicationSettings.hooks!.beforeOperation![0]!
    const auditChange = ApplicationSettings.hooks!.afterChange![0]!
    const doc = { controllerURL: 'https://otserver.example', queuedImports: 'enabled' }

    await expect(invoke(startTransaction, { args, operation: 'update', req })).resolves.toBe(args)
    await expect(
      invoke(auditChange, { doc, previousDoc: { queuedImports: 'deployment' }, req }),
    ).resolves.toBe(doc)
    expect(payload.create).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'audit-logs',
        data: expect.objectContaining({
          action: 'update',
          actorEmail: 'admin@example.test',
          targetCollection: 'application-settings',
        }),
        req,
      }),
    )
  })

  it('persists settings for administrators only and audits the change', async () => {
    const payload = await getPayload({ config })
    const adminRole = await ensureAdminRole(payload)
    const role = await payload.create({
      collection: 'user-roles',
      data: { name: `Settings reader ${randomUUID()}`, permissions: [] },
      overrideAccess: true,
    })
    const password = randomUUID()
    const admin = await payload.create({
      collection: 'users',
      data: {
        email: `settings-admin-${randomUUID()}@example.test`,
        name: 'Settings administrator',
        password,
        role: adminRole.id,
      },
      overrideAccess: true,
    })
    const reader = await payload.create({
      collection: 'users',
      data: {
        email: `settings-reader-${randomUUID()}@example.test`,
        name: 'Settings reader',
        password,
        role: role.id,
      },
      overrideAccess: true,
    })
    const adminReq = await createLocalReq({ user: admin }, payload)
    const readerReq = await createLocalReq({ user: reader }, payload)
    type SettingsDocument = {
      controllerURL?: string | null
      queuedImports?: 'deployment' | 'enabled' | 'disabled' | null
    }
    const settingsAPI = payload as unknown as {
      findGlobal: (args: {
        slug: string
        depth?: number
        overrideAccess?: boolean
        req: typeof adminReq
      }) => Promise<SettingsDocument>
      updateGlobal: (args: {
        slug: string
        data: SettingsDocument
        overrideAccess?: boolean
        req: typeof adminReq
      }) => Promise<SettingsDocument>
    }
    const previous = await settingsAPI.findGlobal({
      slug: 'application-settings',
      depth: 0,
      overrideAccess: true,
      req: adminReq,
    })

    try {
      await expect(
        settingsAPI.findGlobal({
          slug: 'application-settings',
          overrideAccess: false,
          req: readerReq,
        }),
      ).rejects.toMatchObject({ status: 403 })
      await expect(
        settingsAPI.updateGlobal({
          slug: 'application-settings',
          data: { queuedImports: 'disabled' },
          overrideAccess: false,
          req: readerReq,
        }),
      ).rejects.toMatchObject({ status: 403 })

      const updated = await settingsAPI.updateGlobal({
        slug: 'application-settings',
        data: { controllerURL: ' https://saved.example ', queuedImports: 'disabled' },
        overrideAccess: false,
        req: adminReq,
      })
      expect(updated).toMatchObject({
        controllerURL: 'https://saved.example',
        queuedImports: 'disabled',
      })
      process.env.OTSERVER_PUBLIC_URL = 'https://environment.example'
      process.env.OTSERVER_QUEUED_IMPORTS = 'on'
      await expect(configuredControllerURL(payload, adminReq)).resolves.toBe(
        'https://saved.example',
      )
      await expect(queuedImportsEnabled(payload, adminReq)).resolves.toBe(false)

      const audits = await payload.find({
        collection: 'audit-logs',
        depth: 0,
        limit: 5,
        overrideAccess: true,
        req: adminReq,
        sort: '-createdAt',
        where: { targetCollection: { equals: 'application-settings' } },
      })
      expect(audits.docs[0]).toMatchObject({
        action: 'update',
        actorEmail: admin.email,
        changes: {
          controllerURL: { after: 'https://saved.example' },
          queuedImports: { after: 'disabled' },
        },
      })
    } finally {
      await settingsAPI.updateGlobal({
        slug: 'application-settings',
        data: {
          controllerURL: previous.controllerURL || '',
          queuedImports: previous.queuedImports || 'deployment',
        },
        overrideAccess: true,
        req: adminReq,
      })
      await payload.delete({
        collection: 'users',
        id: reader.id,
        overrideAccess: true,
        req: adminReq,
      })
      await payload.delete({
        collection: 'users',
        id: admin.id,
        overrideAccess: true,
        req: adminReq,
      })
      await payload.delete({
        collection: 'user-roles',
        id: role.id,
        overrideAccess: true,
        req: adminReq,
      })
      await payload.destroy()
    }
  })
})
