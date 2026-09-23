import config from '@/payload.config'
import { randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'
import { getPayload, handleEndpoints } from 'payload'

import { ensureAdminRole } from '../../src/collections/UserRoles'

describe('Payload 3.90 compatibility', () => {
  it('uses one aligned Payload release and narrowly permits validated XML uploads', async () => {
    const resolved = await config
    const versions = await Promise.all(
      ['payload', '@payloadcms/db-mongodb', '@payloadcms/next', '@payloadcms/ui'].map(
        async (name) => {
          const packageFile = new URL(`../../node_modules/${name}/package.json`, import.meta.url)
          return JSON.parse(await readFile(packageFile, 'utf8')).version as string
        },
      ),
    )
    expect(new Set(versions)).toEqual(new Set(['3.90.1']))
    expect(resolved.upload.requestSizeLimit).toBe(52 * 1024 * 1024)
    const imports = resolved.collections.find(({ slug }) => slug === 'asset-imports')
    expect(imports?.upload).toMatchObject({
      allowRestrictedFileTypes: true,
      mimeTypes: expect.arrayContaining(['application/xml', 'text/xml']),
    })
    expect(
      resolved.collections.filter(({ upload }) => upload && upload.allowRestrictedFileTypes),
    ).toHaveLength(1)
    expect(resolved.collections.find(({ slug }) => slug === 'users')?.auth).toMatchObject({
      useAPIKey: true,
    })
  })

  it('invalidates existing sessions when a password changes and accepts the new password', async () => {
    const payload = await getPayload({ config })
    const role = await ensureAdminRole(payload)
    const oldPassword = randomUUID()
    const newPassword = randomUUID()
    const user = await payload.create({
      collection: 'users',
      data: {
        email: `password-${randomUUID()}@example.test`,
        name: 'Payload password compatibility',
        password: oldPassword,
        role: role.id,
      },
    })
    try {
      const first = await payload.login({
        collection: 'users',
        data: { email: user.email, password: oldPassword },
      })
      const before = await handleEndpoints({
        config,
        path: '/api/users/me',
        request: new Request('http://localhost/api/users/me', {
          headers: { Authorization: `JWT ${first.token}` },
        }),
      })
      expect((await before.json()).user.id).toBe(user.id)

      await payload.update({
        collection: 'users',
        id: user.id,
        data: { password: newPassword },
        overrideAccess: false,
        user,
      })
      const after = await handleEndpoints({
        config,
        path: '/api/users/me',
        request: new Request('http://localhost/api/users/me', {
          headers: { Authorization: `JWT ${first.token}` },
        }),
      })
      expect((await after.json()).user).toBeNull()
      await expect(
        payload.login({ collection: 'users', data: { email: user.email, password: newPassword } }),
      ).resolves.toMatchObject({ user: { id: user.id } })
    } finally {
      await payload.delete({ collection: 'users', id: user.id })
    }
  })
})
