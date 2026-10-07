import { describe, expect, it, vi } from 'vitest'

import { AuditLogs, withAudit } from '../../src/collections/AuditLogs'

const invoke = async (hook: unknown, args: unknown) =>
  (hook as (value: never) => unknown)(args as never)

describe('audit runtime boundaries', () => {
  it('wraps mutations and authentication hooks without wrapping audit logs again', async () => {
    const payload = {
      create: vi.fn().mockResolvedValue({ id: 'audit-1' }),
      find: vi.fn().mockResolvedValue({ docs: [] }),
    }
    const req = {
      context: {},
      headers: new Headers({ 'x-forwarded-for': '192.0.2.10, 192.0.2.11' }),
      method: 'PATCH',
      payload,
      transactionID: Promise.resolve('transaction-1'),
      url: 'https://otserver.test/admin/collections/assets/asset-1',
      user: { email: 'operator@example.test', id: 'user-1', name: 'Operator' },
    }
    const original = {
      slug: 'assets',
      hooks: { afterChange: [vi.fn()], afterDelete: [vi.fn()] },
    }
    const wrapped = withAudit(original as never)

    expect(withAudit(AuditLogs)).toBe(AuditLogs)
    expect(wrapped.hooks?.afterChange).toHaveLength(2)
    expect(wrapped.hooks?.afterDelete).toHaveLength(2)

    const args = { args: { data: {} }, operation: 'read', req }
    expect(await invoke(wrapped.hooks?.beforeOperation?.[0], args)).toBe(args.args)
    expect(
      await invoke(wrapped.hooks?.beforeOperation?.[0], {
        args: { data: {} },
        operation: 'create',
        req,
      }),
    ).toEqual({ data: {} })
    expect(payload.find).toHaveBeenCalledTimes(1)

    const doc = {
      asset: 'asset-1',
      id: 'asset-1',
      name: 'PLC 1',
      password: 'must not appear',
      site: { id: 'site-1' },
    }
    expect(
      await invoke(wrapped.hooks?.afterChange?.at(-1), {
        collection: { slug: 'assets' },
        doc,
        operation: 'create',
        previousDoc: undefined,
        req,
      }),
    ).toBe(doc)
    await invoke(wrapped.hooks?.afterDelete?.at(-1), {
      collection: { slug: 'assets' },
      doc,
      req,
    })

    const authenticated = withAudit({ auth: true, hooks: {}, slug: 'users' } as never)
    const user = { email: 'operator@example.test', id: 'user-1', name: 'Operator' }
    expect(
      await invoke(authenticated.hooks?.afterLogin?.at(-1), {
        collection: { slug: 'users' },
        req,
        user,
      }),
    ).toBe(user)
    await invoke(authenticated.hooks?.afterLogout?.at(-1), {
      collection: { slug: 'users' },
      req,
    })

    expect(payload.create).toHaveBeenCalledTimes(4)
    expect(payload.create.mock.calls.map(([call]) => call.data.action)).toEqual([
      'create',
      'delete',
      'login',
      'logout',
    ])
    expect(payload.create.mock.calls[0]?.[0]).toMatchObject({
      data: {
        actorType: 'user',
        asset: 'asset-1',
        ipAddress: '192.0.2.10',
        requestPath: '/admin/collections/assets/asset-1',
      },
    })
    expect(JSON.stringify(payload.create.mock.calls[0]?.[0].data)).not.toContain('must not appear')
  })
})
