import { EventEmitter } from 'node:events'
import { Readable } from 'node:stream'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ lookup: vi.fn(), request: vi.fn() }))

vi.mock('node:dns/promises', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:dns/promises')>()),
  lookup: mocks.lookup,
}))
vi.mock('node:https', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:https')>()),
  request: mocks.request,
}))

import { downloadFeed, isPublicFeedAddress, readFeed } from '../../src/vulnerabilities/feedIO'

const response = (statusCode: number, headers: Record<string, string> = {}, body = '') =>
  Object.assign(Readable.from(body ? [Buffer.from(body)] : []), { statusCode, headers })

const respondWith = (...responses: ReturnType<typeof response>[]) => {
  mocks.request.mockImplementation(((_options: unknown, callback: (value: unknown) => void) => {
    const request = new EventEmitter() as EventEmitter & { end: () => void }
    request.end = () => queueMicrotask(() => callback(responses.shift()))
    return request
  }) as never)
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.lookup.mockResolvedValue([{ address: '8.8.8.8', family: 4 }])
})

describe('public vulnerability feed requests', () => {
  it('rejects empty and non-public DNS results', async () => {
    mocks.lookup
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ address: '127.0.0.1', family: 4 }])

    await expect(downloadFeed('https://feeds.example/feed.json')).rejects.toThrow('public IP')
    await expect(downloadFeed('https://feeds.example/feed.json')).rejects.toThrow('public IP')
    expect(mocks.request).not.toHaveBeenCalled()
  })

  it('pins HTTPS requests to validated addresses and retries another resolved address', async () => {
    mocks.lookup.mockResolvedValue([
      { address: '8.8.8.8', family: 4 },
      { address: '1.1.1.1', family: 4 },
    ])
    mocks.request
      .mockImplementationOnce(((_options: unknown) => {
        const request = new EventEmitter() as EventEmitter & { end: () => void }
        request.end = () => queueMicrotask(() => request.emit('error', new Error('first failed')))
        return request
      }) as never)
      .mockImplementationOnce(((_options: unknown, callback: (value: unknown) => void) => {
        const request = new EventEmitter() as EventEmitter & { end: () => void }
        request.end = () => queueMicrotask(() => callback(response(200, {}, 'feed')))
        return request
      }) as never)

    await expect(
      readFeed(await downloadFeed('https://feeds.example/catalog.json?token=private')),
    ).resolves.toEqual(Buffer.from('feed'))

    const calls = mocks.request.mock.calls as unknown as [
      { hostname: string; path: string; servername: string; lookup: Function },
      unknown,
    ][]
    const options = calls[1]![0]
    expect(options).toMatchObject({
      hostname: 'feeds.example',
      path: '/catalog.json?token=private',
      servername: 'feeds.example',
    })
    const allAddresses = vi.fn()
    options.lookup('feeds.example', { all: true }, allAddresses)
    expect(allAddresses).toHaveBeenCalledWith(null, [{ address: '1.1.1.1', family: 4 }])
    const oneAddress = vi.fn()
    options.lookup('feeds.example', {}, oneAddress)
    expect(oneAddress).toHaveBeenCalledWith(null, '1.1.1.1', 4)
  })

  it('rejects when every resolved address fails to connect', async () => {
    mocks.request.mockImplementation(((_options: unknown) => {
      const request = new EventEmitter() as EventEmitter & { end: () => void }
      request.end = () => queueMicrotask(() => request.emit('error', new Error('connect failed')))
      return request
    }) as never)

    await expect(downloadFeed('https://feeds.example/catalog.json')).rejects.toThrow(
      'connect failed',
    )
  })

  it('follows safe redirects and rejects malformed or excessive redirects', async () => {
    respondWith(response(302, { location: '/final.json' }), response(200, {}, 'redirected'))
    await expect(readFeed(await downloadFeed('https://feeds.example/start.json'))).resolves.toEqual(
      Buffer.from('redirected'),
    )

    respondWith(response(302))
    await expect(downloadFeed('https://feeds.example/missing-location')).rejects.toThrow(
      'no destination',
    )

    respondWith(response(302, { location: 'https://user:secret@feeds.example/private' }))
    await expect(downloadFeed('https://feeds.example/credentials')).rejects.toThrow(
      'credentials or a fragment',
    )

    respondWith(...Array.from({ length: 6 }, () => response(302, { location: '/loop' })))
    await expect(downloadFeed('https://feeds.example/loop')).rejects.toThrow('redirect limit')
  })

  it('checks mapped IPv4 addresses while classifying public IPv4 and IPv6 ranges', () => {
    expect(isPublicFeedAddress('::ffff:8.8.8.8')).toBe(false)
    expect(isPublicFeedAddress('2606:4700:4700::1111')).toBe(true)
    expect(isPublicFeedAddress('2001:db8::1')).toBe(false)
    expect(isPublicFeedAddress('192.0.2.1')).toBe(false)
    expect(isPublicFeedAddress('224.0.0.1')).toBe(false)
    expect(isPublicFeedAddress('8.8.8.8')).toBe(true)
  })
})
