import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { gzipSync } from 'node:zlib'
import { describe, expect, it, vi } from 'vitest'

import { decodeFeed, readFeed, verifyFeed } from '../../src/vulnerabilities/feedIO'
import { importNvdFeed, nvdDocuments, NVD_BATCH_SIZE } from '../../src/vulnerabilities/nvd'
import { parseNvdFeed } from '../../src/vulnerabilities/parsers'

const collect = async (input: Parameters<typeof nvdDocuments>[0]) => {
  const documents = []
  for await (const document of nvdDocuments(input)) documents.push(document)
  return documents
}
const hash = (body: Buffer) => createHash('sha256').update(body).digest('hex')

describe('streamed NVD feeds', () => {
  it('preserves parsed evidence across single-byte UTF-8 and escaped-string boundaries', async () => {
    const body = await readFile(
      new URL('../vulnerability_files/nvdcve-2.0-2024.json', import.meta.url),
    )
    const input = JSON.parse(body.toString())
    input.vulnerabilities[0].cve.descriptions[0].value = 'Überwachung 🔒 "quoted" \\ newline\n'
    const bytes = Buffer.from(JSON.stringify(input))
    async function* chunks() {
      for (const byte of bytes) yield Buffer.from([byte])
    }
    const documents = await collect(chunks())
    expect(documents).toEqual(
      parseNvdFeed(input).map((doc) => ({
        ...doc,
        set: { ...doc.set, updatedAt: expect.any(Date) },
      })),
    )
    expect(await collect(Buffer.from('{"vulnerabilities":[]}'))).toEqual([])
  })

  it('rejects malformed envelopes, trailing errors, and failed integrity before writing', async () => {
    const record = '{"cve":{"id":"CVE-2024-12345"}}'
    const array = Array.from({ length: NVD_BATCH_SIZE + 1 }, () => record).join(',')
    const valid = Buffer.from(`{"vulnerabilities":[${array}]}`)
    const write = vi.fn(async () => {})
    for (const body of [
      '{}',
      '[]',
      '{"vulnerabilities":null}',
      '{"nested":{"vulnerabilities":[]}}',
      `{"vulnerabilities":[${array}]`,
      `{"vulnerabilities":[${array}],"vulnerabilities":[]}`,
      `${valid.toString()} trailing`,
    ])
      await expect(importNvdFeed(Buffer.from(body), write)).rejects.toThrow()
    await expect(
      importNvdFeed(
        decodeFeed(gzipSync(valid), {
          gzip: true,
          sha256: '0'.repeat(64),
        }),
        write,
      ),
    ).rejects.toThrow('SHA-256')
    await expect(
      importNvdFeed(
        decodeFeed(gzipSync(valid).subarray(0, -8), {
          gzip: true,
        }),
        write,
      ),
    ).rejects.toThrow()
    expect(write).not.toHaveBeenCalled()
  })

  it('bounds individual values, nesting, and download size and propagates read failures', async () => {
    await expect(
      collect(Buffer.from(`{"vulnerabilities":[],"extra":"${'x'.repeat(4 * 1024 * 1024 + 1)}"}`)),
    ).rejects.toThrow('value exceeds')
    await expect(
      collect(Buffer.from(`{"vulnerabilities":[],"extra":${'['.repeat(65)}0${']'.repeat(65)}}`)),
    ).rejects.toThrow('nesting limit')
    await expect(readFeed(verifyFeed(Buffer.alloc(11), 10))).rejects.toThrow('byte limit')
    async function* failed() {
      yield Buffer.from('{"vulnerabilities":[')
      throw new Error('upload read failed')
    }
    await expect(collect(failed())).rejects.toThrow('upload read failed')
  })

  it('writes bounded batches only after validation and removes staging on success and failure', async () => {
    const directory = await mkdtemp(path.join(tmpdir(), 'nvd-test-'))
    vi.stubEnv('TMPDIR', directory)
    try {
      const body = Buffer.from(
        JSON.stringify({
          vulnerabilities: Array.from({ length: 205 }, (_, i) => ({
            cve: { id: `CVE-2024-${10000 + i}`, published: '2024-01-01T00:00:00Z' },
          })),
        }),
      )
      let verified = false
      async function* source() {
        yield* decodeFeed(gzipSync(body), { gzip: true, sha256: hash(body) })
        verified = true
      }
      const sizes: number[] = []
      expect(
        await importNvdFeed(source(), async (batch) => {
          expect(verified).toBe(true)
          expect(batch[0].set.published).toBeInstanceOf(Date)
          sizes.push(batch.length)
        }),
      ).toBe(205)
      expect(sizes).toEqual([100, 100, 5])
      await expect(
        importNvdFeed(body, async () => {
          throw new Error('database unavailable')
        }),
      ).rejects.toThrow('database unavailable')
      expect(await readdir(directory)).toEqual([])
    } finally {
      vi.unstubAllEnvs()
      await rm(directory, { recursive: true, force: true })
    }
  })

  it('imports a feed larger than the child process heap without retaining the annual file', async () => {
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        '--max-old-space-size=96',
        '--import',
        'tsx',
        '--input-type=module',
        '-e',
        `
        import assert from 'node:assert/strict';
        import { importNvdFeed } from './src/vulnerabilities/nvd.ts';
        const record = JSON.stringify({cve: {id: 'CVE-2024-12345', descriptions: [{lang: 'en', value: 'x'.repeat(16384)}]}});
        async function* body() {
          yield Buffer.from('{"vulnerabilities":[');
          for (let i = 0; i < 12000; i++) yield Buffer.from((i ? ',' : '') + record);
          yield Buffer.from(']}');
        }
        let written = 0;
        const count = await importNvdFeed(body(), async batch => {
          assert.ok(batch.length <= 100);
          written += batch.length;
        });
        assert.equal(count, 12000);
        assert.equal(written, count);
        console.log(JSON.stringify({count, inputMiB: record.length * count / 1024 ** 2, maxRssMiB: process.resourceUsage().maxRSS / 1024}));
      `,
      ],
      { timeout: 120_000 },
    )
    const result = JSON.parse(stdout)
    expect(result.count).toBe(12000)
    expect(result.inputMiB).toBeGreaterThan(180)
    console.info('NVD memory regression:', result)
  }, 130_000)
})
