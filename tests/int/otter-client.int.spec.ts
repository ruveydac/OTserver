import config from '@/payload.config'
import { spawn, execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { getPayload, handleEndpoints } from 'payload'
import { describe, expect, it } from 'vitest'

// Explicit opt-in: the normal TypeScript suite does not require a Rust toolchain.
describe.skipIf(!process.env.OTTER_CLIENT_BIN)('Rust controller interoperability', () => {
  it.each(['bare', 'http'])('enrolls, imports, and restarts using %s URLs', async (format) => {
    const binary = resolve(process.env.OTTER_CLIENT_BIN!)
    const interfaces = JSON.parse(
      execFileSync(binary, ['interfaces', '--json'], { encoding: 'utf8' }),
    ) as { name: string }[]
    expect(interfaces.length).toBeGreaterThan(0)
    const payload = await getPayload({ config })
    const directory = await mkdtemp(join(tmpdir(), 'otter-client-'))
    const oldURL = process.env.OTSERVER_PUBLIC_URL
    const oldKey = process.env.OTSERVER_OTTER_ENCRYPTION_KEY
    process.env.OTSERVER_OTTER_ENCRYPTION_KEY = 'c'.repeat(64)
    const created: {
      collection:
        | 'sites'
        | 'user-roles'
        | 'users'
        | 'otter-scanners'
        | 'otter-profiles'
        | 'otter-runs'
        | 'asset-imports'
      id: string
    }[] = []
    const requests: { path: string; status: number }[] = []
    let client: ReturnType<typeof spawn> | undefined
    let output = ''
    const server = createServer(async (incoming, outgoing) => {
      try {
        const chunks: Buffer[] = []
        for await (const chunk of incoming) chunks.push(Buffer.from(chunk))
        const headers = new Headers()
        for (const [key, value] of Object.entries(incoming.headers)) {
          if (value !== undefined) headers.set(key, Array.isArray(value) ? value.join(', ') : value)
        }
        const path = incoming.url!
        const body = Buffer.concat(chunks)
        const response = await handleEndpoints({
          config,
          path,
          request: new Request(`${process.env.OTSERVER_PUBLIC_URL}${path}`, {
            method: incoming.method,
            headers,
            ...(body.length ? { body: new Uint8Array(body) } : {}),
          }),
        })
        requests.push({ path, status: response.status })
        outgoing.writeHead(response.status, Object.fromEntries(response.headers))
        outgoing.end(Buffer.from(await response.arrayBuffer()))
      } catch {
        outgoing.writeHead(500).end()
      }
    })
    try {
      await new Promise<void>((done) => server.listen(0, '127.0.0.1', done))
      const address = server.address() as { port: number }
      const url = `http://127.0.0.1:${address.port}`
      process.env.OTSERVER_PUBLIC_URL = url
      const site = await payload.create({
        collection: 'sites',
        data: { name: `Client lab ${randomUUID()}`, type: 'Test' },
      })
      created.push({ collection: 'sites', id: site.id })
      const role = await payload.create({
        collection: 'user-roles',
        data: {
          name: `Client operator ${randomUUID()}`,
          otterConfig: true,
          permissions: [{ site: site.id, access: 'read-write' }],
        },
      })
      created.push({ collection: 'user-roles', id: role.id })
      const apiKey = randomUUID()
      const user = await payload.create({
        collection: 'users',
        data: {
          name: 'Client lab',
          email: `client-${randomUUID()}@example.test`,
          password: randomUUID(),
          role: role.id,
          enableAPIKey: true,
          apiKey,
        },
      })
      created.push({ collection: 'users', id: user.id })
      const management = async (path: string, body: unknown) => {
        const response = await fetch(`${url}/api/otter/v1/${path}`, {
          method: 'POST',
          headers: {
            Origin: url,
            Authorization: `users API-Key ${apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(body),
        })
        expect(response.ok).toBe(true)
        return response.json()
      }
      const scanner = (await management('scanners', { name: 'Rust client', site: site.id })) as {
        enrollmentToken: string
        scanner: { id: string }
      }
      created.push({ collection: 'otter-scanners', id: scanner.scanner.id })
      const profile = await payload.create({
        collection: 'otter-profiles',
        overrideAccess: false,
        user,
        data: {
          name: 'Read-only client interoperability',
          site: site.id,
          scanner: scanner.scanner.id,
          configuration: {
            targets: ['192.0.2.1'],
            interface: interfaces[0].name,
            sourceMac: '00:11:22:33:44:55',
            noProtocols: true,
            noArp: true,
            noProfinet: true,
            noSnmp: true,
            noLldp: true,
          },
        },
      })
      created.push({ collection: 'otter-profiles', id: profile.id })
      const run = (await management('runs', {
        scannerID: scanner.scanner.id,
        profileID: profile.id,
      })) as { id: string }
      created.push({ collection: 'otter-runs', id: run.id })
      const startClient = (
        serverURL: string,
        enroll: boolean,
        overwriteStateDir = false,
        enrollmentToken = scanner.enrollmentToken,
      ) => {
        client = spawn(binary, [
          'controller',
          '--server-url',
          serverURL,
          '--state-dir',
          join(directory, 'state'),
          '--file-credentials',
          '--poll-seconds',
          '1',
          ...(enroll ? ['--enroll'] : []),
          ...(overwriteStateDir ? ['--overwrite-state-dir'] : []),
          '--ack-authorized',
        ])
        client.stdout!.on('data', (chunk) => {
          output += chunk.toString()
        })
        client.stderr!.on('data', (chunk) => {
          output += chunk.toString()
        })
        const exited = new Promise<never>((_, reject) => {
          client!.once('error', reject)
          client!.once('close', (code, signal) => {
            reject(new Error(`Rust controller exited (${code ?? signal}): ${output}`))
          })
        })
        client.stdin!.end(enroll ? `${enrollmentToken}\n` : undefined)
        return exited
      }
      let saved: {
        serverUrl?: string
        scanner?: { id: string; site: string }
        assignment?: { id: string; phase: string; importId?: string }
        fileCredential?: { credential: string }
      } = {}
      // A takeover must replace the previous controller binding without replaying its work or deleting exports.
      const stateDirectory = join(directory, 'state')
      await mkdir(stateDirectory, { mode: 0o700 })
      const previousState = JSON.stringify({
        serverUrl: 'https://previous-controller.example/',
        scanner: { id: 'previous-scanner', name: 'Previous scanner', site: 'previous-site' },
        credentialExpiresAt: '',
        fileCredential: {
          credential: 'p'.repeat(43),
          credentialExpiresAt: new Date(Date.now() + 86400_000).toISOString(),
        },
        assignment: { id: 'previous-run', phase: 'scanning', status: 'failed', importId: null },
        pendingImports: [{ id: 'previous-import', status: 'pending', retries: 0 }],
      })
      await writeFile(join(stateDirectory, 'agent-state.json'), previousState, { mode: 0o600 })
      await writeFile(
        join(stateDirectory, 'previous-run.otserver.json'),
        'retained previous export',
        { mode: 0o600 },
      )
      await expect(startClient(url, true, true, 'i'.repeat(43))).rejects.toThrow(
        /Scanner credential is expired or not accepted/,
      )
      expect(await readFile(join(stateDirectory, 'agent-state.json'), 'utf8')).toBe(previousState)
      await Promise.race([
        startClient(format === 'bare' ? `127.0.0.1:${address.port}` : url, true, true),
        expect
          .poll(
            async () => {
              saved = JSON.parse(
                await readFile(join(directory, 'state', 'agent-state.json'), 'utf8'),
              )
              return saved.assignment?.phase
            },
            { timeout: 30_000 },
          )
          .toBe('terminal'),
      ])
      expect(saved.serverUrl).toBe(`${url}/`)
      expect(saved.scanner).toMatchObject({ id: scanner.scanner.id, site: site.id })
      expect(saved.assignment?.id).toBe(run.id)
      expect(await readFile(join(stateDirectory, 'previous-run.otserver.json'), 'utf8')).toBe(
        'retained previous export',
      )
      expect(
        requests.some(
          ({ path }) => path.includes('previous-run') || path.includes('previous-import'),
        ),
      ).toBe(false)
      expect(saved.assignment?.importId).toBeTruthy()
      const finished = await payload.findByID({ collection: 'otter-runs', id: run.id, depth: 0 })
      expect(finished).toMatchObject({ status: 'completed', import: saved.assignment!.importId })
      const imported = await payload.findByID({
        collection: 'asset-imports',
        id: saved.assignment!.importId!,
        depth: 0,
      })
      expect(imported).toMatchObject({
        status: 'completed',
        source: 'otserver-otter',
        site: site.id,
        scanner: scanner.scanner.id,
        otterRun: run.id,
        executionMode: 'sync',
      })
      expect(requests).toContainEqual({ path: '/api/otter/v1/enroll', status: 201 })
      expect(requests).toContainEqual({ path: '/api/asset-imports', status: 201 })
      for (const action of ['start', 'heartbeat', 'finish'])
        expect(requests).toContainEqual({
          path: `/api/otter/v1/runs/${run.id}/${action}`,
          status: 200,
        })
      const exported = JSON.parse(
        await readFile(join(directory, 'state', `${run.id}.otserver.json`), 'utf8'),
      )
      expect(exported).toMatchObject({ format: 'otserver-scan', schemaVersion: 2, devices: [] })
      await new Promise<void>((done) => {
        client!.once('close', () => done())
        client!.kill('SIGKILL')
      })
      await payload.update({
        collection: 'otter-profiles',
        id: profile.id,
        overrideAccess: false,
        user,
        data: { configuration: { ...profile.configuration, interface: `missing-${randomUUID()}` } },
      })
      const failedRun = (await management('runs', {
        scannerID: scanner.scanner.id,
        profileID: profile.id,
      })) as { id: string }
      created.push({ collection: 'otter-runs', id: failedRun.id })
      const requestCount = requests.length
      await Promise.race([
        startClient(url, false),
        expect
          .poll(
            () =>
              requests
                .slice(requestCount)
                .some(({ path, status }) => path === '/api/otter/v1/poll' && status === 200),
            { timeout: 10_000 },
          )
          .toBe(true),
      ])
      expect(
        requests.filter(({ path, status }) => path === '/api/otter/v1/enroll' && status === 201),
      ).toHaveLength(1)
      expect(requests.filter(({ path }) => path === '/api/asset-imports')).toHaveLength(1)
      expect(
        requests.filter(({ path }) => path === `/api/otter/v1/runs/${run.id}/start`),
      ).toHaveLength(1)
      await expect
        .poll(
          async () => {
            const failed = await payload.findByID({
              collection: 'otter-runs',
              id: failedRun.id,
              depth: 0,
            })
            return { status: failed.status, message: failed.message }
          },
          { timeout: 15_000 },
        )
        .toEqual({
          status: 'failed',
          message: 'The selected network interface is not available on this scanner.',
        })
      // The run update can become visible before the finish handler returns its response.
      await expect
        .poll(() => requests, { timeout: 15_000 })
        .toContainEqual({
          path: `/api/otter/v1/runs/${failedRun.id}/finish`,
          status: 200,
        })
      expect(requests.filter(({ path }) => path === '/api/asset-imports')).toHaveLength(1)
      expect(output).not.toContain(scanner.enrollmentToken)
      expect(output).not.toContain(saved.fileCredential!.credential)
    } finally {
      if (client && client.exitCode === null && client.signalCode === null) {
        const stopped = new Promise<void>((done) => client!.once('close', () => done()))
        client.kill('SIGKILL')
        await stopped
      }
      await new Promise<void>((done) => server.close(() => done()))
      const site = created.find((document) => document.collection === 'sites')
      if (site) {
        const imports = await payload.find({
          collection: 'asset-imports',
          pagination: false,
          where: { site: { equals: site.id } },
        })
        for (const imported of imports.docs)
          await payload.delete({ collection: 'asset-imports', id: imported.id })
      }
      for (const document of created.reverse()) await payload.delete(document)
      await rm(directory, { recursive: true, force: true })
      if (oldURL === undefined) delete process.env.OTSERVER_PUBLIC_URL
      else process.env.OTSERVER_PUBLIC_URL = oldURL
      if (oldKey === undefined) delete process.env.OTSERVER_OTTER_ENCRYPTION_KEY
      else process.env.OTSERVER_OTTER_ENCRYPTION_KEY = oldKey
    }
  })
})
