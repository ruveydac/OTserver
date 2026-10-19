// @vitest-environment jsdom

import type { DocumentViewServerProps } from 'payload'
import { renderToStaticMarkup } from 'react-dom/server'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { getAuthorization } from '../../src/access/authorization'
import { loadAssetPanel } from '../../src/application/assetPanel'
import AssetView from '../../src/components/AssetView'

vi.mock('../../src/access/authorization', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../src/access/authorization')>()),
  getAuthorization: vi.fn(),
}))
vi.mock('../../src/application/assetPanel', () => ({ loadAssetPanel: vi.fn() }))
vi.mock('../../src/components/DeviceIdentity', () => ({ default: () => null }))
vi.mock('../../src/components/AssetVulnerabilityReviewActions', () => ({ default: () => null }))
vi.mock('@payloadcms/ui', () => ({ CopyToClipboard: () => null }))

type Panel = Awaited<ReturnType<typeof loadAssetPanel>>
type Finding = Panel['vulnerabilityFindings'][number]
const finding = (index: number, cvssScore?: number): Finding => ({
  assetID: 'asset-1',
  assetName: 'PLC 1',
  assessment: 'matched',
  revision: 0,
  status: 'unconfirmed',
  match: {
    cve: `CVE-2099-${String(1000 + index)}`,
    constraint: '< 2.0',
    cvssScore,
    knownExploited: index === 1,
    matchedVendor: 'example',
    matchedProduct: 'controller',
    version: '1.0',
    versionEvidence: 'firmware',
  },
})
const findings = [
  ...Array.from({ length: 27 }, (_, index) => finding(index + 1, 8)),
  finding(28, 9.8),
  finding(29, 5),
  finding(30, 0),
  finding(31),
  { ...finding(1, 8), assetID: 'module-1', assetName: 'CPU module' },
]
const longDescription = 'A crafted request interrupts controller operation. '.repeat(12)
let props: DocumentViewServerProps
let panel: Panel
let descriptionRead: ReturnType<typeof vi.fn>

const render = async (params: Record<string, string | string[]> = {}) => {
  const element = document.createElement('div')
  element.innerHTML = renderToStaticMarkup(
    await AssetView({ ...props, searchParams: { tab: 'security', ...params } }),
  )
  return element
}
const follow = (link: Element) => {
  const url = new URL(link.getAttribute('href')!, 'http://localhost')
  return render(Object.fromEntries(url.searchParams))
}
const rows = (element: Element) => [
  ...element.querySelectorAll('.asset-view__security-findings li'),
]

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(getAuthorization).mockResolvedValue({
    isAdmin: false,
    writableSiteIDs: [],
  } as never)
  panel = {
    definitions: { docs: [] },
    auditLogs: { docs: [] },
    observations: { docs: [] },
    topologyLinks: { docs: [] },
    endpointCount: { totalDocs: 0 },
    vulnerabilityFindings: findings,
    resolvedVulnerabilities: [],
    historyScopeTruncated: false,
  } as unknown as Panel
  vi.mocked(loadAssetPanel).mockImplementation(async () => panel)
  descriptionRead = vi.fn(async ({ where }) => ({
    docs: where.cve.in.map((cve: string) => ({
      cve,
      description: cve === 'CVE-2099-1001' ? longDescription : null,
      kevName: cve === 'CVE-2099-1029' ? 'Controller service interruption' : null,
    })),
  }))
  props = {
    doc: {
      id: 'asset-1',
      name: 'PLC 1',
      site: 'site-1',
      status: 'online',
      criticality: 'high',
      vulnerabilityCount: 31,
    },
    payload: { config: { routes: { admin: '/admin' } }, find: descriptionRead },
    initPageResult: { req: { user: { id: 'reader-1' } } },
    routeSegments: ['collections', 'assets', 'asset-1'],
  } as unknown as DocumentViewServerProps
})

describe('asset Security overview', () => {
  it('previews catalog descriptions and links each hardware finding to its full details', async () => {
    const view = await render()
    expect(rows(view)).toHaveLength(25)
    expect(view.textContent).toContain('Showing 1–25 of 32 open findings')
    const first = rows(view)[0]!
    const preview = first.querySelector('.asset-view__vulnerability-description')!.textContent!
    expect(preview).toMatch(/^A crafted request interrupts controller operation\./)
    expect(preview.length).toBeLessThanOrEqual(281)
    expect(preview).toMatch(/…$/)
    expect(view.textContent).not.toContain(longDescription)
    expect(first.querySelector('h3 a')?.getAttribute('href')).toBe(
      '/admin/collections/assets/asset-1/vulnerabilities?page=1#finding-module-1:CVE-2099-1001',
    )
    expect(rows(view)[1]?.textContent).toContain('PLC 1')
    expect(rows(view)[1]?.querySelector('h3 a')?.getAttribute('href')).toContain(
      '#finding-asset-1:CVE-2099-1001',
    )
    expect(view.textContent).toContain('No description available.')
    expect(descriptionRead).toHaveBeenCalledWith(
      expect.objectContaining({
        collection: 'vulnerabilities',
        limit: 25,
        overrideAccess: false,
        req: props.initPageResult.req,
        select: { cve: true, description: true, kevName: true },
      }),
    )
    const cves = descriptionRead.mock.calls[0]![0].where.cve.in
    expect(cves.length).toBe(new Set(cves).size)
    descriptionRead.mockClear()
    await render({ tab: 'overview' })
    expect(descriptionRead).not.toHaveBeenCalled()
  })

  it('follows every severity filter, keeps totals stable, and clears back to all findings', async () => {
    const initial = await render()
    for (const [severity, count] of [
      ['CRITICAL', 1],
      ['HIGH', 28],
      ['MEDIUM', 1],
      ['LOW', 1],
      ['UNRATED', 1],
    ] as const) {
      const view = await follow(
        initial.querySelector(`.asset-view__severity-summary a[href$="severity=${severity}"]`)!,
      )
      const active = view.querySelector('.asset-view__severity-summary [aria-current="page"]')!
      expect(active.textContent).toBe(`${severity[0] + severity.slice(1).toLowerCase()}${count}`)
      expect(rows(view)).toHaveLength(Math.min(count, 25))
      expect(
        rows(view).every((row) =>
          row.querySelector(`.asset-view__severity--${severity.toLowerCase()}`),
        ),
      ).toBe(true)
      expect(view.querySelector('.asset-view__severity-summary a')?.textContent).toBe(
        'All severities32',
      )
      if (severity === 'MEDIUM')
        expect(view.textContent).toContain('Controller service interruption')
      if (severity === 'LOW') expect(rows(view)[0]?.textContent).toContain('LOW 0')
      const cleared = await follow(
        view.querySelector('.asset-view__security-findings .asset-view__section-heading a')!,
      )
      expect(
        cleared.querySelector('.asset-view__severity-summary [aria-current="page"]')?.textContent,
      ).toBe('All severities32')
    }
  })

  it('preserves the filter while paging and clamps stale or malformed page parameters', async () => {
    const first = await render({ severity: 'HIGH' })
    const next = first.querySelector('.asset-view__security-findings .asset-view__pagination a')!
    expect(next.getAttribute('href')).toContain('severity=HIGH&vulnerabilityPage=2')
    const second = await follow(next)
    expect(rows(second)).toHaveLength(3)
    expect(second.textContent).toContain('Showing 26–28 of 28 high open findings')
    expect(
      second.querySelector('.asset-view__security-findings h3 a')?.getAttribute('href'),
    ).toContain('/vulnerabilities?page=2#finding-')
    expect(rows(await follow(second.querySelector('.asset-view__pagination a')!))).toHaveLength(25)
    expect(rows(await render({ severity: 'HIGH', vulnerabilityPage: '9999' }))).toHaveLength(3)
    for (const page of ['-1', '1.5', 'Infinity', 'invalid']) {
      expect((await render({ severity: 'high', vulnerabilityPage: page })).textContent).toContain(
        'Showing 1–25 of 28 high open findings',
      )
    }
    expect((await render({ severity: 'invalid' })).textContent).toContain(
      'Showing 1–25 of 32 open findings',
    )
  })

  it('distinguishes an empty filter from no findings and missing assessment', async () => {
    panel.vulnerabilityFindings = [finding(1, 8)]
    const filtered = await render({ severity: 'LOW' })
    expect(rows(filtered)).toHaveLength(0)
    expect(filtered.querySelector('[role="status"]')?.textContent).toContain(
      'No low open findings. Select another severity or clear the filter.',
    )
    expect(descriptionRead).not.toHaveBeenCalled()
    panel.vulnerabilityFindings = []
    expect((await render()).textContent).toContain('No open vulnerability findings for this asset')
    props.doc!.vulnerabilityCount = null
    expect((await render()).textContent).toContain(
      'has not been evaluated against a usable vulnerability catalog',
    )
  })
})
