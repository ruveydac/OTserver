import config from '@/payload.config'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { gzipSync } from 'node:zlib'
import { renderToStaticMarkup } from 'react-dom/server'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { getPayload, type Payload, type TypedUser } from 'payload'

import { ensureAssetClass } from '../../src/collections/AssetClasses'
import { ensureAdminRole } from '../../src/collections/UserRoles'
import AssetVulnerabilitiesView from '../../src/components/AssetVulnerabilitiesView'
import {
  CISA_CSAF_FEED_URLS,
  affectedProducts,
  CISA_KEV_URL,
  CSAF_AGGREGATOR_URL,
  downloadFeed,
  FIRST_NVD_YEAR,
  ICS_ADVISORY_URL,
  initializeVulnerabilityFeeds,
  NVD_FEED_BASE_URL,
  parseCisaCatalog,
  parseCpe,
  parseCsafAggregator,
  parseCsafDocument,
  parseCsafProviderMetadata,
  parseCsv,
  parseIcsAdvisories,
  parseNvdFeed,
  parseNvdMeta,
  parseRolieFeed,
  searchKeys,
  syncVulnerabilityFeeds,
  upsertVulnerabilities,
} from '../../src/vulnerabilities/feeds'
import {
  assetFingerprint,
  assignVulnerabilityCount,
  bySeverity,
  catalogIsLoaded,
  compareVersions,
  countAssetVulnerabilities,
  describeConstraint,
  findAssetVulnerabilities,
  matchAssetVulnerabilities,
  normalizeKey,
  productSearchKey,
  recountAssetVulnerabilities,
  satisfiesConstraint,
  searchTokens,
  similarity,
  versionEvidence,
  vulnerabilityCandidateQuery,
} from '../../src/vulnerabilities/match'

const fixture = async (name: string) =>
  JSON.parse(
    await readFile(new URL(`../vulnerability_files/${name}`, import.meta.url), 'utf8'),
  ) as unknown

const textFixture = (name: string) =>
  readFile(new URL(`../vulnerability_files/${name}`, import.meta.url), 'utf8')

const nvdFeed = () => fixture('nvdcve-2.0-2024.json')
const kevCatalog = () => fixture('known_exploited_vulnerabilities.json')
const csafAggregator = () => fixture('csaf-aggregator.json')
const csafProviderMetadata = () => fixture('csaf-provider-metadata.json')
const csafRolie = () => fixture('csaf-rolie.json')
const csafDocument = () => fixture('csaf-document.json')
const icsCsv = () => textFixture('ics-advisory-project.csv')

const feedDocument = {
  firmwareVersion: 'V2.5',
  hardwareVersion: '1.0',
  model: 'SIMATIC S7-1500 CPU 1516-3 PN/DP',
  operatingSystem: '',
  vendor: 'Siemens AG',
}

describe('vocabulary normalization', () => {
  it('normalizes vendors, products, and tokens', () => {
    expect(normalizeKey('Siemens AG')).toBe('siemensag')
    expect(normalizeKey('SIMATIC S7-1500')).toBe('simatics71500')
    expect(productSearchKey('simatic_s7-1500_firmware')).toBe('simatics71500')
    expect(productSearchKey('simatic_s7-1500')).toBe('simatics71500')
    expect(searchTokens('Siemens AG, SIMATIC S7-1500 Firmware Series')).toEqual([
      'siemens',
      'simatic',
      's7',
      '1500',
    ])
    expect(searchTokens('')).toEqual([])
  })

  it('scores fuzzy text similarity', () => {
    expect(similarity('siemens', 'siemens')).toBe(1)
    expect(similarity('siemensag', 'siemens')).toBeGreaterThan(0.8)
    expect(similarity('siemens', 'rockwell')).toBeLessThan(0.3)
    expect(similarity('', 'siemens')).toBe(0)
    expect(similarity('a', 'b')).toBe(0)
    expect(assetFingerprint(feedDocument)).toBe(
      'Siemens AG|SIMATIC S7-1500 CPU 1516-3 PN/DP||V2.5|1.0',
    )
  })
})

describe('version evaluation', () => {
  it('compares version segments numerically and alphabetically', () => {
    expect(compareVersions('1.2.10', '1.2.9')).toBe(1)
    expect(compareVersions('V2.5', '2.5')).toBe(0)
    expect(compareVersions('2.5', '2.5.0')).toBe(0)
    expect(compareVersions('2.9', '3.0')).toBe(-1)
    expect(compareVersions('1.0a', '1.0b')).toBe(-1)
    expect(compareVersions('', '')).toBe(0)
  })

  it('applies CPE version constraints and describes them', () => {
    const range = {
      part: 'a',
      product: 'simatic_s7-1500_firmware',
      vendor: 'siemens',
      version: '*',
      versionEndExcluding: '2.9',
      versionStartIncluding: '1.0',
    }
    expect(satisfiesConstraint('2.5', range)).toBe(true)
    expect(satisfiesConstraint('2.9', range)).toBe(false)
    expect(satisfiesConstraint('0.9', range)).toBe(false)
    expect(describeConstraint(range)).toBe('>= 1.0, < 2.9')

    expect(satisfiesConstraint('3.0', { ...range, version: '3.0' })).toBe(true)
    expect(satisfiesConstraint('2.5', { ...range, version: '3.0' })).toBe(false)
    expect(
      satisfiesConstraint('2.9', {
        part: 'a',
        product: 'p',
        vendor: 'v',
        version: '*',
        versionEndIncluding: '2.9',
        versionStartExcluding: '1.0',
      }),
    ).toBe(true)
    expect(describeConstraint({ part: 'a', product: 'p', vendor: 'v', version: '*' })).toBe(
      'all versions',
    )
    // A CPE without version information can never be confirmed.
    expect(satisfiesConstraint('2.5', { part: 'a', product: 'p', vendor: 'v', version: '-' })).toBe(
      false,
    )
    expect(
      satisfiesConstraint('1.0', { part: 'a', product: 'p', vendor: 'v', version: '1.0' }),
    ).toBe(true)
  })

  it('routes CPE parts to the matching asset version fields', () => {
    expect(versionEvidence(feedDocument, 'a')).toEqual([
      { source: 'firmware version', version: 'V2.5' },
    ])
    expect(versionEvidence({ model: 'SIMATIC S7-1500 V2.5' }, 'a')).toEqual([
      { source: 'model', version: 'V2.5' },
    ])
    expect(versionEvidence(feedDocument, 'h')).toEqual([
      { source: 'hardware version', version: '1.0' },
    ])
    expect(
      versionEvidence({ operatingSystem: 'Windows 10 Pro 1607', vendor: 'Microsoft' }, 'o'),
    ).toEqual([{ source: 'operating system', version: '1607' }])
    expect(versionEvidence({ operatingSystem: 'Ubuntu 22.04 LTS' }, 'o')).toEqual([
      { source: 'operating system', version: '22.04' },
    ])
    expect(versionEvidence({ firmwareVersion: 'V2.8.0' }, 'o')).toEqual([
      { source: 'firmware version', version: 'V2.8.0' },
    ])
    expect(versionEvidence({ vendor: 'Siemens' }, 'a')).toEqual([])
    expect(versionEvidence({}, 'h')).toEqual([])
    expect(versionEvidence({}, 'o')).toEqual([])
  })
})

describe('feed parsing', () => {
  it('parses CPE strings defensively', () => {
    expect(parseCpe('cpe:2.3:a:siemens:simatic_s7-1500_firmware:*:*:*:*:*:*:*:*')).toEqual({
      part: 'a',
      product: 'simatic_s7-1500_firmware',
      vendor: 'siemens',
      version: '*',
    })
    expect(parseCpe('cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*')).toMatchObject({
      part: 'o',
      version: '1607',
    })
    expect(parseCpe('cpe:2.3:a:vendor:product\\:with\\:colons:1.0:*:*:*:*:*:*:*')).toMatchObject({
      product: 'product:with:colons',
    })
    expect(parseCpe('cpe:2.3:a:*:product:1.0:*:*:*:*:*:*:*')).toBeUndefined()
    expect(parseCpe('cpe:2.3:a:vendor:*:1.0:*:*:*:*:*:*:*')).toBeUndefined()
    expect(parseCpe('cpe:/a:legacy')).toBeUndefined()
    expect(parseCpe(42)).toBeUndefined()
    expect(parseCpe('cpe:2.3:a')).toBeUndefined()
  })

  it('reads the published NVD feed metadata', () => {
    expect(
      parseNvdMeta(
        'lastModifiedDate:2026-09-10T03:00:00-04:00\nsize:247350327\nzipSize:20165415\ngzSize:20165279\nsha256:A2695F3AE4C4F6F89125C8C135176CA997642248C4F1FA6BD590D03BC7D80435\n',
      ),
    ).toEqual({
      lastModifiedDate: '2026-09-10T03:00:00-04:00',
      sha256: 'a2695f3ae4c4f6f89125c8c135176ca997642248c4f1fa6bd590d03bc7d80435',
      size: 247350327,
    })
    expect(parseNvdMeta('garbage')).toEqual({})
  })

  it('flattens configurations into affected products', async () => {
    const documents = parseNvdFeed(await nvdFeed())
    expect(documents.map(({ cve }) => cve)).toEqual([
      'CVE-2099-0001',
      'CVE-2099-0002',
      'CVE-2099-0003',
      'CVE-2099-0004',
      'CVE-2099-0005',
      'CVE-2099-0006',
      'CVE-2099-0007',
    ])

    const [first] = documents
    expect(first.set).toMatchObject({
      cvssScore: 9.8,
      cvssSeverity: 'CRITICAL',
      references: ['https://cert-portal.example.test/advisory/CVE-2099-0001'],
      status: 'Analyzed',
    })
    expect(first.set.description).toContain('A stack-based buffer overflow')
    // Negated nodes and non-vulnerable matches never become evidence.
    expect(first.set.affected).toEqual([
      {
        part: 'a',
        product: 'simatic_s7-1500_firmware',
        vendor: 'siemens',
        version: '*',
        versionEndExcluding: '2.9',
        versionStartIncluding: '1.0',
      },
    ])
    expect(first.set.vendors).toEqual(['siemens'])
    expect(first.set.products).toEqual(['simatics71500'])
    expect(first.set.productTokens).toEqual(['simatic', 's7', '1500'])

    expect(documents[1].set).toMatchObject({ cvssScore: 7.5, cvssSeverity: 'HIGH' })
    expect(documents[3].set.affected).toEqual([])
    expect(documents[4].set).toMatchObject({ affected: [], status: 'Rejected' })
    expect(documents[6].set.affected).toEqual([
      { part: 'o', product: 'windows_10', vendor: 'microsoft', version: '1607' },
    ])
  })

  it('skips malformed and empty feed input', () => {
    expect(() => parseNvdFeed(undefined)).toThrow('vulnerabilities array')
    expect(() => parseNvdFeed({ vulnerabilities: 'nope' })).toThrow('vulnerabilities array')
    expect(parseNvdFeed({ vulnerabilities: [{ cve: { id: 'nope' } }, { cve: {} }, null] })).toEqual(
      [],
    )
    expect(
      parseNvdFeed({
        vulnerabilities: [
          {
            cve: {
              configurations: 'junk',
              descriptions: [],
              id: 'CVE-2099-0009',
              metrics: { cvssMetricV31: [{ cvssData: { baseScore: 'NaN' } }] },
            },
          },
        ],
      })[0].set,
    ).toMatchObject({ affected: [], description: '', products: [], references: [] })
    expect(affectedProducts(undefined)).toEqual([])
    expect(searchKeys([])).toEqual({ products: [], productTokens: [], vendors: [] })
    expect(searchKeys([{ part: 'a', product: 'p', vendor: '*', version: '*' }])).toEqual({
      products: ['p'],
      productTokens: [],
      vendors: [],
    })
  })

  it('parses the CISA KEV catalog', async () => {
    const catalog = parseCisaCatalog(await kevCatalog())
    expect(catalog.catalogVersion).toBe('2026.09.10')
    expect(catalog.dateReleased).toBeInstanceOf(Date)
    expect(catalog.documents.map(({ cve }) => cve)).toEqual(['CVE-2099-0001', 'CVE-2099-0008'])

    const [exploited] = catalog.documents
    expect(exploited.set).toMatchObject({
      knownExploited: true,
      kevProduct: 'SIMATIC S7-1500',
      kevRansomwareUse: 'Known',
      kevVendor: 'Siemens',
    })
    expect(exploited.set.kevDateAdded).toBeInstanceOf(Date)
    expect(exploited.setOnInsert).toMatchObject({
      products: ['simatics71500'],
      vendors: ['siemens'],
    })
    expect(catalog.documents[1].setOnInsert).toMatchObject({
      products: ['exampleproduct'],
      vendors: ['example'],
    })

    expect(() => parseCisaCatalog(undefined)).toThrow('expected catalog schema')
    expect(() =>
      parseCisaCatalog({
        catalogVersion: '1',
        count: 1,
        dateReleased: '2026-09-10T14:00:00.000Z',
        vulnerabilities: [{ cveID: 'bad' }],
      }),
    ).toThrow('invalid entry')
  })

  it('discovers and parses CSAF 2.0 provider advisories', async () => {
    expect(parseCsafAggregator(await csafAggregator())).toEqual([
      'https://aggregator.certvde.com/.well-known/csaf-aggregator/example/provider-metadata.json',
    ])
    expect(parseCsafProviderMetadata(await csafProviderMetadata())).toEqual([
      'https://aggregator.certvde.com/.well-known/csaf-aggregator/example/white/feed.json',
    ])
    expect(parseRolieFeed(await csafRolie())).toMatchObject({
      updated: '2026-09-11T06:30:00Z',
      entries: [
        {
          url: 'https://aggregator.certvde.com/.well-known/csaf-aggregator/example/white/2026/example-2026-001.json',
        },
      ],
    })
    expect(parseCsafDocument(await csafDocument())).toMatchObject([
      {
        cve: 'CVE-2099-0100',
        set: {
          affected: [
            {
              part: 'a',
              product: 'CSAF Test Controller',
              vendor: 'CSAF Test Vendor',
              version: '*',
              versionEndExcluding: '34.015',
            },
          ],
          cvssScore: 8.8,
          cvssSeverity: 'HIGH',
          status: 'CSAF',
        },
      },
    ])

    expect(() => parseCsafAggregator({ aggregator_version: '1.0' })).toThrow('version 2.0')
    expect(() => parseCsafProviderMetadata({ metadata_version: '2.0' })).toThrow('metadata')
    expect(() => parseRolieFeed({ feed: { entry: [], updated: 'invalid' } })).toThrow('ROLIE')
    expect(() => parseCsafDocument({ document: {}, vulnerabilities: [] })).toThrow('version 2.0')
  })

  it('maps every CSAF product-tree shape onto affected version constraints', () => {
    const ranged = (id: string, range: string) => ({
      category: 'product_version_range',
      name: range,
      product: { name: `Ranged Product ${range}`, product_id: id },
    })
    const documents = parseCsafDocument({
      document: { csaf_version: '2.0' },
      product_tree: {
        branches: [
          {
            category: 'vendor',
            name: 'Ranged Vendor',
            branches: [
              {
                branches: [
                  ranged('P1', '<1.5'),
                  ranged('P2', '<=2.0'),
                  ranged('P3', '>3.0'),
                  ranged('P4', '>=4.0'),
                  ranged('P5', '5.0'),
                ],
                category: 'product_name',
                name: 'Ranged Product',
              },
              {
                // A CPE under a version branch keeps the CPE identity and takes the branch bound.
                category: 'product_version',
                name: '6.0',
                product: {
                  name: 'CPE Product 6.0',
                  product_id: 'P6',
                  product_identification_helper: {
                    cpe: 'cpe:2.3:a:cpevendor:cpeproduct:9.9:*:*:*:*:*:*:*',
                  },
                },
              },
              {
                // A CPE with no surrounding version branch keeps its own CPE version.
                category: 'product_name',
                name: 'Bare CPE Product',
                product: {
                  name: 'Bare CPE Product',
                  product_id: 'P7',
                  product_identification_helper: {
                    cpe: 'cpe:2.3:o:barevendor:bareproduct:7.0:*:*:*:*:*:*:*',
                  },
                },
              },
            ],
          },
        ],
        full_product_names: [
          {
            name: 'Full CPE Product',
            product_id: 'P8',
            product_identification_helper: {
              cpe: 'cpe:2.3:a:fullvendor:fullproduct:8.0:*:*:*:*:*:*:*',
            },
          },
          // No CPE and no product id: nothing can be identified, so both are ignored.
          { name: 'Unidentified Product' },
          { name: 'No CPE Product', product_id: 'P9' },
        ],
      },
      vulnerabilities: [
        {
          cve: 'not-a-cve',
          product_status: { known_affected: ['P1'] },
        },
        {
          cve: 'CVE-2099-0300',
          notes: [{ category: 'other', text: 'Fallback note text' }],
          product_status: {
            known_affected: ['P1', 'P2', 'P3', 'P4', 'P5', 'P6', 'P7', 'P8', 'P9', 'missing'],
          },
          scores: [{ cvss_v4: { baseScore: 9.3 } }],
        },
        {
          cve: 'CVE-2099-0301',
          product_status: { known_affected: ['P1'] },
          scores: [{ cvss_v2: { baseScore: 4.4, baseSeverity: 'MEDIUM' } }],
        },
        {
          cve: 'CVE-2099-0302',
          product_status: { known_affected: ['P1'] },
          scores: [{ cvss_v3: {} }],
        },
      ],
    })

    expect(documents.map(({ cve }) => cve)).toEqual([
      'CVE-2099-0300',
      'CVE-2099-0301',
      'CVE-2099-0302',
    ])
    expect(documents[0].set.affected).toEqual([
      {
        part: 'a',
        product: 'Ranged Product',
        vendor: 'Ranged Vendor',
        version: '*',
        versionEndExcluding: '1.5',
      },
      {
        part: 'a',
        product: 'Ranged Product',
        vendor: 'Ranged Vendor',
        version: '*',
        versionEndIncluding: '2.0',
      },
      {
        part: 'a',
        product: 'Ranged Product',
        vendor: 'Ranged Vendor',
        version: '*',
        versionStartExcluding: '3.0',
      },
      {
        part: 'a',
        product: 'Ranged Product',
        vendor: 'Ranged Vendor',
        version: '*',
        versionStartIncluding: '4.0',
      },
      { part: 'a', product: 'Ranged Product', vendor: 'Ranged Vendor', version: '5.0' },
      { part: 'a', product: 'cpeproduct', vendor: 'cpevendor', version: '6.0' },
      { part: 'o', product: 'bareproduct', vendor: 'barevendor', version: '7.0' },
      { part: 'a', product: 'fullproduct', vendor: 'fullvendor', version: '8.0' },
    ])
    // A cvss_v4 metric without a severity still yields its score, and the note fallback is used.
    expect(documents[0].set).toMatchObject({ cvssScore: 9.3, description: 'Fallback note text' })
    expect(documents[0].set).not.toHaveProperty('cvssSeverity')
    expect(documents[1].set).toMatchObject({
      cvssScore: 4.4,
      cvssSeverity: 'MEDIUM',
      description: '',
    })
    // A metric without a base score contributes neither score nor severity.
    expect(documents[2].set).not.toHaveProperty('cvssScore')
    expect(documents[2].set).not.toHaveProperty('cvssSeverity')
  })

  it('reads quoted CSV fields containing commas, quotes, and newlines', () => {
    expect(parseCsv('a,b\r\n1,"x,y"\r\n')).toEqual([
      ['a', 'b'],
      ['1', 'x,y'],
    ])
    expect(parseCsv('"say ""hi""","line\nbreak"')).toEqual([['say "hi"', 'line\nbreak']])
    expect(parseCsv('')).toEqual([])
  })

  it('merges ICS Advisory Project rows per CVE and rejects malformed values', async () => {
    const result = parseIcsAdvisories(await icsCsv())
    expect(result.dateReleased).toEqual(new Date('2026-09-11T00:00:00.000Z'))
    expect(result.documents.map(({ cve }) => cve)).toEqual([
      'CVE-2099-0201',
      'CVE-2099-0202',
      'CVE-2099-0001',
      'CVE-2099-0210',
      'CVE-2099-0212',
    ])

    // Two advisories report CVE-2099-0201; the higher advisory score and the union of sectors win.
    expect(result.documents[0].set).toMatchObject({
      icsAdvisory: ['ICSA-26-001-01', 'ICSMA-26-002-01'],
      icsDistribution: 'Worldwide',
      icsHeadquarters: 'Germany',
      icsSectors: ['Critical Manufacturing', 'Energy', 'Chemical'],
    })
    expect(result.documents[0].setOnInsert).toMatchObject({
      cvssScore: 9.1,
      cvssSeverity: 'CRITICAL',
      description: 'CISA ICS advisory ICSA-26-001-01: Example Controller',
      modified: new Date('2026-09-11T00:00:00.000Z'),
      products: ['examplecontroller'],
      published: new Date('2026-08-01T00:00:00.000Z'),
      references: [
        'https://www.cisa.gov/news-events/ics-advisories/icsa-26-001-01',
        'https://www.cisa.gov/news-events/ics-advisories/icsma-26-002-01',
      ],
      vendors: ['examplevendor', 'example', 'vendor'],
    })
    expect(result.documents[1].setOnInsert).toMatchObject({ cvssScore: 7.5, cvssSeverity: 'HIGH' })
    expect(result.documents[2].set).toMatchObject({ icsAdvisory: ['ICSA-26-005-01'] })

    // An out-of-range score, an unknown severity, blank distribution/headquarters, unparseable
    // dates, and an empty sector segment all degrade to omitted values instead of bad data.
    const [degenerate] = result.documents.slice(3)
    expect(degenerate?.set).toMatchObject({
      icsAdvisory: ['ICSA-26-006-01'],
      icsSectors: ['Critical Manufacturing'],
    })
    expect(degenerate?.set).not.toHaveProperty('icsDistribution')
    expect(degenerate?.set).not.toHaveProperty('icsHeadquarters')
    expect(degenerate?.setOnInsert).not.toHaveProperty('cvssScore')
    expect(degenerate?.setOnInsert).not.toHaveProperty('cvssSeverity')
    expect(degenerate?.setOnInsert).not.toHaveProperty('published')
    expect(degenerate?.setOnInsert).not.toHaveProperty('modified')
    // Row seven has no vendor, so it cannot identify a product and is dropped entirely.
    expect(result.documents.map(({ cve }) => cve)).not.toContain('CVE-2099-0211')
    // An in-range score is kept even when the severity label is not a CVSS level.
    expect(result.documents[4]?.setOnInsert).toMatchObject({ cvssScore: 7 })
    expect(result.documents[4]?.setOnInsert).not.toHaveProperty('cvssSeverity')

    // Advisory context is supplementary, so it never carries matchable version evidence.
    expect(result.documents[0].set).not.toHaveProperty('affected')

    // Row three carries only malformed CVE tokens and a non-numeric score, and row four is
    // truncated, so neither contributes a document.
    expect(result.documents.map(({ cve }) => cve)).not.toContain('CVE-2099-0203')
    const [header] = (await icsCsv()).split('\r\n')
    expect(parseIcsAdvisories(`${header}\r\n`).documents).toEqual([])
    expect(() => parseIcsAdvisories('Vendor,Product\nExample,Example\n')).toThrow('missing columns')
  })
})

describe('asset matching', () => {
  it('counts only entries whose version constraints match', async () => {
    const candidates = parseNvdFeed(await nvdFeed()).map(({ cve, set }) => ({
      affected: set.affected as never,
      cve,
      cvssScore: set.cvssScore as number,
      cvssSeverity: set.cvssSeverity as string,
      knownExploited: false,
    }))

    const [match] = matchAssetVulnerabilities(feedDocument, candidates)
    expect(match).toMatchObject({
      constraint: '>= 1.0, < 2.9',
      cve: 'CVE-2099-0001',
      cvssSeverity: 'CRITICAL',
      matchedProduct: 'simatic_s7-1500_firmware',
      matchedVendor: 'siemens',
      version: 'V2.5',
      versionEvidence: 'firmware version',
    })
    expect(matchAssetVulnerabilities(feedDocument, candidates)).toHaveLength(1)

    // The excluded upper bound and the single affected release both stay out.
    expect(
      matchAssetVulnerabilities({ ...feedDocument, firmwareVersion: 'V2.9' }, candidates).map(
        ({ cve }) => cve,
      ),
    ).toEqual([])
    expect(
      matchAssetVulnerabilities({ ...feedDocument, firmwareVersion: '3.0' }, candidates).map(
        ({ cve }) => cve,
      ),
    ).toEqual(['CVE-2099-0002'])

    // Hardware CPEs use the hardware revision, not the firmware.
    expect(
      matchAssetVulnerabilities(
        { hardwareVersion: '1.0', model: 'SCALANCE X108', vendor: 'Siemens' },
        candidates,
      ).map(({ cve }) => cve),
    ).toEqual(['CVE-2099-0006'])

    // A different vendor never matches, and "all versions" needs a reported version.
    expect(
      matchAssetVulnerabilities(
        { firmwareVersion: '32.011', model: 'CompactLogix 5380', vendor: 'Rockwell Automation' },
        candidates,
      ).map(({ cve }) => cve),
    ).toEqual(['CVE-2099-0003'])
    expect(
      matchAssetVulnerabilities(
        { model: 'CompactLogix 5380', vendor: 'Rockwell Automation' },
        candidates,
      ),
    ).toEqual([])

    expect(
      matchAssetVulnerabilities(
        { model: '', operatingSystem: 'Windows 10 Pro 1607', vendor: 'Microsoft' },
        candidates,
      ).map(({ cve }) => cve),
    ).toEqual(['CVE-2099-0007'])

    // Without vendor or product evidence nothing can be confirmed.
    expect(matchAssetVulnerabilities({ vendor: 'Siemens AG' }, candidates)).toEqual([])
    expect(matchAssetVulnerabilities({ model: 'SIMATIC S7-1500' }, candidates)).toEqual([])
    expect(matchAssetVulnerabilities({}, candidates)).toEqual([])
    expect(matchAssetVulnerabilities(feedDocument, [])).toEqual([])
    expect(matchAssetVulnerabilities({ ...feedDocument, model: '???' }, candidates)).toEqual([])
  })

  it('matches a Siemens S7-1500 firmware CPE from the NVD', () => {
    expect(
      matchAssetVulnerabilities(
        {
          firmwareVersion: 'V2.8.0',
          model: 'SIMATIC S7-1500 CPU',
          vendor: 'Siemens AG',
        },
        [
          {
            affected: [
              {
                part: 'o',
                product: 's7-1500_cpu_firmware',
                vendor: 'siemens',
                version: '*',
                versionEndExcluding: '2.9.2',
              },
            ],
            cve: 'CVE-2020-15782',
            cvssScore: 9.8,
            cvssSeverity: 'CRITICAL',
            knownExploited: false,
          },
        ],
      ),
    ).toMatchObject([
      {
        cve: 'CVE-2020-15782',
        matchedProduct: 's7-1500_cpu_firmware',
        version: 'V2.8.0',
        versionEvidence: 'firmware version',
      },
    ])
  })

  it('orders matches by exploitation, then severity, then identifier', () => {
    const match = (cve: string, cvssScore?: null | number, knownExploited = false) => ({
      constraint: 'all versions',
      cve,
      cvssScore,
      cvssSeverity: null,
      knownExploited,
      matchedProduct: 'p',
      matchedVendor: 'v',
      version: '1.0',
      versionEvidence: 'firmware version',
    })
    expect(
      [
        match('CVE-2099-0002', 9.8),
        match('CVE-2099-0001', null),
        match('CVE-2099-0004', 5.0, true),
        match('CVE-2099-0003', 7.5),
      ]
        .sort(bySeverity)
        .map(({ cve }) => cve),
    ).toEqual(['CVE-2099-0004', 'CVE-2099-0002', 'CVE-2099-0003', 'CVE-2099-0001'])
  })

  it('builds bounded candidate queries from product evidence', () => {
    expect(vulnerabilityCandidateQuery(feedDocument)).toEqual({
      or: [
        { products: { in: ['simatics71500cpu15163pndp'] } },
        { productTokens: { in: ['simatic', 's7', '1500', '1516'] } },
      ],
    })
    expect(vulnerabilityCandidateQuery({ vendor: 'Siemens' })).toBeUndefined()
    expect(vulnerabilityCandidateQuery({ model: 'AB' })).toEqual({
      or: [{ products: { in: ['ab'] } }],
    })
    expect(vulnerabilityCandidateQuery({})).toBeUndefined()
  })
})

describe('downloadFeed', () => {
  it('verifies checksums, unpacks gzip, and rejects bad responses', async () => {
    const body = Buffer.from(JSON.stringify({ ok: true }))
    const gzipped = gzipSync(body)
    // NVD publishes the SHA-256 of the *uncompressed* payload, never of the `.gz` file.
    const sha256 = createHash('sha256').update(body).digest('hex')
    const compressedSha256 = createHash('sha256').update(gzipped).digest('hex')
    const server = createServer((request, response) => {
      if (request.url === '/missing') {
        response.writeHead(404).end()
        return
      }
      if (request.url === '/feed.json.gz') {
        response.writeHead(200, { 'content-encoding': 'identity' }).end(gzipped)
        return
      }
      response.writeHead(200).end(body)
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
    const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`

    try {
      expect((await downloadFeed(`${base}/feed.json`)).toString()).toBe(body.toString())
      expect((await downloadFeed(`${base}/feed.json.gz`, { gzip: true, sha256 })).toString()).toBe(
        body.toString(),
      )
      await expect(
        downloadFeed(`${base}/feed.json.gz`, { gzip: true, sha256: 'deadbeef' }),
      ).rejects.toThrow('SHA-256')
      // Hashing the compressed bytes instead is the bug this contract pins shut.
      expect(compressedSha256).not.toBe(sha256)
      await expect(
        downloadFeed(`${base}/feed.json.gz`, { gzip: true, sha256: compressedSha256 }),
      ).rejects.toThrow('SHA-256')
      expect((await downloadFeed(`${base}/feed.json.gz`, { gzip: true })).toString()).toBe(
        body.toString(),
      )
      await expect(downloadFeed(`${base}/missing`)).rejects.toThrow('responded with 404')
    } finally {
      await new Promise((resolve) => server.close(resolve))
    }
  })
})

describe('vulnerability catalog', () => {
  let payload: Payload
  let adminUser: TypedUser
  let plcClassID: string
  let siteID: string
  const assetIDs: string[] = []
  const roleIDs: string[] = []
  const userIDs: string[] = []

  const downloadFixtures = async (url: string) => {
    if (url === CISA_KEV_URL) return Buffer.from(JSON.stringify(await kevCatalog()))
    if (url === CSAF_AGGREGATOR_URL) return Buffer.from(JSON.stringify(await csafAggregator()))
    if (CISA_CSAF_FEED_URLS.includes(url as (typeof CISA_CSAF_FEED_URLS)[number])) {
      return Buffer.from(JSON.stringify(await csafRolie()))
    }
    if (url.endsWith('/provider-metadata.json')) {
      return Buffer.from(JSON.stringify(await csafProviderMetadata()))
    }
    if (url.endsWith('/feed.json')) return Buffer.from(JSON.stringify(await csafRolie()))
    if (url.endsWith('/example-2026-001.json')) {
      return Buffer.from(JSON.stringify(await csafDocument()))
    }
    if (url === ICS_ADVISORY_URL) return Buffer.from(await icsCsv())
    if (url.endsWith('nvdcve-2.0-2024.meta')) {
      return Buffer.from('lastModifiedDate:2026-09-10T03:00:00-04:00\nsha256:abc123\n')
    }
    if (url.endsWith('nvdcve-2.0-2024.json.gz')) return Buffer.from(JSON.stringify(await nvdFeed()))
    if (url.endsWith('.meta')) return Buffer.from('')
    throw new Error(`${url} is unavailable`)
  }

  beforeAll(async () => {
    payload = await getPayload({ config })
    const rawCollections = (
      payload.db as unknown as {
        collections: Record<string, { collection: { deleteMany: (filter: object) => unknown } }>
      }
    ).collections
    await rawCollections.vulnerabilities.collection.deleteMany({})
    await rawCollections['vulnerability-feeds'].collection.deleteMany({})

    const adminRole = await ensureAdminRole(payload)
    plcClassID = (await ensureAssetClass(payload, 'plc')).id
    const site = await payload.create({
      collection: 'sites',
      data: { name: `Vulnerability site ${randomUUID()}`, type: 'Test site' },
    })
    siteID = site.id
    const user = await payload.create({
      collection: 'users',
      data: {
        email: `vulnerabilities-${randomUUID()}@example.test`,
        name: 'Vulnerability admin',
        password: randomUUID(),
        role: adminRole.id,
      },
    })
    adminUser = user as unknown as TypedUser
    userIDs.push(user.id)
  })

  afterAll(async () => {
    const rawCollections = (
      payload.db as unknown as {
        collections: Record<string, { collection: { deleteMany: (filter: object) => unknown } }>
      }
    ).collections
    // Other integration files share this database; leave no catalog behind.
    await rawCollections.vulnerabilities.collection.deleteMany({})
    await rawCollections['vulnerability-feeds'].collection.deleteMany({})
    for (const id of assetIDs) await payload.delete({ collection: 'assets', id })
    for (const id of userIDs) await payload.delete({ collection: 'users', id })
    for (const id of roleIDs) await payload.delete({ collection: 'user-roles', id })
    await payload.delete({ collection: 'sites', id: siteID })
  })

  const createAsset = async (data: Record<string, unknown>) => {
    const asset = await payload.create({
      collection: 'assets',
      data: {
        assetClass: plcClassID,
        macAddress: `02:${randomBytes(5).toString('hex').toUpperCase().match(/.{2}/g)?.join(':')}`,
        name: 'Vulnerability test PLC',
        site: siteID,
        ...data,
      } as never,
    })
    assetIDs.push(asset.id)
    return asset
  }

  it('leaves the count unevaluated until the catalog is loaded', async () => {
    expect(await catalogIsLoaded(payload)).toBe(false)
    const asset = await createAsset({ ...feedDocument, name: 'Uncounted PLC' })
    expect(asset.vulnerabilityCount ?? null).toBeNull()
    expect(await findAssetVulnerabilities(payload, asset, { user: adminUser })).toEqual([])
  })

  it('upserts feed documents without touching unrelated fields', async () => {
    await upsertVulnerabilities(payload, [
      {
        cve: 'CVE-2099-0008',
        set: { description: 'KEV-only entry', knownExploited: true },
        setOnInsert: { productTokens: ['example'], products: ['exampleproduct'] },
      },
      {
        cve: 'CVE-2099-0099',
        set: { kevName: 'Removed KEV entry', knownExploited: true },
      },
    ])
    await upsertVulnerabilities(payload, [
      { cve: 'CVE-2099-0008', set: { description: 'Updated description' } },
    ])
    const stored = await payload.find({
      collection: 'vulnerabilities',
      overrideAccess: true,
      where: { cve: { equals: 'CVE-2099-0008' } },
    })
    expect(stored.docs[0]).toMatchObject({
      description: 'Updated description',
      knownExploited: true,
      products: ['exampleproduct'],
    })
    expect(stored.totalDocs).toBe(1)
  })

  it('synchronizes every feed, records state, and recounts assets', async () => {
    const logged = vi.spyOn(payload.logger, 'info').mockImplementation(() => undefined as never)
    const result = await syncVulnerabilityFeeds(payload, {
      download: downloadFixtures,
      force: true,
    })
    const messages = logged.mock.calls.map(([message]) => String(message))
    logged.mockRestore()

    // The job announces itself on the console when it starts pulling feeds and when the
    // downloads are done, so a long NVD import is never silent.
    expect(messages[0]).toBe(
      'Vulnerability catalog sync started: downloading CISA KEV, CSAF, ICS Advisory Project, and NVD feeds.',
    )
    expect(messages[1]).toBe('Vulnerability catalog sync finished downloading 15 documents.')

    expect(result).toMatchObject({ loaded: 15, skipped: false, updatedAssets: 1 })
    expect(result.documentCount).toBeGreaterThan(10)

    const feeds = await payload.find({
      collection: 'vulnerability-feeds',
      depth: 0,
      overrideAccess: true,
      sort: 'source',
    })
    expect(feeds.docs.map(({ source, status }) => ({ source, status }))).toEqual([
      { source: 'cisa-kev', status: 'ready' },
      { source: 'csaf', status: 'ready' },
      { source: 'ics-advisories', status: 'ready' },
      { source: 'nvd', status: 'ready' },
    ])
    expect(feeds.docs[0]).toMatchObject({ catalogVersion: '2026.09.10', documentCount: 2 })
    expect(feeds.docs[1]).toMatchObject({ documentCount: 1 })
    expect(feeds.docs[2]).toMatchObject({ documentCount: 5 })
    expect(feeds.docs[2].dateReleased).toBe('2026-09-11T00:00:00.000Z')
    expect(feeds.docs[3].state).toMatchObject({ 2024: { sha256: 'abc123' } })

    const merged = await payload.find({
      collection: 'vulnerabilities',
      overrideAccess: true,
      where: { cve: { equals: 'CVE-2099-0001' } },
    })
    expect(merged.docs[0]).toMatchObject({
      cvssSeverity: 'CRITICAL',
      knownExploited: true,
      kevProduct: 'SIMATIC S7-1500',
      productTokens: ['simatic', 's7', '1500'],
      vendors: ['siemens'],
    })
    expect(merged.docs[0].kevDateAdded).toBe('2026-01-15T00:00:00.000Z')

    // ICS Advisory Project context enriches the NVD record without displacing any NVD value:
    // the advisory score of 6.0 stays out and the NVD CPE evidence is untouched.
    expect(merged.docs[0]).toMatchObject({
      affected: [
        {
          part: 'a',
          product: 'simatic_s7-1500_firmware',
          vendor: 'siemens',
          version: '*',
          versionEndExcluding: '2.9',
          versionStartIncluding: '1.0',
        },
      ],
      cvssScore: 9.8,
      icsAdvisory: ['ICSA-26-005-01'],
      icsHeadquarters: 'Germany',
      icsSectors: ['Critical Manufacturing'],
      status: 'Analyzed',
    })

    // An advisory-only CVE is stored for visibility but carries no matchable version evidence.
    const advisoryOnly = await payload.find({
      collection: 'vulnerabilities',
      overrideAccess: true,
      where: { cve: { equals: 'CVE-2099-0201' } },
    })
    expect(advisoryOnly.docs[0]).toMatchObject({
      cvssScore: 9.1,
      cvssSeverity: 'CRITICAL',
      icsAdvisory: ['ICSA-26-001-01', 'ICSMA-26-002-01'],
      icsSectors: ['Critical Manufacturing', 'Energy', 'Chemical'],
    })
    expect(advisoryOnly.docs[0].affected ?? []).toEqual([])
    // Even with reported version evidence an advisory-only CVE cannot be counted.
    expect(
      await findAssetVulnerabilities(
        payload,
        { firmwareVersion: '1.5', model: 'Example Controller', vendor: 'Example Vendor' },
        { user: adminUser },
      ),
    ).toEqual([])

    const csaf = await payload.find({
      collection: 'vulnerabilities',
      overrideAccess: true,
      where: { cve: { equals: 'CVE-2099-0100' } },
    })
    expect(csaf.docs[0]).toMatchObject({
      affected: [{ product: 'CSAF Test Controller', versionEndExcluding: '34.015' }],
      cvssSeverity: 'HIGH',
      status: 'CSAF',
    })

    const removedKev = await payload.find({
      collection: 'vulnerabilities',
      overrideAccess: true,
      where: { cve: { equals: 'CVE-2099-0099' } },
    })
    expect(removedKev.docs[0]).toMatchObject({ knownExploited: false })
    expect(removedKev.docs[0].kevName).toBeUndefined()

    const audit = await payload.find({
      collection: 'audit-logs',
      limit: 5,
      overrideAccess: true,
      where: { targetCollection: { equals: 'vulnerabilities' } },
    })
    expect(audit.docs[0]).toMatchObject({ action: 'custom', actorType: 'system' })
    expect(audit.docs[0].summary).toContain('vulnerabilities')

    // The recount refreshed the asset created before the catalog existed.
    expect(await catalogIsLoaded(payload)).toBe(true)
    const [asset] = (
      await payload.find({
        collection: 'assets',
        overrideAccess: true,
        where: { name: { equals: 'Uncounted PLC' } },
      })
    ).docs
    expect(asset.vulnerabilityCount).toBe(1)
    expect(await recountAssetVulnerabilities(payload)).toBe(0)
  })

  it('skips a fresh catalog and keeps the previous one on failure', async () => {
    const logged = vi.spyOn(payload.logger, 'info').mockImplementation(() => undefined as never)
    expect(await syncVulnerabilityFeeds(payload, { download: downloadFixtures })).toMatchObject({
      loaded: 0,
      skipped: true,
    })
    // A skipped run pulls nothing, so it stays quiet rather than pretending to be a sync.
    expect(logged.mock.calls).toHaveLength(0)

    const failing = await syncVulnerabilityFeeds(payload, {
      download: async (url) => {
        if (url === CISA_KEV_URL) throw new Error('mirror unreachable')
        if (url === CSAF_AGGREGATOR_URL) throw new Error('aggregator unreachable')
        if (url === ICS_ADVISORY_URL) throw new Error('advisory project unreachable')
        return downloadFixtures(url)
      },
      force: true,
    })
    expect(failing.loaded).toBe(0)
    expect(logged.mock.calls.map(([message]) => String(message))).toEqual([
      'Vulnerability catalog sync started: downloading CISA KEV, CSAF, ICS Advisory Project, and NVD feeds.',
      'Vulnerability catalog sync finished downloading 0 documents with 3 source failures.',
    ])
    logged.mockRestore()

    const feeds = await payload.find({
      collection: 'vulnerability-feeds',
      depth: 0,
      overrideAccess: true,
      sort: 'source',
    })
    expect(feeds.docs.map(({ status }) => status)).toEqual(['failed', 'failed', 'failed', 'ready'])
    expect(feeds.docs[0].error).toContain('mirror unreachable')
    expect(feeds.docs[1].error).toContain('aggregator unreachable')
    expect(feeds.docs[2].error).toContain('advisory project unreachable')
    // The previously stored catalog survives a failed refresh.
    expect(
      (
        await payload.find({
          collection: 'vulnerabilities',
          overrideAccess: true,
          where: { cve: { equals: 'CVE-2099-0001' } },
        })
      ).totalDocs,
    ).toBe(1)
    expect(
      (
        await payload.find({
          collection: 'vulnerabilities',
          overrideAccess: true,
          where: { cve: { equals: 'CVE-2099-0100' } },
        })
      ).totalDocs,
    ).toBe(1)
    // A failed advisory refresh leaves the previous ICS context in place.
    const preserved = await payload.find({
      collection: 'vulnerabilities',
      overrideAccess: true,
      where: { cve: { equals: 'CVE-2099-0201' } },
    })
    expect(preserved.docs[0]).toMatchObject({
      icsAdvisory: ['ICSA-26-001-01', 'ICSMA-26-002-01'],
    })
  })

  it('never runs two synchronizations at once', async () => {
    const [first, second] = await Promise.all([
      syncVulnerabilityFeeds(payload, { download: downloadFixtures, force: true }),
      syncVulnerabilityFeeds(payload, { download: downloadFixtures, force: true }),
    ])
    expect(first).toBe(second)
  })

  it('resumes an interrupted NVD import instead of re-downloading every year', async () => {
    const nvdJson = Buffer.from(JSON.stringify(await nvdFeed()))
    // NVD publishes the digest of the uncompressed feed, exactly like the real `.meta` files.
    const sha256 = createHash('sha256').update(nvdJson).digest('hex')
    const requested: string[] = []
    // An injected `download` stands in for the whole download/verify/gunzip pipeline, so it
    // returns the decompressed body just like `downloadFixtures` does.
    const serve2023 = async (url: string) => {
      requested.push(url)
      if (url === `${NVD_FEED_BASE_URL}/nvdcve-2.0-2023.meta`) {
        return Buffer.from(`lastModifiedDate:2026-09-10T03:00:00-04:00\nsha256:${sha256}\n`)
      }
      if (url === `${NVD_FEED_BASE_URL}/nvdcve-2.0-2023.json.gz`) return nvdJson
      return downloadFixtures(url)
    }

    // Interrupt the run after the year loop, which is where a long initial import would die.
    const count = vi.spyOn(payload, 'count').mockRejectedValueOnce(new Error('interrupted'))
    await expect(
      syncVulnerabilityFeeds(payload, { download: serve2023, force: true }),
    ).rejects.toThrow('interrupted')
    count.mockRestore()

    expect(requested.filter((url) => url.endsWith('nvdcve-2.0-2023.json.gz'))).toHaveLength(1)
    const interruptedState = (
      await payload.find({
        collection: 'vulnerability-feeds',
        depth: 0,
        overrideAccess: true,
        where: { source: { equals: 'nvd' } },
      })
    ).docs[0]
    expect(interruptedState.state).toMatchObject({ 2023: { sha256 } })

    // The next run sees the stored digest and skips the year entirely.
    requested.length = 0
    const result = await syncVulnerabilityFeeds(payload, { download: serve2023, force: true })
    expect(requested.some((url) => url.endsWith('nvdcve-2.0-2023.json.gz'))).toBe(false)
    expect(result.skipped).toBe(false)
    expect(
      (
        await payload.find({
          collection: 'vulnerability-feeds',
          depth: 0,
          overrideAccess: true,
          where: { source: { equals: 'nvd' } },
        })
      ).docs[0].status,
    ).toBe('ready')
  })

  it('keeps counts current when asset metadata changes', async () => {
    const asset = await createAsset({ ...feedDocument, name: 'Counted PLC' })
    expect(asset.vulnerabilityCount).toBe(1)
    expect(asset.fieldProvenance).not.toHaveProperty('vulnerabilityCount')
    expect(asset.fieldProvenance).toMatchObject({
      vendor: { quality: 'human', source: 'human' },
    })

    const upgraded = await payload.update({
      collection: 'assets',
      data: { firmwareVersion: 'V2.9' },
      id: asset.id,
    })
    expect(upgraded.vulnerabilityCount).toBe(0)

    const replaced = await payload.update({
      collection: 'assets',
      data: { firmwareVersion: '3.0' },
      id: asset.id,
    })
    expect(replaced.vulnerabilityCount).toBe(1)

    const bare = await createAsset({ name: 'Bare PLC', vendor: 'Siemens AG' })
    expect(bare.vulnerabilityCount).toBe(0)

    const hookArgs = {
      context: { vulnerabilityCountSync: true },
      data: { vulnerabilityCount: 42 },
      originalDoc: asset,
      req: { context: {}, payload },
    }
    expect(
      await (assignVulnerabilityCount as never as (args: never) => unknown)(hookArgs as never),
    ).toEqual({
      vulnerabilityCount: 42,
    })
    expect(assetFingerprint(asset)).toContain('Siemens AG')
    expect(
      await countAssetVulnerabilities(payload, asset, {
        req: { context: {}, payload } as never,
      }),
    ).toBe(1)
  })

  it('scopes the catalog and its state through collection access', async () => {
    const anonymous = await payload.find({
      collection: 'vulnerability-feeds',
      overrideAccess: false,
      user: adminUser,
    })
    expect(anonymous.totalDocs).toBe(4)

    const operatorRole = await payload.create({
      collection: 'user-roles',
      data: {
        name: `Operator ${randomUUID()}`,
        permissions: [{ access: 'read', site: siteID }],
      },
    })
    roleIDs.push(operatorRole.id)
    const operator = await payload.create({
      collection: 'users',
      data: {
        email: `scoped-${randomUUID()}@example.test`,
        password: randomUUID(),
        role: operatorRole.id,
      },
    })
    userIDs.push(operator.id)
    const scoped = operator as unknown as TypedUser
    expect(
      (
        await payload.find({
          collection: 'vulnerability-feeds',
          disableErrors: true,
          overrideAccess: false,
          user: scoped,
        })
      ).totalDocs,
    ).toBe(0)
    expect(
      (
        await payload.find({
          collection: 'vulnerabilities',
          overrideAccess: false,
          user: scoped,
          where: { cve: { equals: 'CVE-2099-0001' } },
        })
      ).totalDocs,
    ).toBe(1)
  })

  it('renders the lookup view with its validation warning', async () => {
    const asset = (
      await payload.find({
        collection: 'assets',
        overrideAccess: true,
        where: { name: { equals: 'Counted PLC' } },
      })
    ).docs[0]
    const html = renderToStaticMarkup(
      await AssetVulnerabilitiesView({
        doc: asset,
        payload,
        routeSegments: ['collections', 'assets', asset.id, 'vulnerabilities'],
        searchParams: {},
        user: adminUser,
      } as never),
    )
    expect(html).toContain('not validated')
    expect(html).toContain('no vulnerability check was run')
    expect(html).toContain('1 potential vulnerabilities')
    expect(html).toContain('CVE-2099-0002')
    expect(html).toContain('firmware version')
    expect(html).toContain('satisfies')
    expect(html).toContain('cisa-kev')
    expect(html).toContain('ics-advisories')

    // CVE-2099-0001 carries ICS Advisory Project context, which the lookup view surfaces.
    const enriched = (
      await payload.find({
        collection: 'assets',
        overrideAccess: true,
        where: { name: { equals: 'Uncounted PLC' } },
      })
    ).docs[0]
    const enrichedHTML = renderToStaticMarkup(
      await AssetVulnerabilitiesView({
        doc: enriched,
        payload,
        routeSegments: ['collections', 'assets', enriched.id, 'vulnerabilities'],
        searchParams: {},
        user: adminUser,
      } as never),
    )
    expect(enrichedHTML).toContain('CVE-2099-0001')
    expect(enrichedHTML).toContain('CISA ICS advisory ICSA-26-005-01')
    expect(enrichedHTML).toContain('sectors: Critical Manufacturing')
    expect(enrichedHTML).toContain('vendor HQ: Germany')

    const bare = (
      await payload.find({
        collection: 'assets',
        overrideAccess: true,
        where: { name: { equals: 'Bare PLC' } },
      })
    ).docs[0]
    const empty = renderToStaticMarkup(
      await AssetVulnerabilitiesView({
        doc: bare,
        payload,
        routeSegments: ['collections', 'assets', bare.id, 'vulnerabilities'],
        searchParams: {},
        user: adminUser,
      } as never),
    )
    expect(empty).toContain('no catalog entry can be matched')

    const unauthenticated = renderToStaticMarkup(
      await AssetVulnerabilitiesView({
        doc: asset,
        payload,
        routeSegments: ['collections', 'assets', asset.id, 'vulnerabilities'],
        searchParams: { page: '9' },
      } as never),
    )
    expect(unauthenticated).toContain('not validated')
    expect(unauthenticated).not.toContain('CVE-2099-0002')
  })

  it('synchronizes through the real downloader when not in test mode', async () => {
    const nvdJson = Buffer.from(JSON.stringify(await nvdFeed()))
    const gzip = gzipSync(nvdJson)
    // Mirrors NVD's real contract: the published digest covers the uncompressed feed.
    const sha256 = createHash('sha256').update(nvdJson).digest('hex')
    const fetchMock = vi.fn(async (url: string) => {
      if (url === CISA_KEV_URL) return new Response(JSON.stringify(await kevCatalog()))
      if (url === `${NVD_FEED_BASE_URL}/nvdcve-2.0-2024.meta`) {
        return new Response(`lastModifiedDate:2026-09-10T03:00:00-04:00\nsha256:${sha256}\n`)
      }
      if (url === `${NVD_FEED_BASE_URL}/nvdcve-2.0-2024.json.gz`) return new Response(gzip)
      return new Response('not published', { status: 404 })
    })
    vi.stubGlobal('fetch', fetchMock)
    const interval = vi.spyOn(globalThis, 'setInterval').mockReturnValue(0 as never)
    process.env['OTSERVER_VULNERABILITY_FEEDS'] = 'on'

    try {
      await initializeVulnerabilityFeeds(payload)
      // The first call joins the startup freshness check; the second forces a real refresh.
      await syncVulnerabilityFeeds(payload, { force: true })
      await syncVulnerabilityFeeds(payload, { force: true })
      expect(fetchMock).toHaveBeenCalledWith(
        CISA_KEV_URL,
        expect.objectContaining({ headers: expect.any(Object) }),
      )
      expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('.json.gz'))).toBe(true)
      expect(interval).toHaveBeenCalled()
    } finally {
      delete process.env['OTSERVER_VULNERABILITY_FEEDS']
      interval.mockRestore()
      vi.unstubAllGlobals()
    }

    const feeds = await payload.find({
      collection: 'vulnerability-feeds',
      depth: 0,
      overrideAccess: true,
      sort: 'source',
    })
    expect(feeds.docs.map(({ status }) => status)).toEqual(['ready', 'failed', 'failed', 'partial'])
    expect(feeds.docs[3].error).toContain('responded with 404')

    process.env.OTSERVER_VULNERABILITY_FEEDS = 'off'
    const calls = fetchMock.mock.calls.length
    try {
      await initializeVulnerabilityFeeds(payload)
      expect(fetchMock).toHaveBeenCalledTimes(calls)
    } finally {
      delete process.env.OTSERVER_VULNERABILITY_FEEDS
    }
    expect(FIRST_NVD_YEAR).toBeLessThan(new Date().getUTCFullYear())
  })
})
