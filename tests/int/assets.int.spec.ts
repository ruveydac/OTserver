import type { DocumentViewServerProps } from 'payload'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'

import { normalizeMAC, validateIPAddress, validateMACAddress } from '../../src/collections/Assets'
import { findMatchingAssetClass, validateAssignmentRegex } from '../../src/collections/AssetClasses'
import AssetClassListView from '../../src/components/AssetClassListView'
import AssetView from '../../src/components/AssetView'
import { assetListURL } from '../../src/components/assetListURL'

vi.mock('@payloadcms/ui', async () => {
  const { createElement } = await import('react')

  return {
    DefaultEditView: (props: Record<string, unknown>) => {
      if ('payload' in props || 'initPageResult' in props) {
        throw new Error('Server-only props reached the client edit view.')
      }
      return createElement('div', null, 'Payload edit form')
    },
  }
})

describe('asset network fields', () => {
  it('builds scoped links and renders asset classes as collection documents', async () => {
    expect(assetListURL('/admin', 'site', 'site-1')).toBe(
      '/admin/collections/assets?where%5Bsite%5D%5Bequals%5D=site-1',
    )
    expect(assetListURL('/admin', 'assetClass', 'class-1')).toBe(
      '/admin/collections/assets?where%5BassetClass%5D%5Bequals%5D=class-1',
    )

    const view = await AssetClassListView({
      enableRowSelections: true,
      hasCreatePermission: true,
      newDocumentURL: '/admin/collections/asset-classes/create',
      payload: {
        config: { routes: { admin: '/admin' } },
        find: vi.fn().mockResolvedValue({
          docs: [
            {
              assignmentPriority: 10,
              assignmentRules: [
                { id: 'rule-1', manufacturerRegex: 'Siemens', modelRegex: 'S7-1500.*' },
              ],
              createdAt: '2026-08-08T09:00:00.000Z',
              description: 'Programmable controllers',
              id: 'class-1',
              name: 'PLC',
              updatedAt: '2026-08-08T10:00:00.000Z',
            },
          ],
        }),
      },
      user: { id: 'user-1' },
    } as never)
    const html = renderToStaticMarkup(createElement(() => view))

    expect(html).toContain('Asset Classes')
    expect(html).toContain('Add asset class')
    expect(html).toContain('PLC')
    expect(html).toContain('Programmable controllers')
    expect(html).toContain('Rules')
    expect(html).toContain('Priority')
    expect(html).toContain('where%5BassetClass%5D%5Bequals%5D=class-1')
  })

  it('matches safe manufacturer and model regular expressions together', async () => {
    expect(validateAssignmentRegex('Siemens(?: AG)?')).toBe(true)
    expect(validateAssignmentRegex('.*S7-1500.*')).toBe(true)
    expect(validateAssignmentRegex('(')).toBeTypeOf('string')
    expect(validateAssignmentRegex('(a+)+')).toContain('Nested quantified')
    expect(validateAssignmentRegex('a'.repeat(257))).toContain('256')

    const plc = {
      assignmentRules: [{ manufacturerRegex: 'Siemens', modelRegex: 'S7-1500.*' }],
      id: 'plc-class',
      name: 'PLC',
    }
    const payload = { find: vi.fn().mockResolvedValue({ docs: [plc] }) }
    const req = { context: {} }

    await expect(
      findMatchingAssetClass(payload as never, 'Siemens AG', 'SIMATIC S7-1500 CPU', req as never),
    ).resolves.toBe(plc)
    await expect(
      findMatchingAssetClass(payload as never, 'Siemens AG', 'Comfort Panel', req as never),
    ).resolves.toBeUndefined()
    await expect(findMatchingAssetClass(payload as never, '', 'S7-1500')).resolves.toBeUndefined()
    expect(payload.find).toHaveBeenCalledTimes(1)
  })

  it('validates IP addresses and normalizes MAC addresses', () => {
    expect(validateIPAddress('192.168.10.42')).toBe(true)
    expect(validateIPAddress('2001:db8::42')).toBe(true)
    expect(validateIPAddress('999.168.10.42')).toBeTypeOf('string')
    expect(normalizeMAC('00-1a-2b-3c-4d-5e')).toBe('00:1A:2B:3C:4D:5E')
    expect(validateMACAddress('00-1a-2b-3c-4d-5e')).toBe(true)
    expect(validateMACAddress('not-a-mac')).toBeTypeOf('string')
  })

  it('renders every asset section with an explicit edit link', async () => {
    const view = await AssetView({
      doc: {
        assetClass: {
          createdAt: '2026-08-08T09:00:00.000Z',
          id: 'class-1',
          name: 'PLC',
          updatedAt: '2026-08-08T09:00:00.000Z',
        },
        createdAt: '2026-08-08T10:00:00.000Z',
        criticality: 'high',
        customFields: { 'field-enabled': false, 'field-level': 0 },
        description: 'Main line controller',
        id: 'asset-1',
        ipAddress: '192.0.2.10',
        macAddress: '02:00:00:00:00:10',
        name: 'PLC 1',
        notes: 'Maintenance window Sunday',
        serialNumber: 'S-123',
        site: {
          createdAt: '2026-08-08T09:00:00.000Z',
          id: 'site-1',
          name: 'Plant Berlin',
          type: 'Plant',
          updatedAt: '2026-08-08T09:00:00.000Z',
        },
        status: 'online',
        updatedAt: '2026-08-08T11:00:00.000Z',
      },
      payload: {
        config: { routes: { admin: '/admin' } },
        find: vi.fn().mockImplementation(({ collection }: { collection: string }) =>
          Promise.resolve({
            docs:
              collection === 'audit-logs'
                ? [
                    {
                      action: 'update',
                      actorEmail: 'operator@example.test',
                      changes: { status: { after: 'online', before: 'offline' } },
                      createdAt: '2026-08-08T10:30:00.000Z',
                      id: 'audit-1',
                    },
                  ]
                : [
                    { id: 'field-enabled', label: 'Remote access enabled', type: 'checkbox' },
                    { id: 'field-level', label: 'ISA-95 level', type: 'number' },
                  ],
          }),
        ),
      },
      routeSegments: ['collections', 'assets', 'asset-1'],
    } as unknown as DocumentViewServerProps)
    const html = renderToStaticMarkup(createElement(() => view))

    expect(html).toContain('Main line controller')
    expect(html).toContain('Maintenance window Sunday')
    expect(html).toContain('href="/admin/collections/asset-classes/class-1"')
    expect(html).toContain('PLC')
    expect(html).toContain('Plant Berlin')
    expect(html).toContain('href="/admin/collections/sites/site-1"')
    expect(html).toContain('S-123')
    expect(html).toContain('Remote access enabled')
    expect(html).toContain('ISA-95 level')
    expect(html).toContain('<dd>No</dd>')
    expect(html).toContain('<dd>0</dd>')
    expect(html).toContain('href="/admin/collections/assets/asset-1/edit"')
    expect(html).toContain('Edit asset')
    expect(html).toContain('Change history')
    expect(html).toContain('operator@example.test')
    expect(html).toContain('offline → online')
  })

  it('keeps server-only values out of the edit form', async () => {
    const view = await AssetView({
      documentSubViewType: 'default',
      formState: {},
      initPageResult: { req: { payload: { config: {} } } },
      payload: { config: { endpoints: [{ handler: () => null }] } },
      routeSegments: ['collections', 'assets', 'create'],
      viewType: 'document',
    } as unknown as DocumentViewServerProps)

    expect(renderToStaticMarkup(createElement(() => view))).toContain('Payload edit form')
  })

  it('renders empty values, raw relationships, and audit change variants', async () => {
    const view = await AssetView({
      doc: {
        assetClass: 'class-other',
        createdAt: '2026-08-08T10:00:00.000Z',
        criticality: 'low',
        customFields: null,
        description: '',
        id: 'asset-2',
        macAddress: '02:00:00:00:00:20',
        name: 'Unidentified device',
        osAccuracy: null,
        site: 'site-raw',
        status: 'unknown',
        updatedAt: '2026-08-08T11:00:00.000Z',
      },
      payload: {
        config: { routes: { admin: '/admin' } },
        find: vi.fn().mockImplementation(({ collection }: { collection: string }) => {
          if (collection === 'audit-logs') {
            return Promise.resolve({
              docs: [
                {
                  action: 'create',
                  actorName: 'Operator',
                  changes: null,
                  createdAt: '2026-08-08T10:00:00.000Z',
                  id: 'audit-2',
                },
                {
                  action: 'delete',
                  changes: {
                    added: { after: { nested: true } },
                    malformed: 'ignored',
                    removed: { before: 'old' },
                  },
                  createdAt: '2026-08-08T11:00:00.000Z',
                  id: 'audit-3',
                },
              ],
            })
          }
          return Promise.resolve({ docs: [] })
        }),
      },
      routeSegments: ['collections', 'assets', 'asset-2'],
    } as unknown as DocumentViewServerProps)
    const html = renderToStaticMarkup(createElement(() => view))

    expect(html).toContain('No description provided')
    expect(html).toContain('site-raw')
    expect(html).toContain('No scanner evidence recorded yet')
    expect(html).toContain('No topology links recorded yet')
    expect(html).toContain('No field changes recorded')
    expect(html).toContain('old → removed')
    expect(html).toContain('{&quot;nested&quot;:true}')
    expect(html).toContain('System')
  })

  it('renders scanner evidence, topology peers, custom dates, and empty history', async () => {
    const view = await AssetView({
      doc: {
        assetClass: 'class-1',
        createdAt: '2026-08-08T10:00:00.000Z',
        criticality: 'high',
        customFields: { active: true, installed: '2026-08-08', invalid: false },
        id: 'asset-3',
        macAddress: '02:00:00:00:00:30',
        name: 'PLC 3',
        protocols: ['s7'],
        site: 3,
        status: 'online',
        updatedAt: '2026-08-08T11:00:00.000Z',
      },
      payload: {
        config: { routes: { admin: '/admin' } },
        find: vi.fn().mockImplementation(({ collection }: { collection: string }) => {
          if (collection === 'asset-fields') {
            return Promise.resolve({
              docs: [
                { id: 'active', label: 'Active', type: 'checkbox' },
                { id: 'installed', label: 'Installed', type: 'date' },
                { id: 'invalid', label: 'Invalid', type: 'number' },
              ],
            })
          }
          if (collection === 'asset-observations') {
            return Promise.resolve({
              docs: [
                {
                  fields: { name: 'PLC 3' },
                  id: 'observation-1',
                  observedAt: '2026-08-08T10:00:00.000Z',
                  quality: 'high',
                  source: 's7',
                },
              ],
            })
          }
          if (collection === 'topology-links') {
            return Promise.resolve({
              docs: [
                {
                  id: 'link-1',
                  local: { name: 'PLC 3' },
                  localAsset: { id: 'asset-3' },
                  observedAt: '2026-08-08T10:00:00.000Z',
                  remote: { name: 'Peer' },
                  source: 'lldp',
                },
                {
                  id: 'link-2',
                  local: { name: 'Other peer' },
                  localAsset: 'other',
                  observedAt: '2026-08-08T10:00:00.000Z',
                  remote: { name: 'PLC 3' },
                  source: 'lldp',
                },
              ],
            })
          }
          return Promise.resolve({ docs: [] })
        }),
      },
      routeSegments: ['collections', 'assets', 'asset-3'],
    } as unknown as DocumentViewServerProps)
    const html = renderToStaticMarkup(createElement(() => view))

    expect(html).toContain('Yes')
    expect(html).toContain('8 Aug 2026')
    expect(html).toContain('high quality evidence')
    expect(html).toContain('Peer')
    expect(html).toContain('Other peer')
    expect(html).toContain('No changes recorded yet')
  })
})
