import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'

import { MAX_IMPORT_FILE_SIZE, parseProneta } from '../../src/importers/proneta'

describe('PRONETA parser', () => {
  it('parses device fields without treating nested port MACs as assets', async () => {
    const xml = await readFile(
      new URL('../proneta_files/PRONETA-example-topology.xml', import.meta.url),
      'utf8',
    )
    const topology = parseProneta(xml)

    expect(topology.projectName).toBe('PRONETA Example Network')
    expect(topology.assets).toHaveLength(2)
    expect(topology.assets[0]).toEqual({
      description: 'Example PLC',
      gatewayAddress: '192.168.10.1',
      ipAddress: '192.168.10.10',
      location: 'Control cabinet A',
      macAddress: '02:00:00:00:00:10',
      model: 'SIMATIC S7-1500',
      name: 'plc-01',
      networkMask: '255.255.255.0',
      vendor: 'Siemens AG',
    })
    expect(topology.assets.map(({ macAddress }) => macAddress)).not.toContain('02:00:00:00:10:01')

    const variant = parseProneta(`
      <p:Topology xmlns:p="urn:test" PronetaVersion="3.8">
        <p:DeviceCollection><p:Device>
          <p:NameOfStation>case-test</p:NameOfStation>
          <p:IPAddress>192.0.2.8</p:IPAddress>
          <p:GatewayIP>192.0.2.1</p:GatewayIP>
          <p:MAC>02-00-00-00-00-08</p:MAC>
          <p:Unknown>ignored</p:Unknown>
        </p:Device></p:DeviceCollection>
      </p:Topology>
    `)
    expect(variant.sourceVersion).toBe('3.8')
    expect(variant.assets[0]?.macAddress).toBe('02:00:00:00:00:08')
    expect(() =>
      parseProneta('<!DOCTYPE Topology><Topology><DeviceCollection /></Topology>'),
    ).toThrow('document types')
  })

  it('rejects invalid files and safely handles incomplete and duplicate devices', () => {
    expect(() => parseProneta('')).toThrow('empty')
    expect(() => parseProneta('x'.repeat(MAX_IMPORT_FILE_SIZE + 1))).toThrow('10 MB')
    expect(() => parseProneta('<Topology />')).toThrow('not a recognized PRONETA')

    const result = parseProneta(`
      <Topology><Version>4.0</Version><DeviceCollection>
        <Device><NameOfStation>missing-mac</NameOfStation></Device>
        <Device><DeviceType>Fallback model</DeviceType><MAC>02:00:00:00:00:01</MAC><IPAddress>bad</IPAddress><NetworkMask>bad</NetworkMask><GatewayIP>bad</GatewayIP></Device>
        <Device><NameOfStation>duplicate</NameOfStation><MACAddress>02-00-00-00-00-01</MACAddress></Device>
        <Device><NameOfStation><![CDATA[ CDATA device ]]></NameOfStation><MAC>02:00:00:00:00:02</MAC></Device>
      </DeviceCollection><ProjectName> Project </ProjectName><Name> Topology </Name></Topology>
    `)
    expect(result).toMatchObject({
      projectName: 'Project',
      sourceVersion: '4.0',
      topologyName: 'Topology',
    })
    expect(result.assets).toHaveLength(2)
    expect(result.assets[0]).toMatchObject({
      macAddress: '02:00:00:00:00:01',
      name: 'Fallback model',
    })
    expect(result.assets[1]).toMatchObject({ name: 'CDATA device' })
    expect(result.warnings.join('\n')).toContain('no valid MAC')
    expect(result.warnings.join('\n')).toContain('Duplicate device MAC')
    expect(result.warnings.filter((warning) => warning.includes('invalid')).length).toBe(3)
  })
})
