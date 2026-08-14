import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'

import { parseNmap } from '../../src/importers/nmap'
import { MAX_IMPORT_FILE_SIZE } from '../../src/importers/proneta'

describe('Nmap parser', () => {
  it('normalizes and merges hosts by MAC address', () => {
    const scan = parseNmap(`<?xml version="1.0"?>
      <!DOCTYPE nmaprun SYSTEM "nmap.dtd">
      <nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">
        <host endtime="1700000000">
          <status state="up" reason="arp-response" reason_ttl="0" />
          <address addr="192.0.2.10" addrtype="ipv4" />
          <address addr="02-00-00-00-00-10" addrtype="mac" vendor="Siemens AG" />
          <hostnames>
            <hostname name="reverse.example" type="PTR" />
            <hostname name="plc-01" type="user" />
          </hostnames>
          <os>
            <osclass vendor="Siemens" osfamily="VxWorks" osgen="7" accuracy="90" />
            <osmatch name="Siemens embedded device OS" accuracy="98" />
          </os>
        </host>
        <host>
          <status state="up" reason="arp-response" reason_ttl="0" />
          <address addr="192.0.2.11" addrtype="ipv4" />
          <address addr="02:00:00:00:00:10" addrtype="mac" />
          <hostnames><hostname name="plc-updated" type="PTR" /></hostnames>
        </host>
      </nmaprun>
    `)

    expect(scan.assets).toEqual([
      {
        ipAddress: '192.0.2.11',
        lastSeen: new Date(1700000000 * 1000).toISOString(),
        macAddress: '02:00:00:00:00:10',
        name: 'plc-updated',
        operatingSystem: 'Siemens embedded device OS',
        osAccuracy: 98,
        status: 'online',
        vendor: 'Siemens AG',
      },
    ])
    expect(scan.warnings).toContain('Duplicate host MAC 02:00:00:00:00:10 was merged.')
    expect(() =>
      parseNmap('<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun />'),
    ).toThrow('standard Nmap document type')
  })

  it('parses the anonymized full scan, including OS detection and repeated MACs', async () => {
    const xml = await readFile(new URL('../nmap_files/nmap.xml', import.meta.url), 'utf8')
    const scan = parseNmap(xml)

    expect(
      [...xml.matchAll(/<address addr="([^"]+)" addrtype="ipv4"/g)].every(([, address]) =>
        address.startsWith('192.0.2.'),
      ),
    ).toBe(true)
    expect(
      [...xml.matchAll(/<address addr="([^"]+)" addrtype="mac"/g)].every(([, address]) =>
        address.startsWith('02:00:00:00:00:'),
      ),
    ).toBe(true)
    expect(
      [...xml.matchAll(/<hostname name="([^"]+)"/g)].every(([, hostname]) =>
        hostname.endsWith('.example.test'),
      ),
    ).toBe(true)
    expect(scan.sourceVersion).toBe('7.92')
    expect(scan.assets).toHaveLength(7)
    expect(scan.warnings).toHaveLength(3)
    expect(scan.warnings.filter((warning) => warning.includes('Duplicate host MAC'))).toHaveLength(
      2,
    )
    expect(scan.warnings.some((warning) => warning.includes('no valid MAC address'))).toBe(true)
    expect(scan.assets.find(({ macAddress }) => macAddress === '02:00:00:00:00:01')).toMatchObject({
      ipAddress: '192.0.2.1',
      name: 'router-01.example.test',
      operatingSystem: 'Linux 4.15 - 5.6',
      osAccuracy: 96,
    })
    expect(scan.assets.find(({ macAddress }) => macAddress === '02:00:00:00:00:03')).toMatchObject({
      ipAddress: '192.0.2.8',
      name: 'server-01.example.test',
      operatingSystem: 'Linux 5.3 - 5.4',
      osAccuracy: 96,
    })
    expect(scan.assets.find(({ macAddress }) => macAddress === '02:00:00:00:00:07')).toMatchObject({
      vendor: 'Example Mobile Devices',
    })
  })

  it('rejects invalid files and reports unsafe or unusable hosts', () => {
    expect(() => parseNmap('')).toThrow('empty')
    expect(() => parseNmap('x'.repeat(MAX_IMPORT_FILE_SIZE + 1))).toThrow('10 MB')
    expect(() => parseNmap('<root />')).toThrow('not a recognized Nmap')
    expect(() => parseNmap('<nmaprun scanner="nmap"><host /></nmaprun>')).toThrow(
      'not a recognized Nmap',
    )

    const result = parseNmap(`
      <nmaprun scanner="nmap" version="7.95">
        <host><status state="down"/><address addr="02:00:00:00:00:01" addrtype="mac"/></host>
        <host><status state="up"/><hostname name="missing-mac"/></host>
        <host endtime="invalid"><status state="up"/><address addr="bad-ip" addrtype="ipv4"/><address addr="02:00:00:00:00:02" addrtype="mac"/></host>
        <host><status state="up"/><address addr="2001:db8::1" addrtype="ipv6"/><address addr="02:00:00:00:00:03" addrtype="mac"/><os><osclass vendor="Vendor" osfamily="OS" osgen="1" accuracy="80"/></os></host>
      </nmaprun>
    `)
    expect(result.assets).toHaveLength(2)
    expect(result.assets[0]).not.toHaveProperty('ipAddress')
    expect(result.assets[1]).toMatchObject({
      ipAddress: '2001:db8::1',
      name: '2001:db8::1',
      operatingSystem: 'OS 1',
      osAccuracy: 80,
      vendor: 'Vendor',
    })
    expect(result.warnings.join('\n')).toContain('host is not up')
    expect(result.warnings.join('\n')).toContain('no valid MAC')
    expect(result.warnings.join('\n')).toContain('invalid IP address')
  })
})
