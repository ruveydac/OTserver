import { SaxesParser, type SaxesTagPlain } from 'saxes'

import { normalizeMAC, validateIPAddress, validateMACAddress } from '../collections/Assets'
import { MAX_IMPORT_FILE_SIZE } from './proneta'
import type { ImportedAsset, ImportResult } from './types'

type HostDraft = Partial<ImportedAsset> & {
  hostnameType?: string
  isUp?: boolean
  macAddress?: string
  osMatchFound?: boolean
  osVendor?: string
}

const attribute = (tag: SaxesTagPlain, name: string) => {
  const value = tag.attributes[name]
  return value === undefined ? undefined : String(value).trim() || undefined
}

const unixTime = (value: string | undefined) => {
  const seconds = Number(value)
  return value && Number.isFinite(seconds) ? new Date(seconds * 1000).toISOString() : undefined
}

export const parseNmap = (xml: string): ImportResult => {
  if (!xml.trim()) throw new Error('The XML file is empty.')
  if (Buffer.byteLength(xml, 'utf8') > MAX_IMPORT_FILE_SIZE) {
    throw new Error('The XML file exceeds the 10 MB import limit.')
  }

  const assets = new Map<string, ImportedAsset>()
  const result: ImportResult = { assets: [], warnings: [] }
  const tags: string[] = []
  let currentHost: HostDraft | undefined
  let rootName: string | undefined

  const parser = new SaxesParser()
  parser.on('error', (error) => {
    throw new Error(`Invalid XML: ${error.message}`)
  })
  parser.on('doctype', (doctype) => {
    if (!/^\s*nmaprun(?:\s+SYSTEM\s+["'][^"']+["'])?\s*$/i.test(doctype)) {
      throw new Error('Only the standard Nmap document type is allowed.')
    }
  })
  parser.on('opentag', (tag) => {
    const name = tag.name.toLowerCase()
    const parent = tags.at(-1)
    tags.push(name)

    if (!rootName) {
      rootName = name
      if (name === 'nmaprun' && attribute(tag, 'scanner')?.toLowerCase() === 'nmap') {
        result.sourceVersion = attribute(tag, 'version')
      }
    }

    if (name === 'host' && parent === 'nmaprun') {
      currentHost = { lastSeen: unixTime(attribute(tag, 'endtime')) }
    } else if (currentHost && name === 'status' && parent === 'host') {
      currentHost.isUp = attribute(tag, 'state') === 'up'
    } else if (currentHost && name === 'address' && parent === 'host') {
      const address = attribute(tag, 'addr')
      const type = attribute(tag, 'addrtype')?.toLowerCase()
      if (type === 'mac') {
        currentHost.macAddress = address
        currentHost.vendor = attribute(tag, 'vendor') || currentHost.vendor
      } else if ((type === 'ipv4' || (!currentHost.ipAddress && type === 'ipv6')) && address) {
        currentHost.ipAddress = address
      }
    } else if (currentHost && name === 'hostname' && parent === 'hostnames') {
      const hostname = attribute(tag, 'name')
      const type = attribute(tag, 'type')
      if (
        hostname &&
        (!currentHost.name || (type === 'user' && currentHost.hostnameType !== 'user'))
      ) {
        currentHost.name = hostname
        currentHost.hostnameType = type
      }
    } else if (currentHost && name === 'osmatch' && parent === 'os' && !currentHost.osMatchFound) {
      currentHost.operatingSystem = attribute(tag, 'name')
      currentHost.osMatchFound = Boolean(currentHost.operatingSystem)
      const accuracy = Number(attribute(tag, 'accuracy'))
      if (Number.isFinite(accuracy)) currentHost.osAccuracy = accuracy
    } else if (currentHost && name === 'osclass' && (parent === 'os' || parent === 'osmatch')) {
      currentHost.osVendor ||= attribute(tag, 'vendor')
      if (!currentHost.osMatchFound) {
        currentHost.operatingSystem ||= [attribute(tag, 'osfamily'), attribute(tag, 'osgen')]
          .filter(Boolean)
          .join(' ')
        const accuracy = Number(attribute(tag, 'accuracy'))
        if (Number.isFinite(accuracy)) currentHost.osAccuracy = accuracy
      }
    }
  })
  parser.on('closetag', () => {
    const name = tags.at(-1)
    const parent = tags.at(-2)

    if (currentHost && name === 'host' && parent === 'nmaprun') {
      const label = currentHost.name || currentHost.ipAddress || 'Unnamed host'
      const mac = currentHost.macAddress && normalizeMAC(currentHost.macAddress)

      if (!currentHost.isUp) {
        result.warnings.push(`${label} was skipped because the host is not up.`)
      } else if (!mac || validateMACAddress(mac) !== true) {
        result.warnings.push(`${label} was skipped because it has no valid MAC address.`)
      } else {
        if (currentHost.ipAddress && validateIPAddress(currentHost.ipAddress) !== true) {
          result.warnings.push(`${mac} has an invalid IP address; that value was ignored.`)
          delete currentHost.ipAddress
        }
        const asset: ImportedAsset = {
          ...(currentHost.ipAddress ? { ipAddress: currentHost.ipAddress } : {}),
          ...(currentHost.lastSeen ? { lastSeen: currentHost.lastSeen } : {}),
          ...(currentHost.operatingSystem ? { operatingSystem: currentHost.operatingSystem } : {}),
          ...(currentHost.osAccuracy !== undefined ? { osAccuracy: currentHost.osAccuracy } : {}),
          ...(currentHost.vendor || currentHost.osVendor
            ? { vendor: currentHost.vendor || currentHost.osVendor }
            : {}),
          macAddress: mac,
          name: currentHost.name || currentHost.ipAddress || mac,
          status: 'online',
        }
        if (assets.has(mac)) result.warnings.push(`Duplicate host MAC ${mac} was merged.`)
        assets.set(mac, { ...assets.get(mac), ...asset })
      }
      currentHost = undefined
    }

    tags.pop()
  })

  parser.write(xml).close()

  if (rootName !== 'nmaprun' || !result.sourceVersion) {
    throw new Error('This is not a recognized Nmap XML file.')
  }
  result.assets = [...assets.values()]
  return result
}
