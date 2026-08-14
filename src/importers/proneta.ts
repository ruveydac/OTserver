import { validateIPAddress, validateMACAddress, normalizeMAC } from '../collections/Assets'
import { SaxesParser } from 'saxes'

import type { ImportedAsset, ImportResult } from './types'

export const MAX_IMPORT_FILE_SIZE = 10 * 1024 * 1024

type DeviceDraft = Partial<ImportedAsset> & { macAddress?: string }

const versionFields = new Set(['applicationversion', 'pronetaversion', 'softwareversion', 'version'])

const elementName = (name: string) =>
  (name.includes(':') ? name.slice(name.lastIndexOf(':') + 1) : name)
    .replaceAll(/[^a-z0-9]/gi, '')
    .toLowerCase()

const valueOrUndefined = (value: string | undefined) => value?.trim() || undefined

export const parseProneta = (xml: string): ImportResult => {
  if (!xml.trim()) throw new Error('The XML file is empty.')
  if (Buffer.byteLength(xml, 'utf8') > MAX_IMPORT_FILE_SIZE) {
    throw new Error('The XML file exceeds the 10 MB import limit.')
  }

  const assets = new Map<string, ImportedAsset>()
  const result: ImportResult = { assets: [], warnings: [] }
  const tags: string[] = []
  const text: string[] = []
  let currentDevice: DeviceDraft | undefined
  let rootName: string | undefined
  let sawDeviceCollection = false

  const parser = new SaxesParser()
  const appendText = (value: string) => {
    if (text.length) text[text.length - 1] += value
  }

  parser.on('error', (error) => {
    throw new Error(`Invalid XML: ${error.message}`)
  })
  parser.on('doctype', () => {
    throw new Error('XML document types are not allowed.')
  })
  parser.on('text', appendText)
  parser.on('cdata', appendText)
  parser.on('opentag', (tag) => {
    const name = elementName(tag.name)
    const parent = tags.at(-1)
    tags.push(name)
    text.push('')

    if (!rootName) {
      rootName = name
      for (const [attributeName, attributeValue] of Object.entries(tag.attributes)) {
        if (versionFields.has(elementName(attributeName))) {
          result.sourceVersion = String(attributeValue).trim() || undefined
        }
      }
    }
    if (name === 'devicecollection' && parent === 'topology') sawDeviceCollection = true
    if (name === 'device' && parent === 'devicecollection') currentDevice = {}
  })
  parser.on('closetag', () => {
    const name = tags.at(-1) || ''
    const parent = tags.at(-2)
    const value = valueOrUndefined(text.pop())

    if (currentDevice && parent === 'device' && value) {
      switch (name) {
        case 'descriptor':
          currentDevice.description = value
          break
        case 'devicetype':
          currentDevice.model = value
          break
        case 'gatewayip':
          currentDevice.gatewayAddress = value
          break
        case 'ipaddress':
          currentDevice.ipAddress = value
          break
        case 'location':
          currentDevice.location = value
          break
        case 'mac':
        case 'macaddress':
          currentDevice.macAddress = value
          break
        case 'manufacturername':
          currentDevice.vendor = value
          break
        case 'nameofstation':
          currentDevice.name = value
          break
        case 'networkmask':
          currentDevice.networkMask = value
          break
      }
    }

    if (currentDevice && name === 'device' && parent === 'devicecollection') {
      const mac = currentDevice.macAddress && normalizeMAC(currentDevice.macAddress)
      if (!mac || validateMACAddress(mac) !== true) {
        result.warnings.push(
          `${currentDevice.name || 'Unnamed device'} was skipped because it has no valid MAC address.`,
        )
      } else if (assets.has(mac)) {
        result.warnings.push(`Duplicate device MAC ${mac} was ignored.`)
      } else {
        for (const field of ['ipAddress', 'networkMask', 'gatewayAddress'] as const) {
          const fieldValue = currentDevice[field]
          if (fieldValue && validateIPAddress(fieldValue) !== true) {
            result.warnings.push(`${mac} has an invalid ${field}; that value was ignored.`)
            delete currentDevice[field]
          }
        }
        assets.set(mac, {
          ...currentDevice,
          macAddress: mac,
          name: currentDevice.name || currentDevice.model || mac,
        })
      }
      currentDevice = undefined
    } else if (parent === 'topology' && value) {
      if (name === 'projectname') result.projectName = value
      if (name === 'name') result.topologyName = value
      if (versionFields.has(name)) result.sourceVersion = value
    }

    tags.pop()
  })

  parser.write(xml).close()

  if (rootName !== 'topology' || !sawDeviceCollection) {
    throw new Error('This is not a recognized PRONETA topology file.')
  }
  result.assets = [...assets.values()]
  return result
}
