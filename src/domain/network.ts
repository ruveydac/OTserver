import { isIP } from 'node:net'

const macAddressPattern = /^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$/

export const normalizeMAC = (value: string): string =>
  value.trim().replaceAll('-', ':').toUpperCase()

export const validateIPAddress = (value: null | string | undefined): string | true =>
  !value || isIP(value.trim()) !== 0 || 'Enter a valid IPv4 or IPv6 address.'

export const validateMACAddress = (value: null | string | undefined): string | true =>
  !value || macAddressPattern.test(normalizeMAC(value)) || 'Enter a valid MAC address.'
