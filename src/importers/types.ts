import type { DataQuality } from './assetQuality'

export type ImportedObservation = {
  fields: Record<string, unknown>
  interfaces?: unknown[]
  observedAt: string
  ports?: unknown[]
  quality: DataQuality
  raw?: unknown
  source: string
  warnings?: string[]
}

export type ImportedAsset = {
  description?: string
  gatewayAddress?: string
  ipAddress?: string
  lastSeen?: string
  location?: string
  macAddress: string
  model?: string
  name: string
  networkMask?: string
  operatingSystem?: string
  osAccuracy?: number
  firmwareVersion?: string
  protocols?: ('bacnet' | 'ethernet-ip' | 'modbus-tcp' | 'niagara-fox' | 'omron-fins' | 'opc-ua' | 'other' | 'profinet' | 's7')[]
  serialNumber?: string
  status?: 'maintenance' | 'offline' | 'online' | 'unknown'
  vendor?: string
  observations?: ImportedObservation[]
}

export type ImportedTopologyLink = {
  local: Record<string, unknown>
  observedAt: string
  raw?: unknown
  remote: Record<string, unknown>
  source: string
}

export type ImportResult = {
  assets: ImportedAsset[]
  links?: ImportedTopologyLink[]
  projectName?: string
  scanMetadata?: Record<string, unknown>
  sourceVersion?: string
  topologyName?: string
  unresolved?: unknown[]
  warnings: string[]
}
