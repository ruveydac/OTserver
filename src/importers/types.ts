import type { DataQuality } from './assetQuality'
import type { HardwareIdentity } from '../identity/keys'
import type { EndpointEvidence, ServiceEvidence } from '../identity/evidence'

export type ImportedObservation = {
  fields: Record<string, unknown>
  mergeFields?: Record<string, unknown>
  interfaces?: unknown[]
  observedAt: string
  ports?: unknown[]
  quality: DataQuality
  raw?: unknown
  source: string
  warnings?: string[]
}

export type ImportedAsset = {
  catalogNumber?: string
  description?: string
  gatewayAddress?: string
  ipAddress?: string
  lastSeen?: string
  location?: string
  macAddress?: string
  identity?: HardwareIdentity
  endpoints?: EndpointEvidence[]
  services?: ServiceEvidence[]
  componentRef?: string
  parentComponentRef?: string
  slotPath?: string
  observedViaMAC?: string
  model?: string
  name: string
  networkMask?: string
  operatingSystem?: string
  osAccuracy?: number
  firmwareVersion?: string
  hardwareVersion?: string
  protocols?: (
    | 'bacnet'
    | 'dnp3'
    | 'ethernet-ip'
    | 'iec61850'
    | 'modbus-tcp'
    | 'netbios'
    | 'niagara-fox'
    | 'omron-fins'
    | 'opc-ua'
    | 'other'
    | 'profinet'
    | 's7'
  )[]
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
