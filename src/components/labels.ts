export const statusLabels: Record<string, string> = {
  maintenance: 'Maintenance',
  offline: 'Offline',
  online: 'Online',
  unknown: 'Unknown',
}

export const protocolLabels: Record<string, string> = {
  bacnet: 'BACnet',
  dnp3: 'DNP3',
  'ethernet-ip': 'EtherNet/IP',
  iec61850: 'IEC 61850',
  'modbus-tcp': 'Modbus TCP',
  'niagara-fox': 'Niagara Fox',
  'omron-fins': 'Omron FINS',
  'opc-ua': 'OPC UA',
  other: 'Other',
  profinet: 'PROFINET',
  s7: 'S7',
}

export const criticalityLabels: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  low: 'Low',
  medium: 'Medium',
}

const dateFormatter = new Intl.DateTimeFormat('en-GB', { dateStyle: 'medium', timeStyle: 'short' })

export const formatDateTime = (value?: null | string) =>
  value ? dateFormatter.format(new Date(value)) : '—'
