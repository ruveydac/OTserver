export const importSources = [
  {
    label: 'OTserver Scanner',
    value: 'otserver-scanner',
    quality: 'low',
    fileLabel: 'OTserver Scanner JSON',
    steps: [
      'Windows 10+ uses native IP Helper and Packet Monitor (pktmon); Linux requires root or CAP_NET_RAW. Then run otserver-scanner doctor.',
      'List capture devices with otserver-scanner interfaces.',
      'Run otserver-scanner scan --target <network> --interface <id> --source-mac <mac> --output scan.json --ack-authorized.',
      'Optionally add --snmp-config profiles.json for read-only SNMP v2c/v3 collection.',
      'To import directly, add an OTserver URL, site ID, and user API key through otscanner.json or the documented flags and environment variable.',
    ],
    required:
      'A validated otserver-scan JSON file with schemaVersion 2 and a unique MAC address per device.',
    note: 'Native protocol, PROFINET, and SNMP observations are high quality. ARP/OUI, OPC UA asset, and OS fingerprint observations are medium quality. Credentials are never included in the export.',
  },
  {
    label: 'Siemens PRONETA',
    value: 'proneta',
    quality: 'high',
    fileLabel: 'PRONETA topology XML',
    steps: [
      'Discover the network in PRONETA and open the resulting topology.',
      'Export or save the topology as an XML file.',
      'Verify that every device to import has a MAC address.',
    ],
    required: 'A topology XML containing DeviceCollection / Device entries and a MAC per device.',
    note: 'Names, IP addresses, vendor, model, location, and topology metadata are imported when present. PRONETA versions may add or rename optional fields.',
  },
  {
    label: 'Nmap XML',
    value: 'nmap',
    quality: 'medium',
    fileLabel: 'Nmap scan XML',
    steps: [
      'Run Nmap with sufficient privileges from the same Ethernet network or VLAN as the devices so it can discover MAC addresses.',
      'Replace the example network with the network you are authorized to scan, then run the combined TCP and UDP command below.',
      'The command queries Siemens S7, EtherNet/IP, BACnet, Omron FINS, and Tridium Niagara Fox services.',
      'Verify that the wanted hosts are marked up and have a MAC address in the XML.',
    ],
    command:
      'sudo nmap -O -PR -R -sS -sU -p T:102,1911,4911,9600,44818,U:9600,44818,47808 --script s7-info,enip-info,bacnet-info,omron-info,fox-info -oX nmap.xml 192.168.1.0/24',
    required: 'An Nmap -oX file with an up host, an IP address, and a MAC address for every asset.',
    note: 'Only scan authorized OT networks during an approved window. These are Nmap discovery/version scripts. Hosts without a MAC address are skipped, and OS detection may be incomplete when the selected ICS ports do not include both an open and a closed TCP port.',
  },
] as const

export type ImportSource = (typeof importSources)[number]['value']
