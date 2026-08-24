# OTserver Scanner

Windows and Linux read-only discovery CLI for [OTserver](https://otserver.org). It discovers IPv4/MAC pairs
with ARP and directly queries PROFINET DCP, S7, EtherNet/IP, BACnet, Omron FINS, Niagara Fox, OPC UA, and
optional SNMP. Windows uses native IP Helper for active ARP, Win10Pcap for active PROFINET DCP, and
Microsoft pktmon as a passive fallback. Linux uses native raw sockets. No TAP adapter or Windows
Network Bridge is used or modified.

The 64-bit Windows release embeds the unmodified, signed Win10Pcap 10.2.5002 MSI under GPLv2 and can
install it only when explicitly requested from the elevated GUI or with
`otserver-scanner install-win10pcap`. Driver installation does not disrupt networking. The scanner
dynamically loads the installed `Packet.dll` from the Windows system directory, matches the selected
physical interface by GUID, transmits DCP Identify, and captures only PROFINET Ethernet frames. The
corresponding Win10Pcap project information is at <https://www.win10pcap.org/>.

## Linux

```bash
cargo build --release
sudo ./target/release/otserver-scanner doctor
sudo ./target/release/otserver-scanner interfaces
sudo ./target/release/otserver-scanner scan \
  --target 192.168.1.0/24 \
  --interface eth0 \
  --source-mac 00:11:22:33:44:55 \
  --output ./scan.otserver.json \
  --ack-authorized
```

Linux Ethernet discovery uses a native `AF_PACKET` raw socket and therefore needs root or
`CAP_NET_RAW`.

## Windows

```powershell
cargo build --release --target x86_64-pc-windows-msvc
.\target\x86_64-pc-windows-msvc\release\otserver-scanner.exe doctor
.\target\x86_64-pc-windows-msvc\release\otserver-scanner.exe interfaces
.\target\x86_64-pc-windows-msvc\release\otserver-scanner.exe scan `
  --target 192.168.1.0/24 `
  --interface '<interface name or GUID>' `
  --source-mac 00:11:22:33:44:55 `
  --no-bacnet `
  --output .\scan.otserver.json `
  --ack-authorized
```

Only scan networks you own or are authorized to assess. The scanner sends PROFINET DCP Identify,
read-only SNMP requests, and fixed read-only identity requests for S7, EtherNet/IP, BACnet, Omron
FINS, Niagara Fox, and OPC UA. It never runs SNMP SET, DCP Set, brute-force, exploit, vulnerability, or
Modbus requests.

All discovery protocols are enabled by default. Disable individual protocols on the CLI with
`--no-arp`, `--no-profinet`, `--no-s7`, `--no-enip`, `--no-bacnet`, `--no-fins`, `--no-fox`, `--no-opcua`, or
`--no-snmp` and `--no-lldp`. SNMP inventory and LLDP topology queries share the same SNMP settings
but can be enabled independently. The GUI exposes the same choices as highlighted on/off toggle
buttons. The scan log records one entry per probed IP and protocol, for example
`[12:43] 192.168.1.10 Protocol snmp Success`.

The GUI output field accepts a filename directly or opens the native save-file picker. Stopping a
running scan writes a valid partial export containing all results collected before cancellation.

SNMP settings and credentials live in the `snmp` block of `otscanner.json` and are fully editable
in the GUI. Without any settings, SNMPv2c with the community `public` is used, so SNMP never blocks
a scan. Set `version` to `1` for a legacy SNMPv1 agent. For SNMPv3 set `version` to `3` plus
`username`, optional `contextName`, and the
`authProtocol`/`authPassword` and `privacyProtocol`/`privacyPassword` pairs. Credentials are stored
in plaintext in `otscanner.json`; keep the file out of source control and restrict its permissions.
Credentials are never written to logs or scan exports.

SNMP uses bounded, read-only queries for system identity, IF-MIB/IP-MIB interfaces, ENTITY-MIB
components, BRIDGE/Q-BRIDGE ports and VLANs, LLDP topology, and the generic Siemens
AUTOMATION-SYSTEM-MIB identity scalars. It probes configured IPv4 targets even when Layer 2
discovery cannot see them, but creates an asset only after obtaining a valid MAC from an interface,
bridge, or LLDP chassis identity. Forwarding-table MACs are port evidence only and never asset
identities.

OPC UA discovery connects to ports 4840, 4841, and 48400 by default (configurable via `opcuaPorts`).
The scanner prefers anonymous authentication; if the server requires username authentication, set
`opcuaUsername` and `opcuaPassword` in the config or in the GUI. Passwords travel unencrypted
because the scanner uses SecurityPolicy None, and are never written to logs or scan exports.
The scanner reads only asset identification, health, and location variables; it never writes values
or calls methods that modify server state.

Validate an export before uploading it:

```powershell
.\otserver-scanner.exe validate .\scan.otserver.json
```

Exit code `0` means a complete scan, `2` means the valid output contains partial failures, and `1`
means no valid output was produced. Windows ARP discovery needs no additional driver. Windows
active PROFINET discovery requires Win10Pcap (GPLv2) and Administrator rights. Install the bundled
package explicitly from the GUI or by running `otserver-scanner install-win10pcap` in an elevated
terminal. The scanner opens the selected physical adapter directly; no virtual adapter or bridge is
required. If Win10Pcap is unavailable, the scanner uses built-in pktmon as a passive fallback.
Pktmon requires Administrator rights and cannot transmit DCP Identify frames.

## Configuration and direct import

Place an optional `otscanner.json` beside the scanner executable to provide scan defaults and an
OTserver destination:

```json
{
  "targets": ["192.168.1.0/24"],
  "interface": "eth0",
  "sourceMac": "00:11:22:33:44:55",
  "output": "scan.otserver.json",
  "snmp": {
    "version": "2c",
    "community": "public"
  },
  "noArp": false,
  "noProfinet": false,
  "noS7": false,
  "noEnip": false,
  "noBacnet": false,
  "noFins": false,
  "noFox": false,
  "noOpcua": false,
  "opcuaPorts": [4840, 4841, 48400],
  "opcuaUsername": "",
  "opcuaPassword": "",
  "noSnmp": false,
  "noLldp": false,
  "serverUrl": "https://otserver.example",
  "site": "PAYLOAD_SITE_ID",
  "apiKey": "PAYLOAD_USER_API_KEY"
}
```

An SNMPv3 block looks like this instead:

```json
{
  "snmp": {
    "version": "3",
    "username": "inventory",
    "contextName": "optional-snmp-context",
    "authProtocol": "sha256",
    "authPassword": "...",
    "privacyProtocol": "aes128",
    "privacyPassword": "..."
  }
}
```

Command-line values override the file, and `OTSERVER_API_KEY` overrides its `apiKey`. Relative paths
are resolved from the current working directory. The config contains credentials in plaintext; keep
it out of source control and restrict its permissions (for example, `chmod 600 otscanner.json`).
The safer automation setup omits `apiKey` from the file and supplies `OTSERVER_API_KEY` through the
process environment.

When `serverUrl`, `site`, and an API key are present, `scan` writes and validates the local JSON and
then posts it to OTserver's REST API. The local file remains available if the upload fails. The site
must be its Payload document ID, and the API key user must have read/write access there. Explicit
flags can also select the destination:

```bash
OTSERVER_API_KEY='...' otserver-scanner scan \
  --target 192.168.1.0/24 \
  --interface eth0 \
  --source-mac 00:11:22:33:44:55 \
  --server-url https://otserver.example \
  --site PAYLOAD_SITE_ID \
  --ack-authorized
```

`--ack-authorized` is intentionally never read from configuration and remains mandatory for every
scan.

## Virtual OT lab

The Docker lab exercises the complete Linux scanner against deterministic virtual devices for ARP,
PROFINET DCP, S7, EtherNet/IP, BACnet/IP, Omron FINS, Niagara Fox, OPC UA, SNMPv2c, SNMPv3, and LLDP:

```bash
./lab/test.sh
```

It requires Linux containers, Docker Engine with Compose, and permission to use the Docker daemon.
The scanner and Siemens containers receive only `NET_RAW`; the lab does not use host networking or
publish protocol ports. Windows developers can run the same command through Docker Desktop with
WSL2. Scan JSON and Compose logs are retained under `lab/artifacts/`.

To exercise the native Windows executable against the Docker Desktop responders, run PowerShell on
the Windows host:

```powershell
.\lab\test-windows.ps1
```

The Windows version is a protocol-client smoke test, not a multi-device discovery test. It binds the
responder ports only to Docker/WSL's host-only Hyper-V adapter and runs the real `.exe` against that
single host-routed endpoint. Consequently, Windows ARP sees the Hyper-V adapter's MAC and all
forwarded protocol responses belong to that one temporary identity; Docker's internal container
MACs are not visible to the Windows host. The importable scan is deleted after validation and only a
plain-text summary and Compose log are retained.

This smoke test covers Windows ARP, S7, EtherNet/IP, BACnet, FINS, Fox, OPC UA, SNMP, and LLDP client paths.
It does not verify distinct device MAC correlation. Docker Desktop also does not bridge raw Ethernet
frames between its Linux bridge and a Windows capture driver, so the harness disables PROFINET DCP.
Active Windows DCP and multi-device MAC discovery require physical Layer-2 test devices or a
dedicated external Layer-2 test interface.

Images use pinned Snap7 and SNMP Simulator packages plus checksum-pinned OpENer and BACnet Stack sources; the
repository's small FINS and Fox responders implement only the fixed read-only identity requests sent
by this scanner. The OPC UA responder uses the maintained asyncua (opcua-asyncio) Python stack.

SNMPv3 settings may include an optional `contextName`. Most physical devices use the default empty
context and can omit it; simulators and partitioned agents may require it.

## License

OTserver Scanner is dual-licensed with OTserver: it is available under
[GNU AGPLv3](../LICENCE.md), or under a commercial license for proprietary use
without AGPLv3 copyleft obligations. For commercial licensing, enterprise
features, or managed hosting, visit [otserver.org/enterprise](https://otserver.org/enterprise/).

The scanner and the detection needed to find assets and device capabilities
will remain 100% open source. Optional enterprise add-ons, such as SSO
integrations or customized dashboards, do not restrict the open-source core.
