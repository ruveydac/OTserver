#!/usr/bin/env python3
"""Run OTserver Scanner against the lab and assert its public JSON contract."""

import json
import os
import subprocess
import uuid
from pathlib import Path

SCANNER = "/usr/local/bin/otserver-scanner"
ARTIFACTS = Path("/artifacts")
SCANNER_MAC = "02:00:00:00:00:02"
DEVICES = {
    "siemens": "02:00:00:00:00:10",
    "ethernet_ip": "02:00:00:00:00:11",
    "bacnet": "02:00:00:00:00:12",
    "fins": "02:00:00:00:00:13",
    "fox": "02:00:00:00:00:14",
}
TARGETS = [f"172.30.0.{number}" for number in range(10, 15)]


def run(*arguments: str) -> None:
    command = [SCANNER, *arguments]
    print("+", " ".join(command), flush=True)
    subprocess.run(command, check=True)


def scan(output: Path, profile: str, targets: list[str], *flags: str) -> dict:
    arguments = ["scan"]
    for target in targets:
        arguments.extend(("--target", target))
    arguments.extend(
        (
            "--interface",
            "eth0",
            "--source-mac",
            SCANNER_MAC,
            "--snmp-config",
            profile,
            "--output",
            str(output),
            "--ack-authorized",
            *flags,
        )
    )
    run(*arguments)
    run("validate", str(output))
    with output.open(encoding="utf-8") as source:
        return json.load(source)


def by_mac(result: dict, mac: str) -> dict:
    return next(device for device in result["devices"] if device["macAddress"] == mac)


def observation(device: dict, source: str) -> dict:
    return next(value for value in device["observations"] if value["source"] == source)


def assert_full(result: dict) -> None:
    assert result["format"] == "otserver-scan" and result["schemaVersion"] == 2
    assert result["scan"].get("partial", False) is False
    assert result["errors"] == []
    assert {device["macAddress"] for device in result["devices"]} == set(DEVICES.values())

    siemens = by_mac(result, DEVICES["siemens"])
    sources = {item["source"] for item in siemens["observations"]}
    assert {"arp", "profinet-dcp", "s7", "snmp"} <= sources

    dcp = observation(siemens, "profinet-dcp")
    assert dcp["fields"] | {
        "name": "siemens-plc-1",
        "model": "ET 200SP Lab",
        "ipAddress": "172.30.0.10",
        "networkMask": "255.255.255.0",
        "gatewayAddress": "172.30.0.1",
    } == dcp["fields"]
    assert dcp["raw"] | {
        "vendorId": 42,
        "deviceId": 0x1234,
        "aliasName": "port-001.siemens-plc-1",
        "deviceInstance": 0x0102,
        "oemVendorId": 42,
        "oemDeviceId": 0x5678,
        "rsiProperties": 0x003F,
        "protocolProperties": 0x001F,
        "deviceInitiative": 1,
        "configurationDomainName": "ot-lab-domain",
    } == dcp["raw"]

    s7 = observation(siemens, "s7")
    assert s7["fields"]["vendor"] == "Siemens"
    assert s7["fields"]["model"] and s7["fields"]["firmwareVersion"]

    snmp = observation(siemens, "snmp")
    assert snmp["fields"] | {
        "name": "siemens-plc-1",
        "location": "OT Lab / Cell 1",
        "vendor": "Siemens",
        "model": "SIMATIC CPU 315-2 PN/DP",
        "serialNumber": "S7LAB0001",
    } == snmp["fields"]
    interface = next(value for value in siemens["interfaces"] if value["key"] == "ifIndex:1")
    assert interface["macAddress"] == DEVICES["siemens"]
    assert interface["speed"] == 1_000_000_000
    assert interface["adminStatus"] == interface["operStatus"] == "up"
    assert any(
        link["source"] == "lldp"
        and link["local"]["macAddress"] == DEVICES["siemens"]
        and link["remote"]["macAddress"] == DEVICES["ethernet_ip"]
        for link in result["links"]
    )

    ethernet_ip = observation(by_mac(result, DEVICES["ethernet_ip"]), "ethernet-ip")
    assert ethernet_ip["fields"] | {
        "name": "OT Lab EtherNet-IP Adapter",
        "model": "OT Lab EtherNet-IP Adapter",
        "vendor": "Rockwell Automation/Allen-Bradley",
        "firmwareVersion": "2.3",
        "serialNumber": "075BCD15",
    } == ethernet_ip["fields"]
    enip_ports = {
        (value["key"], value["source"])
        for value in by_mac(result, DEVICES["ethernet_ip"])["ports"]
    }
    assert {("tcp:44818", "ethernet-ip"), ("udp:44818", "ethernet-ip")} <= enip_ports

    bacnet = observation(by_mac(result, DEVICES["bacnet"]), "bacnet")
    assert bacnet["fields"] | {
        "name": "BACnet Basic Device",
        "model": "GNU Basic Server Model 42",
        "description": "BACnet Basic Server Device",
        "location": "GNU Basic Building",
        "vendor": "BACnet Stack at SourceForge",
    } == bacnet["fields"]
    assert bacnet["raw"]["instanceNumber"] == 12001

    fins = observation(by_mac(result, DEVICES["fins"]), "omron-fins")
    assert fins["fields"] | {
        "name": "CJ2M-CPU32",
        "model": "CJ2M-CPU32",
        "vendor": "Omron",
        "firmwareVersion": "02.01",
    } == fins["fields"]
    fins_ports = {value["key"] for value in by_mac(result, DEVICES["fins"])["ports"]}
    assert {"tcp:9600", "udp:9600"} <= fins_ports

    fox = observation(by_mac(result, DEVICES["fox"]), "niagara-fox")
    assert fox["fields"] | {
        "name": "niagara-station-1",
        "operatingSystem": "QNX",
        "vendor": "Tridium",
    } == fox["fields"]
    fox_ports = {value["key"]: value["raw"] for value in by_mac(result, DEVICES["fox"])["ports"]}
    assert fox_ports["tcp:1911"]["tls"] is False
    assert fox_ports["tcp:4911"]["tls"] is True


def assert_v3(result: dict) -> None:
    assert result["errors"] == [] and result["scan"].get("partial", False) is False
    assert len(result["devices"]) == 1
    device = by_mac(result, DEVICES["siemens"])
    snmp = observation(device, "snmp")
    assert snmp["fields"]["name"] == "siemens-plc-1"
    assert snmp["fields"]["serialNumber"] == "S7LAB0001"


def main() -> None:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    run_id = uuid.uuid4().hex[:8]
    full_path = ARTIFACTS / f"full-scan-{run_id}.otserver.json"
    v3_path = ARTIFACTS / f"snmp-v3-{run_id}.otserver.json"
    assert_full(scan(full_path, "/lab/snmp-v2c.json", TARGETS))
    assert_v3(
        scan(
            v3_path,
            "/lab/snmp-v3.json",
            ["172.30.0.10"],
            "--no-protocols",
            "--no-profinet",
        )
    )
    for artifact in (full_path, v3_path):
        os.chmod(artifact, 0o666)
    print("OTserver Scanner virtual lab passed.", flush=True)


if __name__ == "__main__":
    main()
