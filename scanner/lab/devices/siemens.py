#!/usr/bin/env python3
"""Siemens lab device: Snap7 server, PROFINET DCP, and SNMP Simulator."""

import signal
import subprocess
import threading
import time

from scapy.all import Ether, get_if_hwaddr, sendp, sniff
from snap7.server import Server

INTERFACE = "eth0"
DCP_MULTICAST = bytes.fromhex("010ECF000000")
ETHERTYPE = bytes.fromhex("8892")


def block(option: int, suboption: int, payload: bytes) -> bytes:
    value = b"\0\0" + payload
    result = bytes((option, suboption)) + len(value).to_bytes(2, "big") + value
    return result + (b"\0" if len(value) % 2 else b"")


def dcp_blocks(mac: bytes) -> bytes:
    uuid = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    return b"".join(
        [
            block(1, 1, mac),
            block(
                1,
                3,
                bytes((172, 30, 0, 10, 255, 255, 255, 0, 172, 30, 0, 1))
                + bytes((1, 1, 1, 1, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0)),
            ),
            block(2, 1, b"ET 200SP Lab"),
            block(2, 2, b"siemens-plc-1"),
            block(2, 3, bytes.fromhex("002A1234")),
            block(2, 4, bytes((1, 0))),
            block(2, 5, bytes((1, 3, 2, 1, 2, 2))),
            block(2, 6, b"port-001.siemens-plc-1"),
            block(2, 7, bytes.fromhex("0102")),
            block(2, 8, bytes.fromhex("002A5678")),
            block(2, 10, bytes.fromhex("003F")),
            block(2, 11, bytes.fromhex("001F")),
            block(3, 61, bytes.fromhex("3D0101")),
            block(3, 255, bytes.fromhex("FF0100")),
            block(6, 1, bytes.fromhex("0001")),
            block(7, 1, uuid + b"ot-lab-domain"),
            block(7, 2, bytes.fromhex("0001")),
            block(7, 3, uuid),
            block(7, 4, uuid),
            block(7, 5, bytes.fromhex("002A12340102")),
        ]
    )


def respond_dcp(packet: Ether) -> None:
    request = bytes(packet)
    if (
        len(request) < 30
        or request[:6] != DCP_MULTICAST
        or request[12:14] != ETHERTYPE
        or request[14:18] != bytes.fromhex("FEFE0500")
        or request[26:30] != bytes.fromhex("FFFF0000")
    ):
        return
    mac = bytes.fromhex(get_if_hwaddr(INTERFACE).replace(":", ""))
    data = dcp_blocks(mac)
    response = (
        request[6:12]
        + mac
        + ETHERTYPE
        + bytes.fromhex("FEFF0501")
        + request[18:22]
        + b"\0\0"
        + len(data).to_bytes(2, "big")
        + data
    )
    if len(response) < 60:
        response += bytes(60 - len(response))
    sendp(Ether(response), iface=INTERFACE, verbose=False)


def run_dcp() -> None:
    sniff(
        iface=INTERFACE,
        store=False,
        prn=respond_dcp,
        lfilter=lambda packet: packet.haslayer(Ether) and packet.type == 0x8892,
    )


def start_snmp() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            "snmpsim-command-responder",
            "--v3-engine-id=80004FB8054F544C4142",
            "--data-dir=/lab/snmp-data",
            "--cache-dir=/tmp/snmpsim",
            "--agent-udpv4-endpoint=0.0.0.0:161",
            "--v3-user=inventory",
            "--v3-auth-key=lab-auth-password",
            "--v3-auth-proto=SHA256",
            "--v3-priv-key=lab-privacy-password",
            "--v3-priv-proto=AES",
            "--process-user=nobody",
            "--process-group=nogroup",
        ]
    )


def main() -> None:
    stop = threading.Event()
    for event in (signal.SIGINT, signal.SIGTERM):
        signal.signal(event, lambda *_: stop.set())

    s7 = Server(log=False)
    s7.start(tcp_port=102)
    snmp = start_snmp()
    threading.Thread(target=run_dcp, daemon=True).start()
    try:
        while not stop.wait(0.5):
            if snmp.poll() is not None:
                raise SystemExit(f"SNMP Simulator exited with {snmp.returncode}")
    finally:
        snmp.terminate()
        try:
            snmp.wait(timeout=5)
        except subprocess.TimeoutExpired:
            snmp.kill()
        s7.stop()
        s7.destroy()


if __name__ == "__main__":
    assert len(dcp_blocks(bytes.fromhex("020000000010"))) % 2 == 0
    main()
