#!/usr/bin/env python3
"""Small read-only responders for protocols without maintained test emulators."""

import asyncio
import ssl
import sys


def fins_payload(sid: int) -> bytes:
    response = bytearray(106)
    response[0] = 0xC0
    response[9] = sid
    response[10:12] = b"\x05\x01"
    response[14:34] = b"CJ2M-CPU32".ljust(20, b"\0")
    response[34:54] = b"02.01".ljust(20, b"\0")
    response[94:96] = (32_000).to_bytes(2, "big")
    response[96] = 64
    response[97:99] = (32_000).to_bytes(2, "big")
    response[99] = 64
    response[100] = 32
    response[101:103] = (20_000).to_bytes(2, "big")
    response[103] = 1
    response[104:106] = (4096).to_bytes(2, "big")
    return bytes(response)


def fins_tcp_frame(command: int, payload: bytes) -> bytes:
    body = command.to_bytes(4, "big") + b"\0\0\0\0" + payload
    return b"FINS" + len(body).to_bytes(4, "big") + body


async def read_fins_frame(reader: asyncio.StreamReader) -> bytes:
    header = await reader.readexactly(8)
    if header[:4] != b"FINS":
        raise ValueError("invalid FINS/TCP header")
    length = int.from_bytes(header[4:8], "big")
    if length > 65_527:
        raise ValueError("oversized FINS/TCP request")
    return header + await reader.readexactly(length)


async def handle_fins(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request = await read_fins_frame(reader)
        if request[8:12] != b"\0\0\0\0":
            return
        writer.write(fins_tcp_frame(1, b"\0\0\0\x0a\0\0\0\x01"))
        await writer.drain()
        request = await read_fins_frame(reader)
        if request[8:12] != b"\0\0\0\x02":
            return
        writer.write(fins_tcp_frame(2, fins_payload(5)))
        await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, ValueError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


class FinsUdp(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, address: tuple[str, int]) -> None:
        if len(data) >= 12 and data[10:12] == b"\x05\x01":
            self.transport.sendto(fins_payload(0xEF), address)


FOX_RESPONSE = b"""fox a 0 -1 fox hello
{
hostName=s:niagara-station-1
hostAddress=s:172.30.0.14
fox.version=s:4.13.1
app.name=s:Station
app.version=s:4.13.1
vm.name=s:Java HotSpot
vm.version=s:17
os.name=s:QNX
timeZone=s:Europe/Berlin
hostId=s:OTLAB-FOX-1
vmUuid=s:00000000-0000-0000-0000-000000000014
brandId=s:Tridium
};;
"""


async def handle_fox(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        request = bytearray()
        while b"};;" not in request and len(request) <= 65_536:
            chunk = await reader.read(2048)
            if not chunk:
                return
            request.extend(chunk)
        if request.startswith(b"fox a 1"):
            writer.write(FOX_RESPONSE)
            await writer.drain()
    except (ConnectionError, ssl.SSLError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def run_fins() -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        FinsUdp, local_addr=("0.0.0.0", 9600)
    )
    server = await asyncio.start_server(handle_fins, "0.0.0.0", 9600)
    try:
        async with server:
            await server.serve_forever()
    finally:
        transport.close()


async def run_fox() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/lab.crt", "/lab.key")
    plain = await asyncio.start_server(handle_fox, "0.0.0.0", 1911)
    tls = await asyncio.start_server(handle_fox, "0.0.0.0", 4911, ssl=context)
    async with plain, tls:
        await asyncio.gather(plain.serve_forever(), tls.serve_forever())


def self_test() -> None:
    udp = fins_payload(0xEF)
    tcp = fins_tcp_frame(2, fins_payload(5))
    assert len(udp) == 106 and udp[9:14] == b"\xef\x05\x01\0\0"
    assert len(tcp) == 122 and tcp[:4] == b"FINS"
    assert tcp[16] == 0xC0 and tcp[25:30] == b"\x05\x05\x01\0\0"
    assert FOX_RESPONSE.startswith(b"fox a 0") and FOX_RESPONSE.endswith(b"};;\n")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode == "self-test":
        self_test()
    elif mode == "fins":
        asyncio.run(run_fins())
    elif mode == "fox":
        asyncio.run(run_fox())
    else:
        raise SystemExit("usage: responders.py {fins|fox|self-test}")
