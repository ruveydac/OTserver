#!/usr/bin/env python3
"""OPC UA lab device built on asyncua (opcua-asyncio).

Mirrors the OPC UA asset management companion specification layout:

  Objects
  ├── Aliases/Assets/AssetsByAssetId/FindAlias
  ├── DeviceSet
  │   └── OT Lab Asset (with Identification, DocumentationLinks, OperationCounters)
  └── OT Lab Asset (same asset, also reachable via DeviceSet)

The server advertises anonymous and username authentication over SecurityPolicy None.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any, List

from asyncua import Server, ua
from asyncua.common import ua_utils
from asyncua.server.user_managers import User, UserRole
from asyncua.ua.ua_binary import struct_to_binary

ASSET_ID = "LAB-ASSET-1"
ASSET_NODE_ID = ua.NodeId(300, 1)
USERNAME = "lab-user"
PASSWORD = "lab-opcua-password"


class LabUserManager:
    """Accept anonymous sessions plus the fixed lab username credential."""

    def get_user(
        self,
        iserver: Any,
        username: str | None = None,
        password: str | None = None,
        certificate: Any = None,
    ) -> User | None:
        if username is None:
            return User(role=UserRole.User)
        if username == USERNAME and password == PASSWORD:
            return User(role=UserRole.Admin)
        return None


async def build_address_space(server: Server) -> None:
    lab = await server.register_namespace("urn:otserver:lab:opcua")
    di = await server.register_namespace("http://opcfoundation.org/UA/DI/")
    amb = await server.register_namespace("http://opcfoundation.org/UA/AMB/")

    objects = server.nodes.objects
    aliases = server.get_node(ua.NodeId(ua.ObjectIds.Aliases, 0))
    assets = await aliases.add_folder(ua.NodeId(110, lab), f"{lab}:Assets")
    category = await assets.add_object(ua.NodeId(111, lab), f"{lab}:AssetsByAssetId")

    # Asset with identification, health, location, documentation, counters.
    asset = await objects.add_object(ua.NodeId(300, lab), f"{lab}:OT Lab Asset")
    identification = await asset.add_folder(
        ua.NodeId(310, lab), f"{di}:Identification"
    )
    await asset.add_variable(
        ua.NodeId(301, lab),
        f"{di}:AssetId",
        ua.Variant(ASSET_ID, ua.VariantType.String),
    )
    await identification.add_variable(
        ua.NodeId(311, lab),
        f"{di}:Manufacturer",
        ua.LocalizedText("OT Lab Manufacturing"),
    )
    await identification.add_variable(
        ua.NodeId(312, lab),
        f"{di}:Model",
        ua.LocalizedText("OPC UA Lab Device"),
    )
    await identification.add_variable(
        ua.NodeId(313, lab),
        f"{di}:SerialNumber",
        ua.Variant("OPCLAB0001", ua.VariantType.String),
    )
    await identification.add_variable(
        ua.NodeId(316, lab),
        f"{di}:ProductInstanceUri",
        ua.Variant("urn:otserver:lab:device:OPCLAB0001", ua.VariantType.String),
    )
    await identification.add_variable(
        ua.NodeId(315, lab),
        f"{di}:DeviceClass",
        ua.Variant("Test Device", ua.VariantType.String),
    )
    await identification.add_variable(
        ua.NodeId(318, lab),
        f"{di}:HardwareRevision",
        ua.Variant("A1", ua.VariantType.String),
    )
    await identification.add_variable(
        ua.NodeId(314, lab),
        f"{di}:SoftwareRevision",
        ua.Variant("2.1.0", ua.VariantType.String),
    )
    await identification.add_variable(
        ua.NodeId(319, lab),
        f"{di}:RevisionCounter",
        ua.Variant(7, ua.VariantType.Int32),
    )
    await identification.add_variable(
        ua.NodeId(317, lab),
        f"{di}:DeviceHealth",
        ua.Variant(0, ua.VariantType.Int32),
    )
    await asset.add_variable(
        ua.NodeId(320, lab),
        f"{amb}:HierarchicalLocation",
        ua.Variant("Plant1/Line3/Cell2", ua.VariantType.String),
    )

    docs = await asset.add_folder(
        ua.NodeId(330, lab), f"{lab}:DocumentationLinks"
    )
    await docs.add_variable(
        ua.NodeId(331, lab),
        f"{lab}:Manual",
        ua.Variant("https://otserver.org/manuals/lab-device.pdf", ua.VariantType.String),
    )
    counters = await asset.add_folder(
        ua.NodeId(340, lab), f"{lab}:OperationCounters"
    )
    await counters.add_variable(
        ua.NodeId(341, lab),
        f"{lab}:OperatingHours",
        ua.Variant(1234.5, ua.VariantType.Double),
    )

    # DeviceSet fallback entry point: the same asset is also organized by DeviceSet.
    device_set = await objects.add_folder(ua.NodeId(200, lab), f"{di}:DeviceSet")
    await device_set.add_reference(asset, ua.NodeId(ua.ObjectIds.Organizes, 0))

    # FindAlias method: returns an AliasNameDataType referencing the asset node.
    def find_alias(parent: Any, pattern: Any) -> List[ua.Variant]:
        alias = ua.AliasNameDataType()
        alias.AliasName = ua.QualifiedName(ASSET_ID, lab)
        alias.ReferencedNodes = [
            ua.ExpandedNodeId(Identifier=ASSET_NODE_ID.Identifier, NamespaceIndex=lab)
        ]
        ext = ua.ExtensionObject(
            TypeId=ua.extension_object_typeids["AliasNameDataType"],
            Body=struct_to_binary(alias),
        )
        return [ua.Variant([ext], ua.VariantType.ExtensionObject)]

    await category.add_method(
        ua.NodeId(121, lab),
        f"{lab}:FindAlias",
        find_alias,
        [ua.VariantType.String],
        [ua.VariantType.ExtensionObject],
    )


async def run_server() -> None:
    server = Server(user_manager=LabUserManager())
    await server.init()
    await server.set_application_uri("urn:otserver:lab:opcua:server")
    server.set_endpoint("opc.tcp://0.0.0.0:4840/")
    server.set_server_name("OT Lab OPC UA Server")
    await build_address_space(server)
    async with server:
        while True:
            await asyncio.sleep(3600)


def self_test() -> None:
    alias = ua.AliasNameDataType()
    alias.AliasName = ua.QualifiedName(ASSET_ID, 1)
    alias.ReferencedNodes = [
        ua.ExpandedNodeId(Identifier=ASSET_NODE_ID.Identifier, NamespaceIndex=1)
    ]
    ext = ua.ExtensionObject(
        TypeId=ua.extension_object_typeids["AliasNameDataType"],
        Body=struct_to_binary(alias),
    )
    payload = ua.Variant([ext], ua.VariantType.ExtensionObject)
    assert isinstance(payload, ua.Variant)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) == 2 else ""
    if mode == "self-test":
        self_test()
    elif mode == "serve":
        asyncio.run(run_server())
    else:
        raise SystemExit("usage: opcua.py {serve|self-test}")
