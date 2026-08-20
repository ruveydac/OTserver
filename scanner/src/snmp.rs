use crate::contract::{Endpoint, NetworkInterface, Observation, Source, TopologyLink};
use async_snmp::{Auth, AuthProtocol, Client, PrivProtocol, Retry, Value, oid::Oid};
use serde::{Deserialize, Serialize};
use serde_json::{Map, json};
use std::collections::BTreeMap;
use std::time::Duration;

#[cfg(not(test))]
const SNMP_PORT: u16 = 161;
#[cfg(test)]
const SNMP_PORT: u16 = 1_161;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Settings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub community: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_password: Option<String>,
}

pub struct ResultData {
    pub observation: Option<Observation>,
    pub interfaces: Vec<NetworkInterface>,
    pub links: Vec<TopologyLink>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuerySelection {
    pub inventory: bool,
    pub lldp: bool,
}

pub fn resolved_version(settings: &Settings) -> &str {
    settings
        .version
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("2c")
}

pub fn auth(settings: &Settings) -> Result<Auth, String> {
    let version = resolved_version(settings);
    if version.eq_ignore_ascii_case("2c") {
        let community = settings
            .community
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("public");
        return Ok(Auth::v2c(community.to_owned()));
    }
    if version != "3" {
        return Err(format!("Unsupported SNMP version {version}."));
    }
    let username = settings
        .username
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "SNMPv3 settings need a username.".to_owned())?;
    let mut builder = Auth::usm(username);
    if let Some(protocol) = &settings.auth_protocol {
        builder = builder.auth(
            auth_protocol(protocol)?,
            password(
                settings.auth_password.as_deref(),
                &format!("SNMPv3 authentication protocol {protocol}"),
            )?,
        );
    }
    if let Some(protocol) = &settings.privacy_protocol {
        builder = builder.privacy(
            privacy_protocol(protocol)?,
            password(
                settings.privacy_password.as_deref(),
                &format!("SNMPv3 privacy protocol {protocol}"),
            )?,
        );
    }
    if let Some(context_name) = &settings.context_name {
        builder = builder.context_name(context_name);
    }
    Ok(builder.into())
}

fn password(value: Option<&str>, context: &str) -> Result<String, String> {
    value
        .map(str::to_owned)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{context} needs a password."))
}

fn auth_protocol(value: &str) -> Result<AuthProtocol, String> {
    match value.to_ascii_lowercase().as_str() {
        "md5" => Ok(AuthProtocol::Md5),
        "sha1" => Ok(AuthProtocol::Sha1),
        "sha224" => Ok(AuthProtocol::Sha224),
        "sha256" => Ok(AuthProtocol::Sha256),
        "sha384" => Ok(AuthProtocol::Sha384),
        "sha512" => Ok(AuthProtocol::Sha512),
        _ => Err(format!("Unsupported SNMP authentication protocol: {value}")),
    }
}

fn privacy_protocol(value: &str) -> Result<PrivProtocol, String> {
    match value.to_ascii_lowercase().as_str() {
        "des" => Ok(PrivProtocol::Des),
        "aes128" => Ok(PrivProtocol::Aes128),
        "aes192" => Ok(PrivProtocol::Aes192),
        "aes256" => Ok(PrivProtocol::Aes256),
        _ => Err(format!("Unsupported SNMP privacy protocol: {value}")),
    }
}

pub async fn query(
    target: &str,
    local_mac: Option<&str>,
    settings: &Settings,
    selection: QuerySelection,
) -> Result<ResultData, String> {
    let client = Client::builder((target, SNMP_PORT), auth(settings)?)
        .timeout(Duration::from_secs(3))
        .retry(Retry::fixed(1, Duration::ZERO))
        .max_walk_results(4000)
        .connect()
        .await
        .map_err(|error| format!("SNMP {target}: {error}"))?;
    let mut fields = BTreeMap::new();
    let mut raw = Map::new();
    let mut interfaces = BTreeMap::<String, NetworkInterface>::new();
    if selection.inventory {
        let system = client
            .get_many(&[
                Oid::parse("1.3.6.1.2.1.1.1.0").unwrap(),
                Oid::parse("1.3.6.1.2.1.1.5.0").unwrap(),
                Oid::parse("1.3.6.1.2.1.1.6.0").unwrap(),
                Oid::parse("1.3.6.1.2.1.1.2.0").unwrap(),
            ])
            .await
            .map_err(|error| format!("SNMP {target}: {error}"))?;
        fields.insert("ipAddress".into(), json!(target));
        fields.insert("status".into(), json!("online"));
        fields.insert("lastSeen".into(), json!(crate::now()));
        for item in system {
            let key = item.oid.to_string();
            raw.insert(key.clone(), value_json(&item.value));
            match key.as_str() {
                "1.3.6.1.2.1.1.1.0" => {
                    if let Some(value) = item.value.as_str() {
                        fields.insert("description".into(), json!(value));
                        if let Some(os) = reported_os(value) {
                            fields.insert("operatingSystem".into(), json!(os));
                        }
                    }
                }
                "1.3.6.1.2.1.1.5.0" => {
                    if let Some(value) = item.value.as_str() {
                        fields.insert("name".into(), json!(value));
                    }
                }
                "1.3.6.1.2.1.1.6.0" => {
                    if let Some(value) = item.value.as_str() {
                        fields.insert("location".into(), json!(value));
                    }
                }
                _ => {}
            }
        }
        let if_values = client
            .walk(Oid::parse("1.3.6.1.2.1.2.2.1").unwrap())
            .map_err(|error| error.to_string())?
            .collect()
            .await
            .map_err(|error| format!("SNMP IF-MIB {target}: {error}"))?;
        for item in if_values {
            let key = item.oid.to_string();
            raw.insert(key.clone(), value_json(&item.value));
            let Some((column, index)) = table_cell(&key, "1.3.6.1.2.1.2.2.1") else {
                continue;
            };
            let interface = interfaces
                .entry(index.clone())
                .or_insert_with(|| NetworkInterface {
                    key: format!("ifIndex:{index}"),
                    source: "snmp".into(),
                    name: None,
                    description: None,
                    mac_address: None,
                    ip_addresses: vec![],
                    admin_status: None,
                    oper_status: None,
                    speed: None,
                    mtu: None,
                    raw: json!({}),
                });
            match column {
                "2" => interface.description = item.value.as_str().map(str::to_owned),
                "5" => interface.speed = item.value.as_u64(),
                "6" => {
                    interface.mac_address = item
                        .value
                        .as_bytes()
                        .filter(|value| value.len() == 6)
                        .map(mac)
                }
                "4" => interface.mtu = item.value.as_u64(),
                "7" => interface.admin_status = item.value.as_i32().map(status),
                "8" => interface.oper_status = item.value.as_i32().map(status),
                _ => {}
            }
        }
        if let Ok(walk) = client.walk(Oid::parse("1.3.6.1.2.1.31.1.1.1").unwrap()) {
            for item in walk.collect().await.unwrap_or_default() {
                let key = item.oid.to_string();
                raw.insert(key.clone(), value_json(&item.value));
                if let Some(("15", index)) = table_cell(&key, "1.3.6.1.2.1.31.1.1.1")
                    && let Some(speed) = item
                        .value
                        .as_u64()
                        .and_then(|value| value.checked_mul(1_000_000))
                    && speed > 0
                    && let Some(interface) = interfaces.get_mut(&index)
                {
                    interface.speed = Some(speed);
                }
            }
        }
        for subtree in [
            "1.3.6.1.2.1.4.20", // IP-MIB address table
            "1.3.6.1.2.1.17",   // BRIDGE-MIB
        ] {
            if let Ok(walk) = client.walk(Oid::parse(subtree).unwrap()) {
                for item in walk.collect().await.unwrap_or_default() {
                    raw.insert(item.oid.to_string(), value_json(&item.value));
                }
            }
        }
        if let Ok(walk) = client.walk(Oid::parse("1.3.6.1.2.1.47.1.1.1.1").unwrap()) {
            for item in walk.collect().await.unwrap_or_default() {
                let key = item.oid.to_string();
                raw.insert(key.clone(), value_json(&item.value));
                let Some((column, _)) = table_cell(&key, "1.3.6.1.2.1.47.1.1.1.1") else {
                    continue;
                };
                let field = match column {
                    "9" => "firmwareVersion",
                    "11" => "serialNumber",
                    "12" => "vendor",
                    "13" => "model",
                    _ => continue,
                };
                if !fields.contains_key(field)
                    && let Some(value) =
                        item.value.as_str().filter(|value| !value.trim().is_empty())
                {
                    fields.insert(field.into(), json!(value));
                }
            }
        }
    }

    let mut neighbors = BTreeMap::<String, Neighbor>::new();
    if selection.lldp {
        for subtree in [
            "1.0.8802.1.1.2.1.5",
            "1.0.8802.1.1.2.1.5.32962",
            "1.0.8802.1.1.2.1.5.4623",
        ] {
            if let Ok(walk) = client.walk(Oid::parse(subtree).unwrap()) {
                for item in walk.collect().await.unwrap_or_default() {
                    raw.insert(item.oid.to_string(), value_json(&item.value));
                }
            }
        }
        let lldp = client
            .walk(Oid::parse("1.0.8802.1.1.2.1.4.1.1").unwrap())
            .map_err(|error| error.to_string())?
            .collect()
            .await
            .unwrap_or_default();
        for item in lldp {
            let key = item.oid.to_string();
            raw.insert(key.clone(), value_json(&item.value));
            let Some((column, index)) = table_cell(&key, "1.0.8802.1.1.2.1.4.1.1") else {
                continue;
            };
            let local_port = index.split('.').nth(1).map(str::to_owned);
            let neighbor = neighbors.entry(index).or_default();
            neighbor.local_port = local_port;
            match column {
                "4" => neighbor.chassis_subtype = item.value.as_i32(),
                "5" => neighbor.chassis_id = item.value.as_bytes().map(<[u8]>::to_vec),
                "7" => neighbor.port = item.value.as_str().map(str::to_owned),
                "9" => neighbor.name = item.value.as_str().map(str::to_owned),
                _ => {}
            }
        }
    }
    let observed_at = crate::now();
    let links = if let Some(local) = local_mac {
        neighbors
            .into_values()
            .filter_map(|neighbor| {
                let remote_mac = neighbor.chassis_mac()?;
                Some(TopologyLink {
                    source: Source::Lldp,
                    observed_at: observed_at.clone(),
                    local: Endpoint {
                        mac_address: local.to_owned(),
                        station_name: None,
                        interface_key: None,
                        port_id: neighbor.local_port,
                        port_mac: None,
                    },
                    remote: Endpoint {
                        mac_address: remote_mac,
                        station_name: neighbor.name,
                        interface_key: None,
                        port_id: neighbor.port,
                        port_mac: None,
                    },
                    raw: json!({ "version": resolved_version(settings) }),
                })
            })
            .collect()
    } else {
        vec![]
    };
    Ok(ResultData {
        observation: selection.inventory.then(|| Observation {
            source: Source::Snmp,
            observed_at,
            ip_address: Some(target.into()),
            mac_address: local_mac.map(str::to_owned),
            fields,
            raw: raw.into(),
            warnings: vec![],
        }),
        interfaces: interfaces.into_values().collect(),
        links,
    })
}

#[derive(Default)]
struct Neighbor {
    local_port: Option<String>,
    chassis_subtype: Option<i32>,
    chassis_id: Option<Vec<u8>>,
    name: Option<String>,
    port: Option<String>,
}

impl Neighbor {
    fn chassis_mac(&self) -> Option<String> {
        (self.chassis_subtype == Some(4)).then_some(mac(self.chassis_id.as_deref()?))
    }
}

fn table_cell<'a>(oid: &'a str, prefix: &str) -> Option<(&'a str, String)> {
    let suffix = oid.strip_prefix(prefix)?.strip_prefix('.')?;
    let (column, index) = suffix.split_once('.')?;
    Some((column, index.to_owned()))
}

fn status(value: i32) -> String {
    match value {
        1 => "up",
        2 => "down",
        3 => "testing",
        _ => "unknown",
    }
    .into()
}

fn reported_os(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    ["windows", "linux", "vxworks", "freebsd", "qnx"]
        .into_iter()
        .find(|name| lower.contains(name))
        .map(|name| match name {
            "windows" => "Windows",
            "linux" => "Linux",
            "vxworks" => "VxWorks",
            "freebsd" => "FreeBSD",
            _ => "QNX",
        })
}
fn mac(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn value_json(value: &Value) -> serde_json::Value {
    if let Some(text) = value.as_str() {
        json!(text)
    } else if let Some(number) = value.as_u64() {
        json!(number)
    } else if let Some(ip) = value.as_ip() {
        json!(ip.to_string())
    } else if let Some(bytes) = value.as_bytes() {
        json!(
            bytes
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>()
        )
    } else {
        json!(format!("{value:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_snmp::message::CommunityMessage;
    use async_snmp::{Oid, Pdu, PduType, VarBind};
    use tokio::net::UdpSocket;

    fn settings(version: &str) -> Settings {
        Settings {
            version: Some(version.into()),
            community: Some("public".into()),
            ..Settings::default()
        }
    }
    #[test]
    fn reads_table_cells() {
        assert_eq!(
            table_cell("1.3.6.1.2.1.2.2.1.6.4", "1.3.6.1.2.1.2.2.1"),
            Some(("6", "4".into()))
        );
    }

    #[test]
    fn recognizes_explicit_operating_system_names() {
        assert_eq!(
            reported_os("Vendor appliance running VxWorks 7"),
            Some("VxWorks")
        );
        assert_eq!(reported_os("Generic managed switch"), None);
    }

    #[test]
    fn only_treats_mac_chassis_ids_as_macs() {
        let neighbor = Neighbor {
            chassis_subtype: Some(4),
            chassis_id: Some(vec![0, 1, 2, 3, 4, 5]),
            ..Neighbor::default()
        };
        assert_eq!(neighbor.chassis_mac().as_deref(), Some("00:01:02:03:04:05"));
        let neighbor = Neighbor {
            chassis_subtype: Some(5),
            ..neighbor
        };
        assert_eq!(neighbor.chassis_mac(), None);
    }

    #[test]
    fn builds_auth_from_inline_settings() {
        assert!(auth(&settings("unsupported")).is_err());

        let v2c = Settings::default();
        assert_eq!(resolved_version(&v2c), "2c");
        assert!(auth(&v2c).is_ok());

        let mut v3 = settings("3");
        v3.community = None;
        assert!(auth(&v3).is_err());
        v3.username = Some("operator".into());
        assert!(auth(&v3).is_ok());
        v3.auth_protocol = Some("invalid".into());
        assert!(auth(&v3).is_err());
        v3.auth_protocol = Some("sha256".into());
        assert!(auth(&v3).is_err());
        v3.auth_password = Some("auth-secret".into());
        v3.privacy_protocol = Some("aes128".into());
        assert!(auth(&v3).is_err());
        v3.privacy_password = Some("privacy-secret".into());
        v3.context_name = Some("lab-context".into());
        assert!(auth(&v3).is_ok());

        for value in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"] {
            assert!(auth_protocol(value).is_ok());
        }
        assert!(auth_protocol("invalid").is_err());
        for value in ["des", "aes128", "aes192", "aes256"] {
            assert!(privacy_protocol(value).is_ok());
        }
        assert!(privacy_protocol("invalid").is_err());
    }

    #[test]
    fn settings_roundtrip_through_json() {
        let value = serde_json::json!({
            "version": "3",
            "username": "inventory",
            "authProtocol": "sha256",
            "authPassword": "secret"
        });
        let parsed: Settings = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(parsed.username.as_deref(), Some("inventory"));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
        assert!(serde_json::from_str::<Settings>(r#"{"unknown":true}"#).is_err());
    }

    #[tokio::test]
    async fn queries_system_interfaces_inventory_and_lldp() {
        let string = |value: &'static str| Value::OctetString(value.into());
        let mut entries = vec![
            ("1.0.8802.1.1.2.1.4.1.1.4.0.7.1", Value::Integer(4)),
            (
                "1.0.8802.1.1.2.1.4.1.1.5.0.7.1",
                Value::OctetString(vec![0, 1, 2, 3, 4, 5].into()),
            ),
            ("1.0.8802.1.1.2.1.4.1.1.7.0.7.1", string("Gi1")),
            ("1.0.8802.1.1.2.1.4.1.1.9.0.7.1", string("peer")),
            ("1.0.8802.1.1.2.1.5.1", Value::IpAddress([192, 0, 2, 1])),
            ("1.3.6.1.2.1.1.1.0", string("Linux industrial controller")),
            (
                "1.3.6.1.2.1.1.2.0",
                Value::ObjectIdentifier(Oid::parse("1.3.6.1.4.1.1").unwrap()),
            ),
            ("1.3.6.1.2.1.1.5.0", string("plc-1")),
            ("1.3.6.1.2.1.1.6.0", string("cabinet-a")),
            ("1.3.6.1.2.1.2.2.1.2.1", string("uplink")),
            ("1.3.6.1.2.1.2.2.1.4.1", Value::Integer(1500)),
            ("1.3.6.1.2.1.2.2.1.5.1", Value::Gauge32(100)),
            (
                "1.3.6.1.2.1.2.2.1.6.1",
                Value::OctetString(vec![6, 7, 8, 9, 10, 11].into()),
            ),
            ("1.3.6.1.2.1.2.2.1.7.1", Value::Integer(1)),
            ("1.3.6.1.2.1.2.2.1.8.1", Value::Integer(2)),
            ("1.3.6.1.2.1.31.1.1.1.15.1", Value::Gauge32(1000)),
            ("1.3.6.1.2.1.47.1.1.1.1.9.1", string("1.2.3")),
            ("1.3.6.1.2.1.47.1.1.1.1.11.1", string("SERIAL")),
            ("1.3.6.1.2.1.47.1.1.1.1.12.1", string("Vendor")),
            ("1.3.6.1.2.1.47.1.1.1.1.13.1", string("Model")),
        ]
        .into_iter()
        .map(|(oid, value)| (Oid::parse(oid).unwrap(), value))
        .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let socket = UdpSocket::bind(("127.0.0.1", SNMP_PORT)).await.unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 65_535];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let message = CommunityMessage::decode(buffer[..length].to_vec().into()).unwrap();
                let request = message.pdu.standard().unwrap();
                let varbinds = request
                    .varbinds
                    .iter()
                    .map(|varbind| {
                        if request.pdu_type == PduType::GetRequest {
                            entries
                                .iter()
                                .find(|(oid, _)| oid == &varbind.oid)
                                .map(|(oid, value)| VarBind::new(oid.clone(), value.clone()))
                                .unwrap_or_else(|| {
                                    VarBind::new(varbind.oid.clone(), Value::NoSuchObject)
                                })
                        } else {
                            entries
                                .iter()
                                .find(|(oid, _)| oid > &varbind.oid)
                                .map(|(oid, value)| VarBind::new(oid.clone(), value.clone()))
                                .unwrap_or_else(|| {
                                    VarBind::new(varbind.oid.clone(), Value::EndOfMibView)
                                })
                        }
                    })
                    .collect();
                let response = CommunityMessage::v2c(
                    message.community,
                    Pdu {
                        pdu_type: PduType::Response,
                        request_id: request.request_id,
                        error_status: 0,
                        error_index: 0,
                        varbinds,
                    },
                )
                .encode();
                socket.send_to(&response, peer).await.unwrap();
            }
        });

        let result = query(
            "127.0.0.1",
            Some("00:11:22:33:44:55"),
            &settings("2c"),
            QuerySelection {
                inventory: true,
                lldp: true,
            },
        )
        .await
        .unwrap();
        let observation = result.observation.unwrap();
        assert_eq!(observation.fields["name"], "plc-1");
        assert_eq!(observation.fields["operatingSystem"], "Linux");
        assert_eq!(result.interfaces[0].speed, Some(1_000_000_000));
        assert_eq!(result.interfaces[0].oper_status.as_deref(), Some("down"));
        assert_eq!(result.links[0].remote.mac_address, "00:01:02:03:04:05");

        let lldp_only = query(
            "127.0.0.1",
            Some("00:11:22:33:44:55"),
            &settings("2c"),
            QuerySelection {
                inventory: false,
                lldp: true,
            },
        )
        .await
        .unwrap();
        assert!(lldp_only.observation.is_none());
        assert!(lldp_only.interfaces.is_empty());
        assert_eq!(lldp_only.links.len(), 1);
        assert_eq!(lldp_only.links[0].raw["version"], "2c");

        task.abort();
    }

    #[test]
    fn converts_status_os_and_snmp_values() {
        assert_eq!(status(1), "up");
        assert_eq!(status(3), "testing");
        assert_eq!(status(99), "unknown");
        for (input, expected) in [
            ("Windows", Some("Windows")),
            ("Linux", Some("Linux")),
            ("FreeBSD", Some("FreeBSD")),
            ("QNX", Some("QNX")),
        ] {
            assert_eq!(reported_os(input), expected);
        }
        assert_eq!(value_json(&Value::Gauge32(7)), json!(7));
        assert_eq!(
            value_json(&Value::IpAddress([192, 0, 2, 1])),
            json!("192.0.2.1")
        );
        assert_eq!(
            value_json(&Value::OctetString(vec![0xaa, 0xbb].into())),
            json!("AABB")
        );
        assert!(value_json(&Value::Null).is_string());
        assert_eq!(table_cell("1.2", "1.2"), None);
    }
}
