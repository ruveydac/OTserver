use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanExport {
    pub format: String,
    pub schema_version: u8,
    pub scanner: ScannerInfo,
    pub scan: ScanInfo,
    pub devices: Vec<Device>,
    pub links: Vec<TopologyLink>,
    pub unresolved: Vec<Observation>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScannerInfo {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub npcap_version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanInfo {
    pub id: String,
    pub started_at: String,
    pub finished_at: String,
    pub targets: Vec<String>,
    pub interface: InterfaceRef,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceRef {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub mac_address: String,
    #[serde(default)]
    pub mac_addresses: Vec<String>,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    #[serde(default)]
    pub observations: Vec<Observation>,
    #[serde(default)]
    pub interfaces: Vec<NetworkInterface>,
    #[serde(default)]
    pub ports: Vec<Port>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub source: Source,
    pub observed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
    #[serde(default)]
    pub raw: Value,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    Arp,
    Bacnet,
    EthernetIp,
    Lldp,
    NiagaraFox,
    OmronFins,
    OsFingerprint,
    ProfinetDcp,
    S7,
    Snmp,
    Unknown,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::Bacnet => "bacnet",
            Self::EthernetIp => "ethernet-ip",
            Self::Lldp => "lldp",
            Self::NiagaraFox => "niagara-fox",
            Self::OmronFins => "omron-fins",
            Self::OsFingerprint => "os-fingerprint",
            Self::ProfinetDcp => "profinet-dcp",
            Self::S7 => "s7",
            Self::Snmp => "snmp",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterface {
    pub key: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oper_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u64>,
    #[serde(default)]
    pub raw: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Port {
    pub key: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub vlans: Vec<u16>,
    #[serde(default)]
    pub raw: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TopologyLink {
    pub source: Source,
    pub observed_at: String,
    pub local: Endpoint,
    pub remote: Endpoint,
    #[serde(default)]
    pub raw: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub mac_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub station_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_mac: Option<String>,
}

pub fn normalize_mac(value: &str) -> Option<String> {
    let hex: String = value
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .collect();
    if hex.len() != 12 {
        return None;
    }
    Some(
        hex.as_bytes()
            .chunks(2)
            .map(|part| std::str::from_utf8(part).unwrap().to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

pub fn merge_devices(devices: Vec<Device>) -> Vec<Device> {
    let mut merged = BTreeMap::<String, Device>::new();
    for mut device in devices {
        let Some(mac) = normalize_mac(&device.mac_address) else {
            continue;
        };
        device.mac_address = mac.clone();
        let target = merged.entry(mac.clone()).or_insert_with(|| Device {
            mac_address: mac.clone(),
            mac_addresses: vec![mac],
            ..Device::default()
        });
        target.mac_addresses.append(&mut device.mac_addresses);
        target.ip_addresses.append(&mut device.ip_addresses);
        target.observations.append(&mut device.observations);
        target.interfaces.append(&mut device.interfaces);
        target.ports.append(&mut device.ports);
    }
    for device in merged.values_mut() {
        device.mac_addresses = device
            .mac_addresses
            .iter()
            .filter_map(|value| normalize_mac(value))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        device.ip_addresses.sort();
        device.ip_addresses.dedup();
    }
    merged.into_values().collect()
}

pub fn validate(scan: &ScanExport) -> Result<(), String> {
    if scan.format != "otserver-scan" || scan.schema_version != 2 {
        return Err("Unsupported scanner file. Expected otserver-scan schemaVersion 2.".into());
    }
    if scan.scan.targets.is_empty() {
        return Err("At least one scan target is required.".into());
    }
    let mut identities = BTreeSet::new();
    for device in &scan.devices {
        let Some(mac) = normalize_mac(&device.mac_address) else {
            return Err(format!(
                "Invalid device MAC address: {}",
                device.mac_address
            ));
        };
        if mac != device.mac_address || !identities.insert(mac) {
            return Err(format!(
                "Duplicate or non-normalized device MAC: {}",
                device.mac_address
            ));
        }
        if device.observations.is_empty() {
            return Err(format!(
                "Device {} has no observations.",
                device.mac_address
            ));
        }
    }
    let value = serde_json::to_value(scan).map_err(|error| error.to_string())?;
    reject_secrets(&value, "")
}

fn reject_secrets(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let lower = key.to_ascii_lowercase();
                if ["community", "password", "secret"]
                    .iter()
                    .any(|needle| lower.contains(needle))
                {
                    return Err(format!(
                        "Export contains a secret-like field at {path}/{key}."
                    ));
                }
                reject_secrets(value, &format!("{path}/{key}"))?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_secrets(value, &format!("{path}/{index}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn object(entries: impl IntoIterator<Item = (String, Value)>) -> Value {
    Value::Object(Map::from_iter(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn observation() -> Observation {
        Observation {
            source: Source::Arp,
            observed_at: "2026-08-11T00:00:00Z".into(),
            ip_address: None,
            mac_address: None,
            fields: BTreeMap::new(),
            raw: Value::Null,
            warnings: vec![],
        }
    }

    fn export(devices: Vec<Device>) -> ScanExport {
        ScanExport {
            format: "otserver-scan".into(),
            schema_version: 2,
            scanner: ScannerInfo {
                name: "OTserver Scanner".into(),
                version: "0.2.0".into(),
                npcap_version: None,
            },
            scan: ScanInfo {
                id: "scan-1".into(),
                started_at: "2026-08-11T00:00:00Z".into(),
                finished_at: "2026-08-11T00:01:00Z".into(),
                targets: vec!["192.0.2.0/24".into()],
                interface: InterfaceRef {
                    id: "test".into(),
                    name: "test".into(),
                    mac_address: None,
                    addresses: vec![],
                },
                partial: false,
            },
            devices,
            links: vec![],
            unresolved: vec![],
            warnings: vec![],
            errors: vec![],
        }
    }

    #[test]
    fn normalizes_and_merges_only_by_mac() {
        assert_eq!(
            normalize_mac("00-1a-2b-3c-4d-5e").as_deref(),
            Some("00:1A:2B:3C:4D:5E")
        );
        assert!(normalize_mac("192.0.2.1").is_none());
        let devices = merge_devices(vec![
            Device {
                mac_address: "00-1a-2b-3c-4d-5e".into(),
                ip_addresses: vec!["192.0.2.1".into()],
                ..Device::default()
            },
            Device {
                mac_address: "00:1A:2B:3C:4D:5E".into(),
                ip_addresses: vec!["192.0.2.2".into()],
                ..Device::default()
            },
        ]);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].ip_addresses.len(), 2);
    }

    #[test]
    fn validates_contract_and_rejects_secret_material() {
        let valid_device = || Device {
            mac_address: "00:1A:2B:3C:4D:5E".into(),
            observations: vec![observation()],
            ..Device::default()
        };
        assert!(validate(&export(vec![valid_device()])).is_ok());

        let mut invalid = export(vec![valid_device()]);
        invalid.format = "other".into();
        assert!(validate(&invalid).unwrap_err().contains("schemaVersion"));
        invalid = export(vec![valid_device()]);
        invalid.scan.targets.clear();
        assert!(validate(&invalid).unwrap_err().contains("target"));
        invalid = export(vec![Device {
            mac_address: "invalid".into(),
            observations: vec![observation()],
            ..Device::default()
        }]);
        assert!(
            validate(&invalid)
                .unwrap_err()
                .contains("Invalid device MAC")
        );
        invalid = export(vec![Device {
            mac_address: "00-1A-2B-3C-4D-5E".into(),
            observations: vec![observation()],
            ..Device::default()
        }]);
        assert!(validate(&invalid).unwrap_err().contains("non-normalized"));
        invalid = export(vec![valid_device(), valid_device()]);
        assert!(validate(&invalid).unwrap_err().contains("Duplicate"));
        invalid = export(vec![Device {
            mac_address: "00:1A:2B:3C:4D:5E".into(),
            ..Device::default()
        }]);
        assert!(validate(&invalid).unwrap_err().contains("no observations"));

        assert!(reject_secrets(&json!({ "nested": [{ "password": "secret" }] }), "").is_err());
        assert!(reject_secrets(&json!([1, "safe"]), "").is_ok());
        assert_eq!(object([("value".into(), json!(1))])["value"], 1);
    }

    #[test]
    fn labels_all_sources_and_discards_invalid_merge_identities() {
        let labels = [
            Source::Arp,
            Source::Bacnet,
            Source::EthernetIp,
            Source::Lldp,
            Source::NiagaraFox,
            Source::OmronFins,
            Source::OsFingerprint,
            Source::ProfinetDcp,
            Source::S7,
            Source::Snmp,
            Source::Unknown,
        ]
        .map(Source::label);
        assert_eq!(labels[0], "arp");
        assert_eq!(labels[10], "unknown");
        let devices = merge_devices(vec![
            Device {
                mac_address: "invalid".into(),
                ..Device::default()
            },
            Device {
                mac_address: "00:1A:2B:3C:4D:5E".into(),
                mac_addresses: vec!["invalid".into(), "00-1a-2b-3c-4d-5e".into()],
                ip_addresses: vec!["192.0.2.1".into(), "192.0.2.1".into()],
                ..Device::default()
            },
        ]);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mac_addresses, ["00:1A:2B:3C:4D:5E"]);
        assert_eq!(devices[0].ip_addresses, ["192.0.2.1"]);
    }
}
