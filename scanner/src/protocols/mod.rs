use crate::contract::{Observation, Port, Source};
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;

mod bacnet;
mod enip;
mod fins;
mod fox;
mod opcua;
mod s7;

pub use opcua::{DEFAULT_PORTS as OPCUA_DEFAULT_PORTS, ProbeSettings as OpcuaSettings};

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

pub struct ProbeResult {
    pub observations: Vec<Observation>,
    pub ports: Vec<Port>,
    pub warnings: Vec<String>,
    pub outcomes: Vec<(Source, bool)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub s7: bool,
    pub enip: bool,
    pub bacnet: bool,
    pub fins: bool,
    pub fox: bool,
    pub opcua: bool,
}

impl Selection {
    pub fn any(self) -> bool {
        self.s7 || self.enip || self.bacnet || self.fins || self.fox || self.opcua
    }

    pub fn labels(self) -> Vec<&'static str> {
        [
            (self.s7, "S7"),
            (self.enip, "EtherNet/IP"),
            (self.bacnet, "BACnet"),
            (self.fins, "FINS"),
            (self.fox, "Fox"),
            (self.opcua, "OPC UA"),
        ]
        .into_iter()
        .filter_map(|(enabled, label)| enabled.then_some(label))
        .collect()
    }
}

impl Default for Selection {
    fn default() -> Self {
        Self {
            s7: true,
            enip: true,
            bacnet: true,
            fins: true,
            fox: true,
            opcua: true,
        }
    }
}

struct Finding {
    source: Source,
    fields: BTreeMap<String, Value>,
    raw: Value,
    ports: Vec<Port>,
    warnings: Vec<String>,
}

pub async fn scan(
    target: Ipv4Addr,
    mac: &str,
    selection: Selection,
    opcua: &opcua::ProbeSettings,
) -> ProbeResult {
    let (s7, enip, bacnet, fins, fox, ua) = tokio::join!(
        async {
            if selection.s7 {
                s7::probe(target).await
            } else {
                Ok(None)
            }
        },
        async {
            if selection.enip {
                enip::probe(target).await
            } else {
                Ok(None)
            }
        },
        async {
            if selection.bacnet {
                bacnet::probe(target).await
            } else {
                Ok(None)
            }
        },
        async {
            if selection.fins {
                fins::probe(target).await
            } else {
                Ok(None)
            }
        },
        async {
            if selection.fox {
                fox::probe(target).await
            } else {
                Ok(None)
            }
        },
        async {
            if selection.opcua {
                opcua::probe(target, opcua).await
            } else {
                Ok(None)
            }
        },
    );
    let mut observations = Vec::new();
    let mut ports = Vec::new();
    let mut warnings = Vec::new();
    let mut outcomes = Vec::new();
    let results = [
        (selection.s7, Source::S7, s7),
        (selection.enip, Source::EthernetIp, enip),
        (selection.bacnet, Source::Bacnet, bacnet),
        (selection.fins, Source::OmronFins, fins),
        (selection.fox, Source::NiagaraFox, fox),
        (selection.opcua, Source::OpcUa, ua),
    ];
    for (enabled, source, result) in results {
        if !enabled {
            continue;
        }
        outcomes.push((source, matches!(result, Ok(Some(_)))));
        match result {
            Ok(Some(mut finding)) => {
                let observed_at = crate::now();
                finding
                    .fields
                    .insert("ipAddress".into(), serde_json::json!(target));
                finding
                    .fields
                    .insert("lastSeen".into(), serde_json::json!(observed_at));
                finding
                    .fields
                    .insert("macAddress".into(), serde_json::json!(mac));
                finding
                    .fields
                    .entry("status".into())
                    .or_insert_with(|| serde_json::json!("online"));
                ports.append(&mut finding.ports);
                observations.push(Observation {
                    source: finding.source,
                    observed_at,
                    ip_address: Some(target.to_string()),
                    mac_address: Some(mac.to_owned()),
                    fields: finding.fields,
                    raw: finding.raw,
                    warnings: finding.warnings,
                });
            }
            Ok(None) => {}
            Err(error) => warnings.push(error),
        }
    }
    ProbeResult {
        observations,
        ports,
        warnings,
        outcomes,
    }
}

fn port(protocol: &str, number: u16, source: Source, raw: Value) -> Port {
    Port {
        key: format!("{protocol}:{number}"),
        source: source.label().into(),
        interface_key: None,
        port_id: Some(number.to_string()),
        description: Some(source.label().into()),
        mac_address: None,
        vlans: vec![],
        raw,
    }
}

fn text(bytes: &[u8]) -> Option<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value = String::from_utf8_lossy(&bytes[..end]).trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};

    #[tokio::test]
    async fn empty_loopback_scan_is_safe() {
        let _network = crate::network_test_lock().await;
        let result = scan(
            Ipv4Addr::LOCALHOST,
            "00:11:22:33:44:55",
            Selection::default(),
            &opcua::ProbeSettings::default(),
        )
        .await;
        assert!(result.observations.is_empty());
        assert!(result.ports.is_empty());
        assert_eq!(result.outcomes.len(), 6);
        assert!(result.outcomes.iter().all(|(_, success)| !success));
        assert!(text(b"  value\0ignored").as_deref() == Some("value"));
        assert_eq!(text(b" \0"), None);
        assert_eq!(hex(&[0xaa, 0x01]), "AA01");
    }

    #[tokio::test]
    async fn disabled_protocols_do_not_probe() {
        let selection = Selection {
            s7: false,
            enip: false,
            bacnet: false,
            fins: false,
            fox: false,
            opcua: false,
        };
        assert!(!selection.any());
        assert!(selection.labels().is_empty());
        let result = scan(
            Ipv4Addr::LOCALHOST,
            "00:11:22:33:44:55",
            selection,
            &opcua::ProbeSettings::default(),
        )
        .await;
        assert!(result.observations.is_empty());
        assert!(result.ports.is_empty());
        assert!(result.warnings.is_empty());
        assert!(result.outcomes.is_empty());
    }

    #[tokio::test]
    async fn loopback_scan_collects_findings_and_protocol_errors() {
        let _network = crate::network_test_lock().await;
        let fox = TcpListener::bind((Ipv4Addr::LOCALHOST, 1911))
            .await
            .unwrap();
        let fox_task = tokio::spawn(async move {
            let (mut stream, _) = fox.accept().await.unwrap();
            let mut request = [0; 128];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"fox a 0\n{\nhostName=s:station\n};;\n")
                .await
                .unwrap();
        });
        let bacnet = UdpSocket::bind((Ipv4Addr::LOCALHOST, 47808)).await.unwrap();
        let bacnet_task = tokio::spawn(async move {
            let mut request = [0; 17];
            let (_, peer) = bacnet.recv_from(&mut request).await.unwrap();
            bacnet.send_to(&[0; 9], peer).await.unwrap();
        });
        let result = scan(
            Ipv4Addr::LOCALHOST,
            "00:11:22:33:44:55",
            Selection::default(),
            &opcua::ProbeSettings::default(),
        )
        .await;
        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].fields["name"], "station");
        assert_eq!(result.ports.len(), 1);
        let outcomes: std::collections::BTreeMap<Source, bool> =
            result.outcomes.iter().copied().collect();
        assert!(outcomes[&Source::NiagaraFox]);
        assert!(!outcomes[&Source::S7]);
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("BACnet"))
        );
        fox_task.await.unwrap();
        bacnet_task.await.unwrap();
    }
}
