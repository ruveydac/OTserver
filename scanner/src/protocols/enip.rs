use super::{Finding, TIMEOUT, hex, port, text};
use crate::contract::Source;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const LIST_IDENTITY: [u8; 24] = [
    0x63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc1, 0xde, 0xbe, 0xd1, 0, 0, 0, 0,
];

pub async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    let (tcp, udp) = tokio::join!(tcp(target), udp(target));
    let mut responses = Vec::new();
    let mut ports = Vec::new();
    for (protocol, result) in [("tcp", tcp), ("udp", udp)] {
        match result {
            Ok(Some(response)) => {
                responses.push(parse(&response)?);
                ports.push(port(
                    protocol,
                    44818,
                    Source::EthernetIp,
                    json!({ "state": "open" }),
                ));
            }
            Ok(None) => {}
            Err(error) => return Err(format!("EtherNet/IP {target}: {error}")),
        }
    }
    let Some((fields, raw)) = responses.into_iter().next() else {
        return Ok(None);
    };
    Ok(Some(Finding {
        source: Source::EthernetIp,
        fields,
        raw,
        ports,
        warnings: vec![],
    }))
}

async fn tcp(target: Ipv4Addr) -> Result<Option<Vec<u8>>, String> {
    let address = SocketAddr::new(IpAddr::V4(target), 44818);
    let mut stream = match timeout(TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => return Ok(None),
        Ok(Err(error)) => return Err(error.to_string()),
        Err(_) => return Ok(None),
    };
    timeout(TIMEOUT, stream.write_all(&LIST_IDENTITY))
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|error| error.to_string())?;
    let mut header = [0; 24];
    timeout(TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    let length = u16::from_le_bytes([header[2], header[3]]) as usize;
    if length > 65_511 {
        return Err("oversized response".into());
    }
    let mut response = vec![0; 24 + length];
    response[..24].copy_from_slice(&header);
    timeout(TIMEOUT, stream.read_exact(&mut response[24..]))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    Ok(Some(response))
}

async fn udp(target: Ipv4Addr) -> Result<Option<Vec<u8>>, String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| error.to_string())?;
    socket
        .connect((target, 44818))
        .await
        .map_err(|error| error.to_string())?;
    socket
        .send(&LIST_IDENTITY)
        .await
        .map_err(|error| error.to_string())?;
    let mut response = vec![0; 65_535];
    match timeout(TIMEOUT, socket.recv(&mut response)).await {
        Ok(Ok(length)) => {
            response.truncate(length);
            Ok(Some(response))
        }
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => Ok(None),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Ok(None),
    }
}

fn parse(response: &[u8]) -> Result<(BTreeMap<String, Value>, Value), String> {
    if response.len() < 26
        || u16::from_le_bytes([response[0], response[1]]) != 0x63
        || 24 + u16::from_le_bytes([response[2], response[3]]) as usize != response.len()
        || response[8..12] != [0; 4]
        || response[20..24] != [0; 4]
    {
        return Err("invalid List Identity response".into());
    }
    let count = u16::from_le_bytes([response[24], response[25]]) as usize;
    let mut cursor = 26;
    let mut identity = None;
    for _ in 0..count {
        let header = response
            .get(cursor..cursor + 4)
            .ok_or("truncated CPF item")?;
        let item_type = u16::from_le_bytes([header[0], header[1]]);
        let length = u16::from_le_bytes([header[2], header[3]]) as usize;
        cursor += 4;
        let payload = response
            .get(cursor..cursor + length)
            .ok_or("truncated CPF item")?;
        if item_type == 0x000c {
            identity = Some(payload);
        }
        cursor += length;
    }
    if cursor != response.len() {
        return Err("invalid CPF item count".into());
    }
    let identity = identity.ok_or("List Identity item is missing")?;
    if identity.len() < 34 || identity[2..4] != [0, 2] {
        return Err("invalid List Identity item".into());
    }
    let device_ip = Ipv4Addr::new(identity[6], identity[7], identity[8], identity[9]);
    let vendor_id = u16::from_le_bytes([identity[18], identity[19]]);
    let device_type = u16::from_le_bytes([identity[20], identity[21]]);
    let product_code = u16::from_le_bytes([identity[22], identity[23]]);
    let revision = format!("{}.{}", identity[24], identity[25]);
    let status = u16::from_le_bytes([identity[26], identity[27]]);
    let serial = u32::from_le_bytes(identity[28..32].try_into().unwrap());
    let name_length = identity[32] as usize;
    if 34 + name_length > identity.len() {
        return Err("truncated product name".into());
    }
    let product_name = text(&identity[33..33 + name_length]);
    let state = identity[33 + name_length];
    let mut fields = BTreeMap::from([
        ("firmwareVersion".into(), json!(revision)),
        ("protocols".into(), json!(["ethernet-ip"])),
        ("serialNumber".into(), json!(format!("{serial:08X}"))),
    ]);
    if let Some(name) = &product_name {
        fields.insert("model".into(), json!(name));
        fields.insert("name".into(), json!(name));
    }
    if let Some(vendor) = vendor(vendor_id) {
        fields.insert("vendor".into(), json!(vendor));
    }
    let raw = Value::Object(Map::from_iter([
        ("deviceIp".into(), json!(device_ip)),
        ("deviceType".into(), json!(device_type)),
        ("productCode".into(), json!(product_code)),
        ("productName".into(), json!(product_name)),
        ("response".into(), json!(hex(response))),
        ("revision".into(), json!(revision)),
        ("serialNumber".into(), json!(format!("{serial:08X}"))),
        ("state".into(), json!(state)),
        ("status".into(), json!(status)),
        ("vendorId".into(), json!(vendor_id)),
    ]));
    Ok((fields, raw))
}

fn vendor(id: u16) -> Option<&'static str> {
    match id {
        1 => Some("Rockwell Automation/Allen-Bradley"),
        47 => Some("Omron Corporation"),
        108 => Some("Beckhoff Automation GmbH"),
        145 => Some("Siemens"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn identity_response() -> Vec<u8> {
        let mut response = vec![0; 68];
        response[0] = 0x63;
        response[2..4].copy_from_slice(&44_u16.to_le_bytes());
        response[24..26].copy_from_slice(&1_u16.to_le_bytes());
        response[26..28].copy_from_slice(&0x000c_u16.to_le_bytes());
        response[28..30].copy_from_slice(&38_u16.to_le_bytes());
        response[32..34].copy_from_slice(&2_u16.to_be_bytes());
        response[36..40].copy_from_slice(&[192, 0, 2, 1]);
        response[48..50].copy_from_slice(&1_u16.to_le_bytes());
        response[52..54].copy_from_slice(&158_u16.to_le_bytes());
        response[54..56].copy_from_slice(&[3, 7]);
        response[58..62].copy_from_slice(&42_u32.to_le_bytes());
        response[62] = 4;
        response[63..67].copy_from_slice(b"PLC1");
        response
    }

    #[test]
    fn parses_list_identity() {
        let mut response = identity_response();
        let (fields, raw) = parse(&response).unwrap();
        assert_eq!(fields["model"], "PLC1");
        assert_eq!(fields["vendor"], "Rockwell Automation/Allen-Bradley");
        assert_eq!(raw["deviceIp"], "192.0.2.1");
        response[2..4].copy_from_slice(&48_u16.to_le_bytes());
        response[24..26].copy_from_slice(&2_u16.to_le_bytes());
        response.extend([0x34, 0x12, 0, 0]);
        assert!(parse(&response).is_ok());
        response[8] = 1;
        assert!(parse(&response).is_err());
    }

    #[tokio::test]
    async fn probes_tcp_and_udp_identity() {
        let _network = crate::network_test_lock().await;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 44818))
            .await
            .unwrap();
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 44818)).await.unwrap();
        let response = identity_response();
        let tcp_response = response.clone();
        let tcp_task = tokio::spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut request = [0; 24];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, LIST_IDENTITY);
            stream.write_all(&tcp_response).await.unwrap();
        });
        let udp_task = tokio::spawn(async move {
            let mut request = [0; 24];
            let (_, peer) = udp.recv_from(&mut request).await.unwrap();
            assert_eq!(request, LIST_IDENTITY);
            udp.send_to(&response, peer).await.unwrap();
        });

        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["model"], "PLC1");
        assert_eq!(finding.ports.len(), 2);
        tcp_task.await.unwrap();
        udp_task.await.unwrap();
    }
}
