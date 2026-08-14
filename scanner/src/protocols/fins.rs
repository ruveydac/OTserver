use super::{Finding, TIMEOUT, hex, port, text};
use crate::contract::Source;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const UDP_REQUEST: [u8; 13] = [0x80, 0, 2, 0, 0, 0, 0, 0x63, 0, 0xef, 5, 1, 0];
const TCP_ADDRESS_REQUEST: [u8; 20] = [
    b'F', b'I', b'N', b'S', 0, 0, 0, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

pub async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    let (tcp, udp) = tokio::join!(tcp(target), udp(target));
    let mut ports = Vec::new();
    let mut parsed = None;
    for (protocol, offset, result) in [("tcp", 16, tcp), ("udp", 0, udp)] {
        match result {
            Ok(Some(response)) => {
                let value = parse(&response, offset)?;
                parsed.get_or_insert(value);
                ports.push(port(
                    protocol,
                    9600,
                    Source::OmronFins,
                    json!({ "state": "open" }),
                ));
            }
            Ok(None) => {}
            Err(error) => return Err(format!("Omron FINS {target}: {error}")),
        }
    }
    let Some((fields, raw, warnings)) = parsed else {
        return Ok(None);
    };
    Ok(Some(Finding {
        source: Source::OmronFins,
        fields,
        raw,
        ports,
        warnings,
    }))
}

async fn udp(target: Ipv4Addr) -> Result<Option<Vec<u8>>, String> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|error| error.to_string())?;
    socket
        .connect((target, 9600))
        .await
        .map_err(|error| error.to_string())?;
    socket
        .send(&UDP_REQUEST)
        .await
        .map_err(|error| error.to_string())?;
    let mut response = vec![0; 65_535];
    match timeout(TIMEOUT, socket.recv(&mut response)).await {
        Ok(Ok(length)) => {
            response.truncate(length);
            Ok(Some(response))
        }
        Ok(Err(error))
            if matches!(
                error.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
            ) =>
        {
            Ok(None)
        }
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Ok(None),
    }
}

async fn tcp(target: Ipv4Addr) -> Result<Option<Vec<u8>>, String> {
    let mut stream = match timeout(
        TIMEOUT,
        TcpStream::connect(SocketAddr::new(IpAddr::V4(target), 9600)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => return Ok(None),
        Ok(Err(error)) => return Err(error.to_string()),
        Err(_) => return Ok(None),
    };
    write(&mut stream, &TCP_ADDRESS_REQUEST).await?;
    let address_response = read_tcp(&mut stream).await?;
    if address_response.len() != 24
        || &address_response[..4] != b"FINS"
        || address_response[8..12] != [0, 0, 0, 1]
        || address_response[12..16] != [0; 4]
    {
        return Ok(None);
    }
    let address = address_response[23];
    let mut request = vec![
        b'F', b'I', b'N', b'S', 0, 0, 0, 0x15, 0, 0, 0, 2, 0, 0, 0, 0, 0x80, 0, 2, 0,
    ];
    request.extend([address, 0, 0, 0, 0xef, 5, 5, 1, 0]);
    write(&mut stream, &request).await?;
    read_tcp(&mut stream).await.map(Some)
}

async fn write(stream: &mut TcpStream, value: &[u8]) -> Result<(), String> {
    timeout(TIMEOUT, stream.write_all(value))
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|error| error.to_string())
}

async fn read_tcp(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut header = [0; 8];
    timeout(TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    if &header[..4] != b"FINS" {
        return Err("invalid FINS/TCP header".into());
    }
    let length = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    if length > 65_527 {
        return Err("oversized FINS/TCP response".into());
    }
    let mut response = vec![0; 8 + length];
    response[..8].copy_from_slice(&header);
    timeout(TIMEOUT, stream.read_exact(&mut response[8..]))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    Ok(response)
}

type Parsed = (BTreeMap<String, Value>, Value, Vec<String>);

fn parse(response: &[u8], offset: usize) -> Result<Parsed, String> {
    if offset == 16
        && (response.len() < 16
            || &response[..4] != b"FINS"
            || u32::from_be_bytes(response[4..8].try_into().unwrap()) as usize
                != response.len() - 8
            || response[8..12] != [0, 0, 0, 2]
            || response[12..16] != [0; 4])
    {
        return Err("invalid FINS/TCP response".into());
    }
    let expected_sid = if offset == 16 { 5 } else { 0xef };
    if response.len() < 106 + offset
        || response[offset] & 0x40 == 0
        || response[offset + 9] != expected_sid
        || response[offset + 10..offset + 12] != [5, 1]
    {
        return Err("invalid controller response".into());
    }
    let code = u16::from_be_bytes([response[12 + offset], response[13 + offset]]);
    let mut raw = Map::from_iter([
        ("response".into(), json!(hex(response))),
        ("responseCode".into(), json!(format!("{code:04X}"))),
    ]);
    let mut fields = BTreeMap::from([
        ("protocols".into(), json!(["omron-fins"])),
        ("vendor".into(), json!("Omron")),
    ]);
    let mut warnings = Vec::new();
    if code == 0 {
        let model = text(&response[14 + offset..34 + offset]);
        let version = text(&response[34 + offset..54 + offset]);
        if let Some(model) = &model {
            fields.insert("model".into(), json!(model));
            fields.insert("name".into(), json!(model));
        }
        if let Some(version) = &version {
            fields.insert("firmwareVersion".into(), json!(version));
        }
        raw.insert("controllerModel".into(), json!(model));
        raw.insert("controllerVersion".into(), json!(version));
        raw.extend(Map::from_iter([
            (
                "programAreaSize".into(),
                json!(u16::from_be_bytes(
                    response[94 + offset..96 + offset].try_into().unwrap()
                )),
            ),
            ("iomSize".into(), json!(response[96 + offset])),
            (
                "dmWords".into(),
                json!(u16::from_be_bytes(
                    response[97 + offset..99 + offset].try_into().unwrap()
                )),
            ),
            ("timerCounterSize".into(), json!(response[99 + offset])),
            ("expansionDmSize".into(), json!(response[100 + offset])),
            (
                "steps".into(),
                json!(u16::from_be_bytes(
                    response[101 + offset..103 + offset].try_into().unwrap()
                )),
            ),
            ("memoryCardKind".into(), json!(response[103 + offset])),
            (
                "memoryCardSize".into(),
                json!(u16::from_be_bytes(
                    response[104 + offset..106 + offset].try_into().unwrap()
                )),
            ),
        ]));
    } else {
        warnings.push(format!("Controller returned FINS status {code:04X}."));
    }
    Ok((fields, Value::Object(raw), warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn controller_response() -> Vec<u8> {
        let mut response = vec![0; 106];
        response[0] = 0xc0;
        response[9] = 0xef;
        response[10..12].copy_from_slice(&[5, 1]);
        response[14..24].copy_from_slice(b"CJ2M-CPU32");
        response[24] = 0;
        response[34..39].copy_from_slice(b"02.01");
        response
    }

    #[test]
    fn parses_controller_identity() {
        let response = controller_response();
        let (fields, _, _) = parse(&response, 0).unwrap();
        assert_eq!(fields["model"], "CJ2M-CPU32");
        assert_eq!(fields["firmwareVersion"], "02.01");
    }

    #[test]
    fn request_and_response_validation_match_fins() {
        assert_eq!(UDP_REQUEST.last(), Some(&0));
        let mut response = vec![0; 106];
        response[0] = 0xc0;
        response[9] = 0xef;
        response[10..12].copy_from_slice(&[5, 1]);
        response[12..14].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            parse(&response, 0).unwrap().2[0],
            "Controller returned FINS status 0001."
        );
        response[10] = 4;
        assert!(parse(&response, 0).is_err());
    }

    #[tokio::test]
    async fn probes_udp_controller_identity() {
        let _network = crate::network_test_lock().await;
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 9600)).await.unwrap();
        let responder = tokio::spawn(async move {
            let mut request = [0; UDP_REQUEST.len()];
            let (_, peer) = socket.recv_from(&mut request).await.unwrap();
            assert_eq!(request, UDP_REQUEST);
            socket.send_to(&controller_response(), peer).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["model"], "CJ2M-CPU32");
        assert_eq!(finding.ports.len(), 1);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn probes_tcp_controller_identity() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 9600))
            .await
            .unwrap();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; TCP_ADDRESS_REQUEST.len()];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, TCP_ADDRESS_REQUEST);
            let mut address = vec![0; 24];
            address[..4].copy_from_slice(b"FINS");
            address[4..8].copy_from_slice(&16_u32.to_be_bytes());
            address[8..12].copy_from_slice(&1_u32.to_be_bytes());
            address[23] = 1;
            stream.write_all(&address).await.unwrap();

            let mut header = [0; 8];
            stream.read_exact(&mut header).await.unwrap();
            let length = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            let mut response = vec![0; 16];
            response[..4].copy_from_slice(b"FINS");
            response[8..12].copy_from_slice(&2_u32.to_be_bytes());
            let mut controller = controller_response();
            controller[9] = 5;
            response.extend(controller);
            let length = (response.len() - 8) as u32;
            response[4..8].copy_from_slice(&length.to_be_bytes());
            stream.write_all(&response).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["model"], "CJ2M-CPU32");
        assert_eq!(finding.ports.len(), 1);
        responder.await.unwrap();
    }
}
