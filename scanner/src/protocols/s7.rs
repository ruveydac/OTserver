use super::{Finding, TIMEOUT, hex, port, text};
use crate::contract::Source;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// (source, destination) TSAP pairings: connection type PG 0x01xx, OP 0x02xx, S7 basic
// 0x03xx, with destination slot 0/1 for S7-1200/1500, 2 for S7-300, and 3 for S7-400.
const TSAP_PAIRS: [(u16, u16); 12] = [
    (0x0100, 0x0100),
    (0x0100, 0x0101),
    (0x0100, 0x0102),
    (0x0100, 0x0103),
    (0x0200, 0x0200),
    (0x0200, 0x0201),
    (0x0200, 0x0202),
    (0x0200, 0x0203),
    (0x0300, 0x0300),
    (0x0300, 0x0301),
    (0x0300, 0x0302),
    (0x0300, 0x0303),
];
const SETUP: &[u8] = &hex_literal::<25>("0300001902F08032010000000000080000F0000001000101E0");
const SZL_11: &[u8] =
    &hex_literal::<33>("0300002102F080320700000000000800080001120411440100FF09000400110001");
const SZL_1C: &[u8] =
    &hex_literal::<33>("0300002102F080320700000000000800080001120411440100FF090004001C0001");
#[cfg(not(test))]
const CONNECT_PORT: u16 = 102;
#[cfg(test)]
const CONNECT_PORT: u16 = 10_102;

const fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'A'..=b'F' => value - b'A' + 10,
        _ => 0,
    }
}

const fn hex_literal<const N: usize>(value: &str) -> [u8; N] {
    let bytes = value.as_bytes();
    let mut output = [0; N];
    let mut index = 0;
    while index < N {
        output[index] = nibble(bytes[index * 2]) << 4 | nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    output
}

pub async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    // Real CPUs reject a connect request whose TSAP does not match a configured
    // connection (RST, FIN, or silence), so every TSAP pairing gets its own connection.
    for (src_tsap, dst_tsap) in TSAP_PAIRS {
        let request = connect_request(src_tsap, dst_tsap);
        let mut stream = match timeout(
            TIMEOUT,
            TcpStream::connect(SocketAddr::new(IpAddr::V4(target), CONNECT_PORT)),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) if matches!(error.kind(), std::io::ErrorKind::ConnectionRefused) => {
                return Ok(None);
            }
            Ok(Err(error)) => return Err(format!("S7 {target}: {error}")),
            Err(_) => return Ok(None),
        };
        if negotiate(&mut stream, &request).await.unwrap_or(false) {
            return read_identity(stream, target).await;
        }
    }
    Ok(None)
}

fn connect_request(src_tsap: u16, dst_tsap: u16) -> [u8; 22] {
    let mut frame = [
        0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x14, 0x00, 0xc1, 0x02, 0x00, 0x00,
        0xc2, 0x02, 0x00, 0x00, 0xc0, 0x01, 0x0a,
    ];
    frame[13..15].copy_from_slice(&src_tsap.to_be_bytes());
    frame[17..19].copy_from_slice(&dst_tsap.to_be_bytes());
    frame
}

async fn negotiate(stream: &mut TcpStream, request: &[u8]) -> Result<bool, String> {
    write(stream, request).await?;
    let response = read_frame(stream).await?;
    Ok(response.len() >= 7 && response[5] == 0xd0 && response[4] as usize + 5 == response.len())
}

async fn read_identity(mut stream: TcpStream, target: Ipv4Addr) -> Result<Option<Finding>, String> {
    write(&mut stream, SETUP).await?;
    if !setup_response(&read_frame(&mut stream).await?) {
        return Ok(None);
    }
    let hardware = read_szl(&mut stream, SZL_11).await?;
    let identity = read_szl(&mut stream, SZL_1C).await?;
    parse(&hardware, &identity)
        .map(Some)
        .map_err(|error| format!("S7 {target}: {error}"))
}

async fn read_szl(stream: &mut TcpStream, request: &[u8]) -> Result<Vec<u8>, String> {
    write(stream, request).await?;
    let mut output = Vec::new();
    for _ in 0..=255 {
        let frame = read_frame(stream).await?;
        let (payload, last) = userdata(&frame)?;
        if output.len() + payload.len() > 65_535 {
            return Err("oversized S7 SZL response".into());
        }
        output.extend_from_slice(payload);
        if last {
            return Ok(output);
        }
    }
    Err("too many S7 SZL fragments".into())
}

async fn write(stream: &mut TcpStream, value: &[u8]) -> Result<(), String> {
    timeout(TIMEOUT, stream.write_all(value))
        .await
        .map_err(|_| "write timed out".to_string())?
        .map_err(|error| error.to_string())
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut header = [0; 4];
    timeout(TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    let length = u16::from_be_bytes([header[2], header[3]]) as usize;
    if header[0] != 3 || !(4..=65_535).contains(&length) {
        return Err("invalid TPKT header".into());
    }
    let mut frame = vec![0; length];
    frame[..4].copy_from_slice(&header);
    timeout(TIMEOUT, stream.read_exact(&mut frame[4..]))
        .await
        .map_err(|_| "response timed out".to_string())?
        .map_err(|error| error.to_string())?;
    Ok(frame)
}

fn parse(hardware: &[u8], identity: &[u8]) -> Result<Finding, String> {
    let hardware_response = hardware;
    let hardware = szl(hardware, 0x0011)?;
    let identity = szl(identity, 0x001c)?;
    let module = record(&hardware, 1)
        .and_then(|value| value.get(2..22))
        .and_then(text);
    let basic_hardware = record(&hardware, 6)
        .and_then(|value| value.get(2..22))
        .and_then(text);
    let version_record = record(&hardware, 7).ok_or("S7 firmware record is missing")?;
    let version_bytes = version_record
        .get(25..28)
        .ok_or("truncated S7 firmware record")?;
    let version = format!(
        "{}.{}.{}",
        version_bytes[0], version_bytes[1], version_bytes[2]
    );
    let identity_text = |index: u16, length: usize| {
        record(&identity, index)
            .and_then(|value| value.get(2..2 + length))
            .and_then(text)
    };
    let system_name = identity_text(1, 24);
    let module_type = identity_text(2, 24).or_else(|| identity_text(7, 32));
    let plant = identity_text(3, 32);
    let copyright = identity_text(4, 26);
    let serial = identity_text(5, 24);

    let mut fields = BTreeMap::from([
        ("firmwareVersion".into(), json!(version)),
        ("protocols".into(), json!(["s7"])),
        ("vendor".into(), json!("Siemens")),
    ]);
    if let Some(name) = system_name.as_ref() {
        fields.insert("name".into(), json!(name));
    }
    if let Some(model) = module_type
        .as_ref()
        .or(module.as_ref())
        .or(basic_hardware.as_ref())
    {
        fields.insert("model".into(), json!(model));
    }
    if let Some(serial) = &serial {
        fields.insert("serialNumber".into(), json!(serial));
    }
    let raw = Value::Object(Map::from_iter([
        ("basicHardware".into(), json!(basic_hardware)),
        ("copyright".into(), json!(copyright)),
        ("module".into(), json!(module)),
        ("moduleType".into(), json!(module_type)),
        ("plantIdentification".into(), json!(plant)),
        ("response".into(), json!(hex(hardware_response))),
        ("systemName".into(), json!(system_name)),
        ("version".into(), json!(version)),
    ]));
    Ok(Finding {
        source: Source::S7,
        fields,
        ports: vec![port("tcp", 102, Source::S7, json!({ "state": "open" }))],
        raw,
        warnings: vec![],
    })
}

fn record<'a>(records: &[(u16, &'a [u8])], index: u16) -> Option<&'a [u8]> {
    records
        .iter()
        .find(|(value, _)| *value == index)
        .map(|(_, value)| *value)
}

fn setup_response(frame: &[u8]) -> bool {
    let Ok((rosctr, parameter, _, error)) = s7_frame(frame) else {
        return false;
    };
    rosctr == 3 && error == 0 && parameter.first() == Some(&0xf0)
}

fn userdata(frame: &[u8]) -> Result<(&[u8], bool), String> {
    let (rosctr, parameter, data, error) = s7_frame(frame)?;
    if rosctr != 7
        || error != 0
        || parameter.len() < 12
        || parameter[..5] != [0, 1, 0x12, 8, 0x12]
        || parameter[5] >> 6 != 2
        || parameter[5] & 0x3f != 4
        || parameter[6] != 1
        || parameter[10..12] != [0, 0]
        || data.len() < 4
        || data[0] != 0xff
        || data[1] != 9
    {
        return Err("invalid S7 SZL response".into());
    }
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;
    if length != data.len() - 4 {
        return Err("invalid S7 SZL data length".into());
    }
    Ok((&data[4..], parameter[9] == 0))
}

type S7Frame<'a> = (u8, &'a [u8], &'a [u8], u16);

fn s7_frame(frame: &[u8]) -> Result<S7Frame<'_>, String> {
    if frame.len() < 17
        || frame[0] != 3
        || u16::from_be_bytes([frame[2], frame[3]]) as usize != frame.len()
        || frame[4..7] != [2, 0xf0, 0x80]
        || frame[7] != 0x32
    {
        return Err("invalid S7 frame".into());
    }
    let rosctr = frame[8];
    let parameter_length = u16::from_be_bytes([frame[13], frame[14]]) as usize;
    let data_length = u16::from_be_bytes([frame[15], frame[16]]) as usize;
    let header_length = if matches!(rosctr, 2 | 3) { 12 } else { 10 };
    let parameter_start: usize = 7 + header_length;
    let parameter_end = parameter_start
        .checked_add(parameter_length)
        .ok_or("invalid S7 length")?;
    let data_end = parameter_end
        .checked_add(data_length)
        .ok_or("invalid S7 length")?;
    if data_end != frame.len() {
        return Err("invalid S7 payload length".into());
    }
    let error = if header_length == 12 {
        u16::from_be_bytes([frame[17], frame[18]])
    } else {
        0
    };
    Ok((
        rosctr,
        &frame[parameter_start..parameter_end],
        &frame[parameter_end..data_end],
        error,
    ))
}

fn szl(data: &[u8], expected_id: u16) -> Result<Vec<(u16, &[u8])>, String> {
    if data.len() < 8 || u16::from_be_bytes([data[0], data[1]]) != expected_id {
        return Err("unexpected S7 SZL identity".into());
    }
    let record_length = u16::from_be_bytes([data[4], data[5]]) as usize;
    let count = u16::from_be_bytes([data[6], data[7]]) as usize;
    if record_length < 2
        || 8 + record_length
            .checked_mul(count)
            .ok_or("invalid S7 SZL count")?
            != data.len()
    {
        return Err("invalid S7 SZL records".into());
    }
    Ok(data[8..]
        .chunks_exact(record_length)
        .map(|record| (u16::from_be_bytes([record[0], record[1]]), record))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn identities() -> (Vec<u8>, Vec<u8>) {
        let mut hardware = vec![0, 0x11, 0, 1, 0, 28, 0, 3];
        for (index, value) in [(1, "CPU-01"), (6, "6ES7-X"), (7, "Firmware")] {
            let mut record = vec![0; 28];
            record[..2].copy_from_slice(&u16::to_be_bytes(index));
            record[2..2 + value.len()].copy_from_slice(value.as_bytes());
            if index == 7 {
                record[25..28].copy_from_slice(&[3, 2, 1]);
            }
            hardware.extend(record);
        }
        let mut identity = vec![0, 0x1c, 0, 1, 0, 34, 0, 3];
        for (index, value) in [(1, "PLC1"), (2, "S7-1500"), (5, "SERIAL")] {
            let mut record = vec![0; 34];
            record[..2].copy_from_slice(&u16::to_be_bytes(index));
            record[2..2 + value.len()].copy_from_slice(value.as_bytes());
            identity.extend(record);
        }
        (hardware, identity)
    }

    async fn read_tpkt(stream: &mut TcpStream) -> Vec<u8> {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.unwrap();
        let mut frame = vec![0; u16::from_be_bytes([header[2], header[3]]) as usize];
        frame[..4].copy_from_slice(&header);
        stream.read_exact(&mut frame[4..]).await.unwrap();
        frame
    }

    fn setup_frame() -> Vec<u8> {
        vec![
            3, 0, 0, 20, 2, 0xf0, 0x80, 0x32, 3, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xf0,
        ]
    }

    fn userdata_frame(payload: &[u8]) -> Vec<u8> {
        let parameter = [0, 1, 0x12, 8, 0x12, 0x84, 1, 0, 1, 0, 0, 0];
        let data_length = payload.len() + 4;
        let length = 17 + parameter.len() + data_length;
        let mut frame = vec![
            3,
            0,
            0,
            0,
            2,
            0xf0,
            0x80,
            0x32,
            7,
            0,
            0,
            0,
            0,
            0,
            parameter.len() as u8,
            0,
            data_length as u8,
        ];
        frame[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        frame.extend(parameter);
        frame.extend([0xff, 9]);
        frame.extend((payload.len() as u16).to_be_bytes());
        frame.extend(payload);
        frame
    }

    #[test]
    fn parses_s7_identity_fields() {
        let (hardware, identity) = identities();
        let result = parse(&hardware, &identity).unwrap();
        assert_eq!(result.fields["name"], "PLC1");
        assert_eq!(result.fields["serialNumber"], "SERIAL");
    }

    #[test]
    fn builds_connect_request_with_tsaps() {
        let frame = connect_request(0x0100, 0x0102);
        assert_eq!(frame.len(), 22);
        assert_eq!(&frame[..4], &[0x03, 0x00, 0x00, 0x16]);
        assert_eq!(frame[5], 0xe0);
        assert_eq!(&frame[11..15], &[0xc1, 0x02, 0x01, 0x00]);
        assert_eq!(&frame[15..19], &[0xc2, 0x02, 0x01, 0x02]);
        assert_eq!(&frame[19..22], &[0xc0, 0x01, 0x0a]);

        let op = connect_request(0x0200, 0x0203);
        assert_eq!(&op[11..15], &[0xc1, 0x02, 0x02, 0x00]);
        assert_eq!(&op[15..19], &[0xc2, 0x02, 0x02, 0x03]);
    }

    #[test]
    fn tsap_pairs_match_connection_type() {
        assert_eq!(TSAP_PAIRS.len(), 12);
        for (src, dst) in TSAP_PAIRS {
            assert_eq!(src >> 8, dst >> 8, "source and destination type differ");
            assert_eq!(src & 0xff, 0, "source TSAP must be rack/slot zero");
        }
    }

    #[test]
    fn validates_userdata_envelope() {
        let parameter = [0, 1, 0x12, 8, 0x12, 0x84, 1, 0, 1, 0, 0, 0];
        let data = [0xff, 9, 0, 4, 0, 0x11, 0, 1];
        let length = 17 + parameter.len() + data.len();
        let mut frame = vec![
            3,
            0,
            0,
            length as u8,
            2,
            0xf0,
            0x80,
            0x32,
            7,
            0,
            0,
            0,
            0,
            0,
            parameter.len() as u8,
            0,
            data.len() as u8,
        ];
        frame.extend(parameter);
        frame.extend(data);
        assert_eq!(userdata(&frame).unwrap(), (&[0, 0x11, 0, 1][..], true));
        frame[26] = 1;
        assert!(!userdata(&frame).unwrap().1);
        frame[26] = 0;
        let last = frame.len() - 1;
        frame[last] = 2;
        assert!(userdata(&frame).is_ok());
        frame[8] = 3;
        assert!(userdata(&frame).is_err());
    }

    #[tokio::test]
    async fn probes_s7_identity() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, CONNECT_PORT))
            .await
            .unwrap();
        let (hardware, identity) = identities();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&[3, 0, 0, 7, 2, 0xd0, 0]).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&setup_frame()).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&userdata_frame(&hardware)).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&userdata_frame(&identity)).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["name"], "PLC1");
        assert_eq!(finding.fields["model"], "S7-1500");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn retries_next_tsap_when_connect_request_is_rejected() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, CONNECT_PORT))
            .await
            .unwrap();
        let (hardware, identity) = identities();
        let responder = tokio::spawn(async move {
            let (mut rejected, _) = listener.accept().await.unwrap();
            let first = read_tpkt(&mut rejected).await;
            assert_eq!(&first[17..19], &[0x01, 0x00]);
            drop(rejected);
            let (mut stream, _) = listener.accept().await.unwrap();
            let second = read_tpkt(&mut stream).await;
            assert_eq!(&second[17..19], &[0x01, 0x01]);
            stream.write_all(&[3, 0, 0, 7, 2, 0xd0, 0]).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&setup_frame()).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&userdata_frame(&hardware)).await.unwrap();
            read_tpkt(&mut stream).await;
            stream.write_all(&userdata_frame(&identity)).await.unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["name"], "PLC1");
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_invalid_and_truncated_tpkt_frames() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut server, _) = listener.accept().await.unwrap();
            server.write_all(&[2, 0, 0, 4]).await.unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        assert!(read_frame(&mut client).await.unwrap_err().contains("TPKT"));

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { listener.accept().await.unwrap() });
        let mut client = TcpStream::connect(address).await.unwrap();
        assert!(read_frame(&mut client).await.is_err());
        assert!(!setup_response(&[]));
        assert!(szl(&[], 0x11).is_err());
    }
}
