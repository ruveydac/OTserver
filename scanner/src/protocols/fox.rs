use super::{Finding, TIMEOUT, port};
use crate::contract::Source;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_native_tls::TlsConnector;

const HELLO: &[u8] = b"fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n";

pub async fn probe(target: Ipv4Addr) -> Result<Option<Finding>, String> {
    let mut findings = Vec::new();
    let mut ports = Vec::new();
    for port_number in [1911, 4911] {
        if let Some((response, tls)) = exchange(target, port_number).await?
            && let Some(values) = parse(&response)
        {
            findings.push((values, tls, response));
            ports.push(port(
                "tcp",
                port_number,
                Source::NiagaraFox,
                json!({ "state": "open", "tls": tls }),
            ));
        }
    }
    let Some((values, tls, response)) = findings.into_iter().next() else {
        return Ok(None);
    };
    let mut fields = BTreeMap::from([("protocols".into(), json!(["niagara-fox"]))]);
    for (source, field) in [
        ("hostName", "name"),
        ("os.name", "operatingSystem"),
        ("brandId", "vendor"),
    ] {
        if let Some(value) = values.get(source) {
            fields.insert(field.into(), value.clone());
        }
    }
    let mut raw = values;
    raw.insert("response".into(), json!(response));
    raw.insert("tls".into(), json!(tls));
    Ok(Some(Finding {
        source: Source::NiagaraFox,
        fields,
        raw: Value::Object(raw),
        ports,
        warnings: vec![],
    }))
}

async fn exchange(target: Ipv4Addr, port: u16) -> Result<Option<(String, bool)>, String> {
    let address = SocketAddr::new(IpAddr::V4(target), port);
    let mut stream = match timeout(TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => return Ok(None),
        Ok(Err(error)) => return Err(format!("Niagara Fox {target}:{port}: {error}")),
        Err(_) => return Ok(None),
    };
    if let Ok(response) = request(&mut stream).await
        && response.starts_with("fox a 0")
    {
        return Ok(Some((response, false)));
    }

    let stream = match timeout(TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        _ => return Ok(None),
    };
    let connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|error| error.to_string())?;
    let mut stream = match timeout(
        TIMEOUT,
        TlsConnector::from(connector).connect(&target.to_string(), stream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        _ => return Ok(None),
    };
    let response = request(&mut stream).await?;
    Ok(response.starts_with("fox a 0").then_some((response, true)))
}

async fn request(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> Result<String, String> {
    timeout(TIMEOUT, stream.write_all(HELLO))
        .await
        .map_err(|_| "Fox write timed out".to_string())?
        .map_err(|error| error.to_string())?;
    let response = timeout(TIMEOUT, async {
        let mut response = Vec::new();
        let mut chunk = [0; 2048];
        loop {
            let length = stream
                .read(&mut chunk)
                .await
                .map_err(|error| error.to_string())?;
            if length == 0 {
                return Err::<Vec<u8>, String>("incomplete Fox response".into());
            }
            response.extend_from_slice(&chunk[..length]);
            if response.len() > 65_536 {
                return Err::<Vec<u8>, String>("oversized Fox response".into());
            }
            if response.windows(3).any(|value| value == b"};;") {
                return Ok(response);
            }
        }
    })
    .await
    .map_err(|_| "Fox response timed out".to_string())??;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

fn parse(response: &str) -> Option<Map<String, Value>> {
    if !response.starts_with("fox a 0") || !response.contains('{') {
        return None;
    }
    let mut values = Map::new();
    for line in response.lines() {
        let Some((key, value)) = line.split_once("=s:") else {
            continue;
        };
        if matches!(
            key,
            "hostName"
                | "hostAddress"
                | "fox.version"
                | "app.name"
                | "app.version"
                | "vm.name"
                | "vm.version"
                | "os.name"
                | "timeZone"
                | "hostId"
                | "vmUuid"
                | "brandId"
                | "fatal"
        ) {
            values.insert(key.into(), json!(value.trim_end_matches(';')));
        }
    }
    (!values.is_empty()).then_some(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parses_fox_identity() {
        let values = parse("fox a 0 -1 fox hello\n{\nhostName=s:station-1\nos.name=s:Windows\nbrandId=s:vykon\n};;\n").unwrap();
        assert_eq!(values["hostName"], "station-1");
        assert_eq!(values["os.name"], "Windows");
    }

    #[tokio::test]
    async fn reads_fragmented_fox_response() {
        let (mut client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut hello = vec![0; HELLO.len()];
            server.read_exact(&mut hello).await.unwrap();
            server.write_all(b"fox a 0\n{\nhost").await.unwrap();
            server.write_all(b"Name=s:plc\n};;\n").await.unwrap();
        });
        assert!(request(&mut client).await.unwrap().ends_with("};;\n"));
    }

    #[tokio::test]
    async fn probes_plain_fox_service() {
        let _network = crate::network_test_lock().await;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 1911))
            .await
            .unwrap();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hello = vec![0; HELLO.len()];
            stream.read_exact(&mut hello).await.unwrap();
            stream
                .write_all(
                    b"fox a 0\n{\nhostName=s:station-1\nos.name=s:Linux\nbrandId=s:Tridium\n};;\n",
                )
                .await
                .unwrap();
        });
        let finding = probe(Ipv4Addr::LOCALHOST).await.unwrap().unwrap();
        assert_eq!(finding.fields["name"], "station-1");
        assert_eq!(finding.ports.len(), 1);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_incomplete_and_oversized_responses() {
        let (mut client, mut server) = tokio::io::duplex(128);
        tokio::spawn(async move {
            let mut hello = vec![0; HELLO.len()];
            server.read_exact(&mut hello).await.unwrap();
        });
        assert!(
            request(&mut client)
                .await
                .unwrap_err()
                .contains("incomplete")
        );

        let (mut client, mut server) = tokio::io::duplex(2048);
        tokio::spawn(async move {
            let mut hello = vec![0; HELLO.len()];
            server.read_exact(&mut hello).await.unwrap();
            let _ = server.write_all(&vec![b'x'; 65_537]).await;
        });
        assert!(
            request(&mut client)
                .await
                .unwrap_err()
                .contains("oversized")
        );
        assert!(parse("invalid").is_none());
        assert!(parse("fox a 0\n{\nignored=i:1\n};;").is_none());
    }
}
