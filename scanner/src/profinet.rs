use crate::contract::{Device, Observation, Source, normalize_mac, object};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;
#[cfg(windows)]
#[path = "profinet_win10pcap.rs"]
mod win10pcap;
#[cfg(target_os = "linux")]
use std::time::Instant;
#[cfg(any(windows, target_os = "linux", test))]
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureInterface {
    pub name: String,
    pub friendly_name: String,
    pub description: String,
    pub addresses: Vec<String>,
}

#[cfg(any(windows, target_os = "linux", test))]
const DCP_MULTICAST: [u8; 6] = [0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00];
const PROFINET_ETHERTYPE: [u8; 2] = [0x88, 0x92];
// Engineering tools must use a value from 0x0002 through 0x1900. A factor of 128 spreads
// device responses over at most 1.27 seconds and gives the requester a three-second response
// window. Never use zero: it is reserved and can make non-conforming devices reply at once.
#[cfg(any(windows, target_os = "linux", test))]
const DCP_RESPONSE_DELAY_FACTOR: u16 = 0x0080;

#[cfg(windows)]
pub fn interfaces() -> Result<Vec<CaptureInterface>, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    let mut size = 0_u32;
    // SAFETY: Initial call to get buffer size.
    unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        );
    }
    if size == 0 {
        return Err("Could not query Windows network adapters.".into());
    }

    let mut buffer = vec![0_u8; size as usize];
    let adapter_addresses = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

    // SAFETY: Buffer is allocated with size returned by GetAdaptersAddresses.
    let status = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            0,
            std::ptr::null_mut(),
            adapter_addresses,
            &mut size,
        )
    };
    if status != 0 {
        return Err(format!(
            "Could not list Windows network interfaces (error code {status})."
        ));
    }

    let mut result = Vec::new();
    let mut current = adapter_addresses;
    while !current.is_null() {
        // SAFETY: current points to valid IP_ADAPTER_ADDRESSES_LH element.
        let adapter = unsafe { &*current };

        // Convert adapter name (GUID string or friendly name)
        let name = unsafe {
            std::ffi::CStr::from_ptr(adapter.AdapterName.cast())
                .to_string_lossy()
                .into_owned()
        };
        let friendly_name = if !adapter.FriendlyName.is_null() {
            let mut len = 0;
            while unsafe { *adapter.FriendlyName.add(len) } != 0 {
                len += 1;
            }
            let slice = unsafe { std::slice::from_raw_parts(adapter.FriendlyName, len) };
            String::from_utf16_lossy(slice)
        } else {
            name.clone()
        };
        let description = if !adapter.Description.is_null() {
            let mut len = 0;
            while unsafe { *adapter.Description.add(len) } != 0 {
                len += 1;
            }
            let slice = unsafe { std::slice::from_raw_parts(adapter.Description, len) };
            String::from_utf16_lossy(slice)
        } else {
            friendly_name.clone()
        };

        let mut addresses = Vec::new();
        if adapter.PhysicalAddressLength == 6 {
            let mac = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                adapter.PhysicalAddress[0],
                adapter.PhysicalAddress[1],
                adapter.PhysicalAddress[2],
                adapter.PhysicalAddress[3],
                adapter.PhysicalAddress[4],
                adapter.PhysicalAddress[5]
            );
            addresses.push(mac);
        }

        let mut unicast = adapter.FirstUnicastAddress;
        while !unicast.is_null() {
            // SAFETY: unicast points to valid IP_ADAPTER_UNICAST_ADDRESS_LH.
            let item = unsafe { &*unicast };
            if !item.Address.lpSockaddr.is_null() {
                let family = unsafe { (*item.Address.lpSockaddr).sa_family as u32 };
                if family == windows_sys::Win32::Networking::WinSock::AF_INET as u32 {
                    let sockaddr = unsafe {
                        &*(item.Address.lpSockaddr
                            as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN)
                    };
                    let s_addr = unsafe { sockaddr.sin_addr.S_un.S_addr };
                    let ip = std::net::Ipv4Addr::from(u32::from_be(s_addr));
                    addresses.push(ip.to_string());
                }
            }
            unicast = item.Next;
        }

        result.push(CaptureInterface {
            name,
            friendly_name,
            description,
            addresses,
        });

        current = adapter.Next;
    }

    Ok(result)
}

#[cfg(target_os = "linux")]
pub fn interfaces() -> Result<Vec<CaptureInterface>, String> {
    let entries = std::fs::read_dir("/sys/class/net")
        .map_err(|error| format!("Could not list Linux network interfaces: {error}"))?;
    let mut interfaces = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let mac = std::fs::read_to_string(entry.path().join("address"))
                .ok()
                .map(|value| value.trim().to_ascii_uppercase())
                .filter(|value| normalize_mac(value).is_some());
            Some(CaptureInterface {
                name: name.clone(),
                friendly_name: name.clone(),
                description: name,
                addresses: mac.into_iter().collect(),
            })
        })
        .collect::<Vec<_>>();
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(interfaces)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn interfaces() -> Result<Vec<CaptureInterface>, String> {
    Err("PROFINET capture is supported on Windows and Linux.".into())
}

#[cfg(windows)]
pub fn scan(interface: &str, source_mac: &str, wait: Duration) -> Result<Vec<Device>, String> {
    let selected = windows_scan_interface(interface)?;
    let source = mac_bytes(source_mac)
        .ok_or_else(|| "A valid source MAC address is required.".to_string())?;
    let xid = new_xid();
    if win10pcap::available() {
        validate_source_mac(&selected, source_mac)?;
        let request = identify_request(source, xid);
        let frames = win10pcap::capture(&selected.name, &request, wait)?;
        return Ok(parse_active_frames(frames, source, xid));
    }
    let mut devices = BTreeMap::new();
    for frame in windows_capture::capture(wait)? {
        if frame.len() < 14 || frame[12..14] != PROFINET_ETHERTYPE || frame[6..12] == source {
            continue;
        }
        if frame.len() >= 22
            && frame[14..16] == [0xfe, 0xff]
            && let Some(device) = parse_response(
                &frame,
                u32::from_be_bytes(frame[18..22].try_into().expect("four-byte slice")),
            )
        {
            devices.insert(device.mac_address.clone(), device);
            continue;
        }
        let mac = hex_mac(&frame[6..12]);
        let Some(mac) = normalize_mac(&mac) else {
            continue;
        };
        let observed_at = crate::now();
        let fields = BTreeMap::from([
            ("lastSeen".into(), json!(observed_at)),
            ("macAddress".into(), json!(mac)),
            ("protocols".into(), json!(["profinet"])),
            ("status".into(), json!("online")),
        ]);
        let observation = Observation {
            source: Source::ProfinetDcp,
            observed_at,
            ip_address: None,
            mac_address: Some(mac.clone()),
            fields,
            raw: json!({ "capture": "pktmon", "etherType": "0x8892", "passive": true }),
            warnings: vec![
                "Observed passive PROFINET traffic; pktmon cannot transmit DCP Identify requests."
                    .into(),
            ],
        };
        devices.entry(mac.clone()).or_insert_with(|| Device {
            mac_address: mac.clone(),
            mac_addresses: vec![mac],
            observations: vec![observation],
            ..Device::default()
        });
    }
    Ok(devices.into_values().collect())
}

#[cfg(windows)]
fn parse_active_frames(frames: Vec<Vec<u8>>, source: [u8; 6], xid: u32) -> Vec<Device> {
    let mut devices = BTreeMap::new();
    for frame in frames {
        if frame.len() >= 14
            && frame[6..12] != source
            && let Some(device) = parse_response(&frame, xid)
        {
            devices.insert(device.mac_address.clone(), device);
        }
    }
    devices.into_values().collect()
}

#[cfg(windows)]
mod windows_capture {
    use std::path::Path;
    use std::process::{Command, Output};
    use std::time::Duration;

    pub fn capture(wait: Duration) -> Result<Vec<Vec<u8>>, String> {
        let id = format!(
            "{}-{}",
            std::process::id(),
            crate::now().replace([':', '.'], "-")
        );
        let base = std::env::temp_dir();
        let etl = base.join(format!("otserver-{id}.etl"));
        let pcap = base.join(format!("otserver-{id}.pcapng"));
        let started = Command::new("pktmon")
            .args(["start", "--capture", "--comp", "nics", "--pkt-size", "0"])
            .arg("--file-name")
            .arg(&etl)
            .args(["--file-size", "32", "--log-mode", "circular"])
            .output()
            .map_err(|error| format!("Could not start pktmon: {error}"))?;
        command_result("Could not start pktmon capture", &started)?;
        std::thread::sleep(wait);
        let stopped = Command::new("pktmon")
            .arg("stop")
            .output()
            .map_err(|error| format!("Could not stop pktmon: {error}"))?;
        command_result("Could not stop pktmon capture", &stopped)?;
        let converted = Command::new("pktmon")
            .arg("etl2pcap")
            .arg(&etl)
            .arg("--out")
            .arg(&pcap)
            .output()
            .map_err(|error| format!("Could not convert pktmon capture: {error}"))?;
        let conversion = command_result("Could not convert pktmon capture", &converted);
        let bytes = conversion.and_then(|()| {
            std::fs::read(&pcap).map_err(|error| format!("Could not read pktmon capture: {error}"))
        });
        remove_capture_file(&etl);
        remove_capture_file(&pcap);
        parse_pcapng(&bytes?)
    }

    fn command_result(context: &str, output: &Output) -> Result<(), String> {
        if output.status.success() {
            return Ok(());
        }
        let detail = String::from_utf8_lossy(if output.stderr.is_empty() {
            &output.stdout
        } else {
            &output.stderr
        });
        Err(format!(
            "{context}: {}. Run OTserver Scanner as Administrator and ensure no other pktmon capture is active.",
            detail.trim()
        ))
    }

    fn remove_capture_file(path: &Path) {
        if let Err(error) = std::fs::remove_file(path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!("warning: could not remove {}: {error}", path.display());
        }
    }

    fn parse_pcapng(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let mut packets = Vec::new();
        let mut offset = 0_usize;
        while offset + 12 <= bytes.len() {
            let block_type = le_u32(&bytes[offset..offset + 4]);
            let length = le_u32(&bytes[offset + 4..offset + 8]) as usize;
            if length < 12
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > bytes.len())
            {
                return Err("pktmon produced a malformed pcapng block.".into());
            }
            if le_u32(&bytes[offset + length - 4..offset + length]) as usize != length {
                return Err("pktmon produced a pcapng block with mismatched lengths.".into());
            }
            if block_type == 6 && length >= 32 {
                let captured = le_u32(&bytes[offset + 20..offset + 24]) as usize;
                let start = offset + 28;
                if start
                    .checked_add(captured)
                    .is_some_and(|end| end <= offset + length - 4)
                {
                    packets.push(bytes[start..start + captured].to_vec());
                }
            } else if block_type == 3 && length >= 16 {
                let original = le_u32(&bytes[offset + 8..offset + 12]) as usize;
                let captured = original.min(length - 16);
                packets.push(bytes[offset + 12..offset + 12 + captured].to_vec());
            }
            offset += length;
        }
        Ok(packets)
    }

    fn le_u32(value: &[u8]) -> u32 {
        u32::from_le_bytes(value.try_into().expect("four-byte slice"))
    }

    #[cfg(test)]
    mod tests {
        use super::parse_pcapng;

        #[test]
        fn reads_enhanced_packet_blocks_and_rejects_bad_lengths() {
            let frame = [1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 0x88, 0x92];
            let mut block = vec![0_u8; 48];
            block[0..4].copy_from_slice(&6_u32.to_le_bytes());
            block[4..8].copy_from_slice(&48_u32.to_le_bytes());
            block[20..24].copy_from_slice(&(frame.len() as u32).to_le_bytes());
            block[24..28].copy_from_slice(&(frame.len() as u32).to_le_bytes());
            block[28..42].copy_from_slice(&frame);
            block[44..48].copy_from_slice(&48_u32.to_le_bytes());
            assert_eq!(parse_pcapng(&block).unwrap(), vec![frame]);

            block[44..48].copy_from_slice(&44_u32.to_le_bytes());
            assert!(parse_pcapng(&block).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub fn scan(interface: &str, source_mac: &str, wait: Duration) -> Result<Vec<Device>, String> {
    use std::ffi::CString;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let source = mac_bytes(source_mac)
        .ok_or_else(|| "A valid source MAC address is required.".to_string())?;
    let xid = new_xid();
    let interface_name = CString::new(interface)
        .map_err(|_| "The Linux interface name contains an invalid null byte.".to_string())?;
    // SAFETY: interface_name is a valid, null-terminated C string for the duration of the call.
    let interface_index = unsafe { libc::if_nametoindex(interface_name.as_ptr()) };
    if interface_index == 0 {
        return Err(format!(
            "Could not find Linux interface {interface}: {}",
            io::Error::last_os_error()
        ));
    }

    let protocol = u16::from_be_bytes(PROFINET_ETHERTYPE).to_be();
    // SAFETY: socket returns a new file descriptor which is immediately owned below.
    let descriptor = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            i32::from(protocol),
        )
    };
    if descriptor < 0 {
        return Err(format!(
            "Could not open the Linux raw socket; run as root or grant CAP_NET_RAW: {}",
            io::Error::last_os_error()
        ));
    }
    // SAFETY: descriptor was returned by socket and has not been transferred elsewhere.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    // SAFETY: sockaddr_ll is a plain C struct and zero is a valid initial state.
    let mut address: libc::sockaddr_ll = unsafe { zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = protocol;
    address.sll_ifindex = interface_index as i32;
    // SAFETY: address points to a fully initialized sockaddr_ll of the supplied size.
    let bound = unsafe {
        libc::bind(
            descriptor.as_raw_fd(),
            (&raw const address).cast(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bound < 0 {
        return Err(format!(
            "Could not bind Linux interface {interface}: {}",
            io::Error::last_os_error()
        ));
    }

    address.sll_halen = DCP_MULTICAST.len() as u8;
    address.sll_addr[..DCP_MULTICAST.len()].copy_from_slice(&DCP_MULTICAST);
    let request = identify_request(source, xid);
    let send_request = || {
        // SAFETY: request and address remain valid for the duration of sendto.
        let sent = unsafe {
            libc::sendto(
                descriptor.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&raw const address).cast(),
                size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if sent == request.len() as isize {
            Ok(())
        } else {
            Err(format!(
                "Could not send complete PROFINET DCP request: {}",
                io::Error::last_os_error()
            ))
        }
    };
    send_request()?;

    let deadline = Instant::now() + wait;
    let mut buffer = [0_u8; 65_536];
    let mut devices = BTreeMap::new();
    while Instant::now() < deadline {
        // SAFETY: buffer is writable for its full reported length and descriptor stays owned.
        let received = unsafe {
            libc::recv(
                descriptor.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };
        if received > 0 {
            if let Some(device) = parse_response(&buffer[..received as usize], xid) {
                devices.insert(device.mac_address.clone(), device);
            }
            continue;
        }
        let error = io::Error::last_os_error();
        if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        return Err(format!("Linux PROFINET capture failed: {error}"));
    }
    Ok(devices.into_values().collect())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn scan(_interface: &str, _source_mac: &str, _wait: Duration) -> Result<Vec<Device>, String> {
    Err("PROFINET capture is supported on Windows and Linux.".into())
}

#[cfg(any(windows, target_os = "linux", test))]
fn identify_request(source: [u8; 6], xid: u32) -> Vec<u8> {
    let mut frame = Vec::with_capacity(64);
    frame.extend(DCP_MULTICAST);
    frame.extend(source);
    frame.extend(PROFINET_ETHERTYPE);
    frame.extend([0xfe, 0xfe, 0x05, 0x00]); // Identify request
    frame.extend(xid.to_be_bytes());
    frame.extend(DCP_RESPONSE_DELAY_FACTOR.to_be_bytes());
    frame.extend([0x00, 0x04, 0xff, 0xff, 0x00, 0x00]); // Identify all
    frame.resize(60, 0);
    frame
}

pub fn parse_response(frame: &[u8], expected_xid: u32) -> Option<Device> {
    if frame.len() < 26
        || frame[12..14] != PROFINET_ETHERTYPE
        || frame[14..16] != [0xfe, 0xff]
        || frame[16] != 0x05
        || frame[17] != 0x01
        || frame[18..22] != expected_xid.to_be_bytes()
        || frame[22..24] != [0, 0]
    {
        return None;
    }
    let mac = normalize_mac(&hex_mac(&frame[6..12]))?;
    let data_length = u16::from_be_bytes([frame[24], frame[25]]) as usize;
    let end = 26_usize.checked_add(data_length)?;
    if data_length == 0 || end > frame.len() {
        return None;
    }
    let mut offset = 26;
    let mut fields = BTreeMap::new();
    let mut raw = BTreeMap::new();
    let mut raw_blocks = Vec::new();
    let mut warnings = Vec::new();
    fields.insert("macAddress".into(), json!(mac));
    fields.insert("status".into(), json!("online"));
    fields.insert("lastSeen".into(), json!(crate::now()));
    fields.insert("protocols".into(), json!(["profinet"]));

    while offset < end {
        if offset + 4 > end {
            return None;
        }
        let option = frame[offset];
        let suboption = frame[offset + 1];
        let length = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]) as usize;
        offset += 4;
        let padded_length = length.checked_add(length % 2)?;
        if offset.checked_add(padded_length)? > end {
            return None;
        }
        let value = &frame[offset..offset + length];
        let has_block_info = matches!(option, 1 | 2 | 3 | 6 | 7);
        if has_block_info && length < 2 {
            return None;
        }
        let block_info = has_block_info.then(|| u16::from_be_bytes([value[0], value[1]]));
        let payload = if has_block_info { &value[2..] } else { value };
        raw_blocks.push(json!({
            "blockInfo": block_info,
            "option": option,
            "suboption": suboption,
            "value": hex(value),
        }));
        match (option, suboption) {
            (1, 1) => {
                if payload.len() < 6 {
                    return None;
                }
                let advertised_mac = normalize_mac(&hex_mac(&payload[..6]))?;
                raw.insert("dcpMacAddress".into(), json!(advertised_mac));
                if advertised_mac != mac {
                    warnings.push(format!(
                        "DCP MAC {advertised_mac} differs from Ethernet source {mac}."
                    ));
                }
            }
            (1, 2) => {
                if payload.len() < 12 {
                    return None;
                }
                fields.insert("ipAddress".into(), json!(ipv4(&payload[0..4])));
                fields.insert("networkMask".into(), json!(ipv4(&payload[4..8])));
                fields.insert("gatewayAddress".into(), json!(ipv4(&payload[8..12])));
                raw.insert("ipBlockInfo".into(), json!(block_info?));
                if block_info? & 0x80 != 0 {
                    warnings.push("DCP reports an IP address conflict.".into());
                }
            }
            (1, 3) => {
                if payload.len() < 28 {
                    return None;
                }
                fields.insert("ipAddress".into(), json!(ipv4(&payload[0..4])));
                fields.insert("networkMask".into(), json!(ipv4(&payload[4..8])));
                fields.insert("gatewayAddress".into(), json!(ipv4(&payload[8..12])));
                raw.insert(
                    "dnsServers".into(),
                    json!([
                        ipv4(&payload[12..16]),
                        ipv4(&payload[16..20]),
                        ipv4(&payload[20..24]),
                        ipv4(&payload[24..28]),
                    ]),
                );
                raw.insert("ipBlockInfo".into(), json!(block_info?));
            }
            (2, 1) => insert_string(&mut fields, "model", payload),
            (2, 2) => {
                insert_string(&mut fields, "name", payload);
            }
            (2, 3) => {
                if payload.len() < 4 {
                    return None;
                }
                raw.insert(
                    "vendorId".into(),
                    json!(u16::from_be_bytes([payload[0], payload[1]])),
                );
                raw.insert(
                    "deviceId".into(),
                    json!(u16::from_be_bytes([payload[2], payload[3]])),
                );
            }
            (2, 4) => {
                if payload.len() < 2 {
                    return None;
                }
                let value = payload[0];
                let roles = [
                    (0x01, "io-device"),
                    (0x02, "io-controller"),
                    (0x04, "io-multidevice"),
                    (0x08, "pn-supervisor"),
                ]
                .into_iter()
                .filter_map(|(mask, label)| (value & mask != 0).then_some(label))
                .collect::<Vec<_>>();
                raw.insert(
                    "deviceRole".into(),
                    json!({ "roles": roles, "value": value }),
                );
            }
            (2, 5) => {
                if payload.len() % 2 != 0 {
                    return None;
                }
                raw.insert(
                    "deviceOptions".into(),
                    json!(
                        payload
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|pair| json!({ "option": pair[0], "suboption": pair[1] }))
                            .collect::<Vec<_>>()
                    ),
                );
            }
            (2, 6) => insert_string(&mut raw, "aliasName", payload),
            (2, 7) => {
                if payload.len() < 2 {
                    return None;
                }
                raw.insert(
                    "deviceInstance".into(),
                    json!(u16::from_be_bytes([payload[0], payload[1]])),
                );
            }
            (2, 8) => {
                if payload.len() < 4 {
                    return None;
                }
                raw.insert(
                    "oemVendorId".into(),
                    json!(u16::from_be_bytes([payload[0], payload[1]])),
                );
                raw.insert(
                    "oemDeviceId".into(),
                    json!(u16::from_be_bytes([payload[2], payload[3]])),
                );
            }
            (2, 10) | (2, 11) => {
                if payload.len() < 2 {
                    return None;
                }
                raw.insert(
                    if suboption == 10 {
                        "rsiProperties"
                    } else {
                        "protocolProperties"
                    }
                    .into(),
                    json!(u16::from_be_bytes([payload[0], payload[1]])),
                );
            }
            (3, 61) => {
                raw.insert("dhcpClientId".into(), json!(hex(payload)));
            }
            (3, 255) => {
                raw.insert("dhcpAddressResolution".into(), json!(hex(payload)));
            }
            (6, 1) => {
                if payload.len() < 2 {
                    return None;
                }
                raw.insert(
                    "deviceInitiative".into(),
                    json!(u16::from_be_bytes([payload[0], payload[1]])),
                );
            }
            (7, 1) => {
                if payload.len() < 16 {
                    return None;
                }
                raw.insert(
                    "configurationDomainUuid".into(),
                    json!(uuid(&payload[..16])),
                );
                insert_string(&mut raw, "configurationDomainName", &payload[16..]);
            }
            (7, 2) => {
                if payload.len() < 2 {
                    return None;
                }
                raw.insert(
                    "nmePriority".into(),
                    json!(u16::from_be_bytes([payload[0], payload[1]])),
                );
            }
            (7, 3) | (7, 4) => {
                if payload.len() < 16 {
                    return None;
                }
                raw.insert(
                    if suboption == 3 {
                        "nmeParameterUuid"
                    } else {
                        "nmeAgentUuid"
                    }
                    .into(),
                    json!(uuid(&payload[..16])),
                );
            }
            (7, 5) => {
                if payload.len() < 6 {
                    return None;
                }
                raw.insert(
                    "cimInterface".into(),
                    json!({
                        "deviceId": u16::from_be_bytes([payload[2], payload[3]]),
                        "instance": u16::from_be_bytes([payload[4], payload[5]]),
                        "vendorId": u16::from_be_bytes([payload[0], payload[1]]),
                    }),
                );
            }
            _ => {}
        }
        offset += padded_length;
    }
    raw.insert("blocks".into(), json!(raw_blocks));
    fields.entry("name".into()).or_insert_with(|| json!(mac));
    let ip = fields
        .get("ipAddress")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(Device {
        mac_address: mac.clone(),
        mac_addresses: vec![mac.clone()],
        ip_addresses: ip.clone().into_iter().collect(),
        observations: vec![Observation {
            source: Source::ProfinetDcp,
            observed_at: crate::now(),
            ip_address: ip,
            mac_address: Some(mac),
            fields,
            raw: object(raw),
            warnings,
        }],
        interfaces: vec![],
        ports: vec![],
    })
}

#[cfg(any(windows, target_os = "linux", test))]
fn new_xid() -> u32 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (elapsed.as_nanos() as u32) ^ std::process::id().rotate_left(16)
}

#[cfg(windows)]
pub fn win10pcap_available() -> bool {
    win10pcap::available()
}

#[cfg(windows)]
pub fn win10pcap_interface_available(interface: &str) -> bool {
    windows_scan_interface(interface)
        .is_ok_and(|selected| win10pcap::interface_available(&selected.name))
}

#[cfg(windows)]
fn windows_scan_interface(interface: &str) -> Result<CaptureInterface, String> {
    let selected = interfaces()?
        .into_iter()
        .find(|item| {
            item.name.eq_ignore_ascii_case(interface)
                || item.friendly_name.eq_ignore_ascii_case(interface)
        })
        .ok_or_else(|| format!("Windows network interface {interface} was not found."))?;
    if is_obsolete_bridge(&selected) {
        return Err(
            "The selected interface is the obsolete Windows Network Bridge left by the previous TAP backend. Remove that bridge, refresh interfaces, and select the physical Ethernet adapter; Win10Pcap does not require a bridge."
                .into(),
        );
    }
    Ok(selected)
}

#[cfg(any(windows, test))]
fn interface_mac(interface: &CaptureInterface) -> Option<String> {
    interface
        .addresses
        .iter()
        .find_map(|address| normalize_mac(address))
}

#[cfg(any(windows, test))]
fn validate_source_mac(interface: &CaptureInterface, source_mac: &str) -> Result<(), String> {
    let actual = interface_mac(interface).ok_or_else(|| {
        format!(
            "Windows did not report a hardware MAC address for interface {}. Active PROFINET DCP was not started.",
            interface.friendly_name
        )
    })?;
    let configured = normalize_mac(source_mac)
        .ok_or_else(|| "A valid source MAC address is required.".to_string())?;
    if configured != actual {
        return Err(format!(
            "Source MAC {configured} does not belong to selected interface {} ({actual}). Active PROFINET DCP was not started because spoofing a source MAC can trigger switch port security and interrupt the network.",
            interface.friendly_name
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn is_obsolete_bridge(interface: &CaptureInterface) -> bool {
    interface
        .description
        .eq_ignore_ascii_case("Microsoft Network Adapter Multiplexor Driver")
        || interface
            .friendly_name
            .eq_ignore_ascii_case("Network Bridge")
}

#[cfg(any(windows, target_os = "linux"))]
fn mac_bytes(value: &str) -> Option<[u8; 6]> {
    let normalized = normalize_mac(value)?;
    let values = normalized
        .split(':')
        .map(|part| u8::from_str_radix(part, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    values.try_into().ok()
}

fn hex_mac(value: &[u8]) -> String {
    value
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02X}")).collect()
}
fn ipv4(value: &[u8]) -> String {
    format!("{}.{}.{}.{}", value[0], value[1], value[2], value[3])
}
fn insert_string(target: &mut BTreeMap<String, Value>, key: &str, value: &[u8]) {
    let value = String::from_utf8_lossy(value)
        .trim_matches(char::from(0))
        .trim()
        .to_string();
    if !value.is_empty() {
        target.insert(key.into(), json!(value));
    }
}
fn uuid(value: &[u8]) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex(&value[0..4]),
        hex(&value[4..6]),
        hex(&value[6..8]),
        hex(&value[8..10]),
        hex(&value[10..16]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_identity_and_ip_blocks() {
        let xid = 0x1234_5678;
        let mut frame = identify_request([0, 1, 2, 3, 4, 5], xid);
        frame[6..12].copy_from_slice(&[0, 17, 34, 51, 68, 85]);
        frame[15] = 0xff;
        frame[17] = 0x01;
        frame[22..24].fill(0);
        let blocks = [
            2, 1, 0, 9, 0, 0, b'E', b'T', b'2', b'0', b'0', b'S', b'P', 0, 2, 2, 0, 5, 0, 0, b'p',
            b'l', b'c', 0, 1, 2, 0, 14, 0, 0, 192, 0, 2, 1, 255, 255, 255, 0, 192, 0, 2, 254,
        ];
        frame[24..26].copy_from_slice(&(blocks.len() as u16).to_be_bytes());
        frame.truncate(26);
        frame.extend(blocks);
        let device = parse_response(&frame, xid).unwrap();
        assert_eq!(device.mac_address, "00:11:22:33:44:55");
        assert_eq!(device.observations[0].fields["ipAddress"], "192.0.2.1");
        assert_eq!(device.observations[0].fields["model"], "ET200SP");
    }

    #[test]
    fn rejects_unrelated_and_malformed_responses() {
        let xid = 0x1234_5678;
        let frame = response(xid, &[2, 2, 0, 5, 0, 0, b'p', b'l', b'c', 0]);
        assert!(parse_response(&frame, xid.wrapping_add(1)).is_none());
        for (offset, value) in [(12, 0), (14, 0), (16, 3), (17, 5), (22, 1)] {
            let mut invalid = frame.clone();
            invalid[offset] = value;
            assert!(parse_response(&invalid, xid).is_none());
        }
        let mut truncated = frame.clone();
        truncated[24..26].copy_from_slice(&100_u16.to_be_bytes());
        assert!(parse_response(&truncated, xid).is_none());
        assert!(parse_response(&response(xid, &[2, 2, 0, 6, 0, 0, b'p']), xid).is_none());
    }

    #[test]
    fn decodes_identify_all_device_metadata() {
        let xid = 9;
        let mut blocks = Vec::new();
        add_block(
            &mut blocks,
            1,
            3,
            &[
                192, 0, 2, 1, 255, 255, 255, 0, 192, 0, 2, 254, 192, 0, 2, 53, 192, 0, 2, 54, 0, 0,
                0, 0, 0, 0, 0, 0,
            ],
        );
        add_block(&mut blocks, 2, 4, &[3, 0]);
        add_block(&mut blocks, 2, 6, b"port-001.plc");
        add_block(&mut blocks, 2, 7, &[0x12, 0x34]);
        add_block(&mut blocks, 2, 8, &[0, 42, 0, 7]);
        add_block(&mut blocks, 2, 10, &[0, 3]);
        add_block(&mut blocks, 2, 11, &[0, 0x21]);

        let observation = &parse_response(&response(xid, &blocks), xid)
            .unwrap()
            .observations[0];
        assert_eq!(observation.fields["ipAddress"], "192.0.2.1");
        assert_eq!(observation.raw["dnsServers"][0], "192.0.2.53");
        assert_eq!(observation.raw["deviceRole"]["roles"][1], "io-controller");
        assert_eq!(observation.raw["aliasName"], "port-001.plc");
        assert_eq!(observation.raw["deviceInstance"], 0x1234);
        assert_eq!(observation.raw["oemVendorId"], 42);
        assert_eq!(observation.raw["rsiProperties"], 3);
        assert_eq!(observation.raw["protocolProperties"], 0x21);
    }

    #[test]
    fn preserves_repeated_blocks_and_reports_ip_conflicts() {
        let xid = 7;
        let blocks = [
            1, 2, 0, 14, 0, 0x81, 192, 0, 2, 1, 255, 255, 255, 0, 192, 0, 2, 254, 0x80, 1, 0, 3,
            0xaa, 0xcc, 0xdd, 0, 0x80, 1, 0, 3, 0xbb, 0xee, 0xff, 0,
        ];
        let device = parse_response(&response(xid, &blocks), xid).unwrap();
        let observation = &device.observations[0];
        assert_eq!(observation.raw["blocks"].as_array().unwrap().len(), 3);
        assert_eq!(
            observation.warnings,
            ["DCP reports an IP address conflict."]
        );
    }

    #[test]
    fn builds_identify_all_request() {
        let request = identify_request([0, 1, 2, 3, 4, 5], 0x1234_5678);
        assert_eq!(
            &request[..30],
            &[
                1, 14, 207, 0, 0, 0, 0, 1, 2, 3, 4, 5, 0x88, 0x92, 0xfe, 0xfe, 5, 0, 0x12, 0x34,
                0x56, 0x78, 0, 0x80, 0, 4, 0xff, 0xff, 0, 0,
            ]
        );
    }

    #[test]
    fn rejects_a_source_mac_that_does_not_belong_to_the_selected_interface() {
        let interface = CaptureInterface {
            name: "{GUID}".into(),
            friendly_name: "Ethernet 2".into(),
            description: "Physical Ethernet".into(),
            addresses: vec!["40:8D:5C:B7:93:F4".into(), "192.0.2.10".into()],
        };
        assert!(validate_source_mac(&interface, "40-8d-5c-b7-93-f4").is_ok());
        let error = validate_source_mac(&interface, "00:11:22:33:44:55").unwrap_err();
        assert!(error.contains("was not started"));
        assert!(error.contains("port security"));

        let mut missing = interface;
        missing.addresses = vec!["192.0.2.10".into()];
        assert!(validate_source_mac(&missing, "00:11:22:33:44:55").is_err());
    }

    #[test]
    fn rejects_obsolete_windows_bridge_interfaces() {
        assert!(is_obsolete_bridge(&CaptureInterface {
            name: "{GUID}".into(),
            friendly_name: "Network Bridge".into(),
            description: "Microsoft Network Adapter Multiplexor Driver".into(),
            addresses: vec![],
        }));
        assert!(!is_obsolete_bridge(&CaptureInterface {
            name: "{GUID}".into(),
            friendly_name: "Ethernet 2".into(),
            description: "Intel(R) Ethernet Connection".into(),
            addresses: vec![],
        }));
    }

    #[test]
    fn decodes_remaining_blocks_and_platform_input_errors() {
        let xid = 11;
        let mut blocks = Vec::new();
        add_block(&mut blocks, 1, 1, &[0, 1, 2, 3, 4, 6]);
        add_block(&mut blocks, 2, 3, &[0, 42, 0, 7]);
        add_block(&mut blocks, 2, 5, &[1, 2, 3, 4]);
        add_block(&mut blocks, 3, 61, &[1, 2]);
        add_block(&mut blocks, 3, 255, &[3, 4]);
        add_block(&mut blocks, 6, 1, &[0, 1]);
        add_block(&mut blocks, 7, 1, &[0; 16]);
        add_block(&mut blocks, 7, 2, &[0, 2]);
        add_block(&mut blocks, 7, 3, &[1; 16]);
        add_block(&mut blocks, 7, 4, &[2; 16]);
        add_block(&mut blocks, 7, 5, &[0, 42, 0, 7, 0, 1]);
        add_block(&mut blocks, 99, 99, &[1]);
        let device = parse_response(&response(xid, &blocks), xid).unwrap();
        let raw = &device.observations[0].raw;
        assert_eq!(raw["vendorId"], 42);
        assert_eq!(raw["deviceOptions"][1]["suboption"], 4);
        assert_eq!(raw["deviceInitiative"], 1);
        assert_eq!(raw["nmePriority"], 2);
        assert!(device.observations[0].warnings[0].contains("differs"));
        assert!(mac_bytes("invalid").is_none());
        assert!(mac_bytes("00-11-22-33-44-55").is_some());
        assert_ne!(new_xid(), 0);
        assert!(
            scan(
                "missing-otserver-interface",
                "00:11:22:33:44:55",
                Duration::ZERO
            )
            .is_err()
        );
        assert!(scan("lo", "invalid", Duration::ZERO).is_err());
        #[cfg(target_os = "linux")]
        {
            let _ = scan("lo", "00:11:22:33:44:55", Duration::ZERO);
        }
    }

    #[test]
    fn rejects_malformed_identify_blocks() {
        let xid = 12;
        assert!(parse_response(&[], xid).is_none());
        let mut empty = response(xid, &[]);
        empty[24..26].fill(0);
        assert!(parse_response(&empty, xid).is_none());
        assert!(parse_response(&response(xid, &[1, 1, 0]), xid).is_none());
        for (option, suboption, payload) in [
            (1, 1, vec![0; 5]),
            (1, 2, vec![0; 11]),
            (1, 3, vec![0; 27]),
            (2, 3, vec![0; 3]),
            (2, 4, vec![]),
            (2, 5, vec![1]),
            (2, 7, vec![0]),
            (2, 8, vec![0; 3]),
            (2, 10, vec![0]),
            (6, 1, vec![0]),
            (7, 1, vec![0; 15]),
            (7, 2, vec![0]),
            (7, 3, vec![0; 15]),
            (7, 5, vec![0; 5]),
        ] {
            let mut blocks = Vec::new();
            add_block(&mut blocks, option, suboption, &payload);
            assert!(parse_response(&response(xid, &blocks), xid).is_none());
        }
    }

    fn response(xid: u32, blocks: &[u8]) -> Vec<u8> {
        let mut frame = identify_request([0, 1, 2, 3, 4, 5], xid);
        frame[6..12].copy_from_slice(&[0, 17, 34, 51, 68, 85]);
        frame[15] = 0xff;
        frame[17] = 1;
        frame[22..24].fill(0);
        frame[24..26].copy_from_slice(&(blocks.len() as u16).to_be_bytes());
        frame.truncate(26);
        frame.extend(blocks);
        frame
    }

    fn add_block(blocks: &mut Vec<u8>, option: u8, suboption: u8, payload: &[u8]) {
        let length = payload.len() + 2;
        blocks.extend([option, suboption]);
        blocks.extend((length as u16).to_be_bytes());
        blocks.extend([0, 0]);
        blocks.extend(payload);
        if !length.is_multiple_of(2) {
            blocks.push(0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lists_linux_interfaces_without_privileges() {
        assert!(!interfaces().unwrap().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn tests_windows_interfaces() {
        let result = interfaces();
        assert!(result.is_ok());
        assert!(scan("invalid-iface", "invalid-mac", Duration::ZERO).is_err());
    }
}
