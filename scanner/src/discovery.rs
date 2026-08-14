use crate::contract::{Device, Observation, Source, normalize_mac};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::Duration;
#[cfg(any(target_os = "linux", test))]
use std::time::Instant;

#[cfg(any(target_os = "linux", test))]
const ARP_ETHERTYPE: [u8; 2] = [0x08, 0x06];
const BROADCAST: [u8; 6] = [0xff; 6];
const MAX_TARGETS: usize = 65_536;

#[derive(Clone, Copy)]
struct Fingerprint {
    ttl: u8,
    dont_fragment: bool,
}

type DiscoveryResults = BTreeMap<Ipv4Addr, ([u8; 6], Option<Fingerprint>)>;

pub fn expand_targets(values: &[String]) -> Result<Vec<Ipv4Addr>, String> {
    let mut targets = BTreeSet::new();
    for value in values {
        if let Some((address, prefix)) = value.split_once('/') {
            let address = address
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("Only IPv4 targets are supported: {value}"))?;
            let prefix = prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= 32)
                .ok_or_else(|| format!("Invalid IPv4 CIDR prefix: {value}"))?;
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = u32::from(address) & mask;
            let count = 1_u64 << (32 - prefix);
            if count > MAX_TARGETS as u64 || targets.len() + count as usize > MAX_TARGETS {
                return Err(format!(
                    "The scan contains more than {MAX_TARGETS} IPv4 addresses. Split it into smaller scans."
                ));
            }
            let skip_edges = prefix < 31;
            for offset in 0..count {
                if skip_edges && (offset == 0 || offset + 1 == count) {
                    continue;
                }
                targets.insert(Ipv4Addr::from(network.wrapping_add(offset as u32)));
            }
        } else {
            targets.insert(
                value
                    .parse::<Ipv4Addr>()
                    .map_err(|_| format!("Only IPv4 targets are supported: {value}"))?,
            );
        }
        if targets.len() > MAX_TARGETS {
            return Err(format!(
                "The scan contains more than {MAX_TARGETS} IPv4 addresses. Split it into smaller scans."
            ));
        }
    }
    Ok(targets.into_iter().collect())
}

pub fn scan(
    interface: &str,
    source_mac: &str,
    targets: &[Ipv4Addr],
    wait: Duration,
) -> Result<Vec<Device>, String> {
    let source_mac = mac_bytes(source_mac)
        .ok_or_else(|| "A valid source MAC address is required.".to_string())?;
    let source_ip = source_ipv4(interface)?;
    let replies = platform_scan(interface, source_mac, source_ip, targets, wait)?;
    Ok(replies
        .into_iter()
        .map(|(ip, (mac, fingerprint))| device(ip, mac, fingerprint))
        .collect())
}

fn device(ip: Ipv4Addr, mac: [u8; 6], fingerprint: Option<Fingerprint>) -> Device {
    let mac = format_mac(mac);
    let observed_at = crate::now();
    let mut fields = BTreeMap::from([
        ("ipAddress".into(), json!(ip)),
        ("lastSeen".into(), json!(observed_at)),
        ("macAddress".into(), json!(mac)),
        ("name".into(), json!(ip)),
        ("status".into(), json!("online")),
    ]);
    let vendor = oui_data::lookup(&mac).map(|entry| entry.organization());
    if let Some(vendor) = vendor {
        fields.insert("vendor".into(), json!(vendor));
    }
    let mut observations = vec![Observation {
        source: Source::Arp,
        observed_at: observed_at.clone(),
        ip_address: Some(ip.to_string()),
        mac_address: Some(mac.clone()),
        fields,
        raw: vendor.map_or(Value::Null, |vendor| json!({ "ouiVendor": vendor })),
        warnings: vec![],
    }];
    if let Some(fingerprint) = fingerprint {
        let mut fields = BTreeMap::from([("macAddress".into(), json!(mac))]);
        if let Some(os) = classify(fingerprint) {
            fields.insert("operatingSystem".into(), json!(os));
            fields.insert("osAccuracy".into(), json!(60));
        }
        observations.push(Observation {
            source: Source::OsFingerprint,
            observed_at,
            ip_address: Some(ip.to_string()),
            mac_address: Some(mac.clone()),
            fields,
            raw: json!({ "dontFragment": fingerprint.dont_fragment, "ttl": fingerprint.ttl }),
            warnings: vec![],
        });
    }
    Device {
        mac_address: mac.clone(),
        mac_addresses: vec![mac.clone()],
        ip_addresses: vec![ip.to_string()],
        observations,
        ..Device::default()
    }
}

// ponytail: intentionally broad families; replace with a maintained fingerprint database only if
// lab measurements prove this bounded heuristic is too coarse.
fn classify(fingerprint: Fingerprint) -> Option<&'static str> {
    match (fingerprint.ttl, fingerprint.dont_fragment) {
        (65..=128, true) => Some("Windows family"),
        (1..=64, true) => Some("Linux/Unix family"),
        (129..=u8::MAX, false) => Some("Network/embedded family"),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", test))]
fn request(source_mac: [u8; 6], source_ip: Ipv4Addr, target: Ipv4Addr) -> [u8; 42] {
    let mut frame = [0_u8; 42];
    frame[..6].copy_from_slice(&BROADCAST);
    frame[6..12].copy_from_slice(&source_mac);
    frame[12..14].copy_from_slice(&ARP_ETHERTYPE);
    frame[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    frame[22..28].copy_from_slice(&source_mac);
    frame[28..32].copy_from_slice(&source_ip.octets());
    frame[38..42].copy_from_slice(&target.octets());
    frame
}

#[cfg(any(target_os = "linux", test))]
fn reply(
    frame: &[u8],
    targets: &BTreeSet<Ipv4Addr>,
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
) -> Option<(Ipv4Addr, [u8; 6])> {
    if frame.len() < 42
        || frame[12..14] != ARP_ETHERTYPE
        || frame[14..22] != [0, 1, 8, 0, 6, 4, 0, 2]
        || (frame[..6] != source_mac && frame[..6] != BROADCAST)
        || frame[32..38] != source_mac
        || frame[38..42] != source_ip.octets()
        || frame[6..12] != frame[22..28]
    {
        return None;
    }
    let ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    if !targets.contains(&ip) {
        return None;
    }
    let mac: [u8; 6] = frame[22..28].try_into().ok()?;
    (mac != [0; 6] && mac != BROADCAST).then_some((ip, mac))
}

#[cfg(windows)]
fn source_ipv4(interface: &str) -> Result<Ipv4Addr, String> {
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
        return Err(format!(
            "Could not inspect Windows interfaces for {interface}."
        ));
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
            "Could not inspect Windows interfaces (error code {status})."
        ));
    }

    let mut current = adapter_addresses;
    while !current.is_null() {
        // SAFETY: current points to valid IP_ADAPTER_ADDRESSES_LH element.
        let adapter = unsafe { &*current };
        let name =
            unsafe { std::ffi::CStr::from_ptr(adapter.AdapterName.cast()).to_string_lossy() };
        let friendly_name = if !adapter.FriendlyName.is_null() {
            let mut len = 0;
            while unsafe { *adapter.FriendlyName.add(len) } != 0 {
                len += 1;
            }
            let slice = unsafe { std::slice::from_raw_parts(adapter.FriendlyName, len) };
            String::from_utf16_lossy(slice)
        } else {
            String::new()
        };

        if name == interface || friendly_name == interface {
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
                        return Ok(Ipv4Addr::from(u32::from_be(s_addr)));
                    }
                }
                unicast = item.Next;
            }
        }
        current = adapter.Next;
    }

    Err(format!("Interface {interface} has no IPv4 address."))
}

#[cfg(target_os = "linux")]
fn source_ipv4(interface: &str) -> Result<Ipv4Addr, String> {
    use std::ffi::{CStr, CString};
    use std::ptr;

    let wanted = CString::new(interface)
        .map_err(|_| "The interface name contains an invalid null byte.".to_string())?;
    let mut addresses = ptr::null_mut();
    // SAFETY: getifaddrs initializes addresses on success and freeifaddrs releases the list once.
    if unsafe { libc::getifaddrs(&mut addresses) } != 0 {
        return Err(format!(
            "Could not inspect Linux interfaces: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut current = addresses;
    let mut result = None;
    while !current.is_null() {
        // SAFETY: current traverses the valid list returned by getifaddrs.
        let item = unsafe { &*current };
        if !item.ifa_addr.is_null()
            && unsafe { CStr::from_ptr(item.ifa_name) }.to_bytes() == wanted.as_bytes()
            && unsafe { (*item.ifa_addr).sa_family as i32 } == libc::AF_INET
        {
            // SAFETY: AF_INET guarantees that ifa_addr points to sockaddr_in.
            let address = unsafe { &*(item.ifa_addr.cast::<libc::sockaddr_in>()) };
            result = Some(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)));
            break;
        }
        current = item.ifa_next;
    }
    // SAFETY: addresses is the list returned by getifaddrs.
    unsafe { libc::freeifaddrs(addresses) };
    result.ok_or_else(|| format!("Interface {interface} has no IPv4 address."))
}

#[cfg(not(any(windows, target_os = "linux")))]
fn source_ipv4(_interface: &str) -> Result<Ipv4Addr, String> {
    Err("Native discovery is supported on Windows and Linux.".into())
}

#[cfg(windows)]
fn platform_scan(
    _interface: &str,
    _source_mac: [u8; 6],
    source_ip: Ipv4Addr,
    targets: &[Ipv4Addr],
    _wait: Duration,
) -> Result<DiscoveryResults, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::SendARP;

    // pktmon is a capture-only facility. Use the supported IP Helper API to cause Windows to
    // transmit each ARP request on the adapter owning source_ip and return the resolved MAC.
    // SendARP expects IPAddr values in the same byte layout as inet_addr/SOCKADDR_IN.
    let source = u32::from_ne_bytes(source_ip.octets());
    let mut replies = BTreeMap::new();
    for batch in targets.chunks(32) {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            for target in batch.iter().copied() {
                let sender = sender.clone();
                scope.spawn(move || {
                    let destination = u32::from_ne_bytes(target.octets());
                    let mut mac = [0_u8; 8];
                    let mut length = mac.len() as u32;
                    // SAFETY: mac is writable for length bytes and length remains valid for the call.
                    let status = unsafe {
                        SendARP(destination, source, mac.as_mut_ptr().cast(), &mut length)
                    };
                    if status == 0 && length >= 6 {
                        let value: [u8; 6] = mac[..6].try_into().expect("six-byte slice");
                        if value != [0; 6] && value != BROADCAST {
                            let _ = sender.send((target, value));
                        }
                    }
                });
            }
        });
        drop(sender);
        for (target, mac) in receiver {
            replies.insert(target, (mac, None));
        }
    }
    Ok(replies)
}

#[cfg(target_os = "linux")]
fn platform_scan(
    interface: &str,
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
    targets: &[Ipv4Addr],
    wait: Duration,
) -> Result<DiscoveryResults, String> {
    use std::ffi::CString;
    use std::mem::{size_of, zeroed};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let name = CString::new(interface)
        .map_err(|_| "The interface name contains an invalid null byte.".to_string())?;
    // SAFETY: name is a valid C string for this call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(format!("Could not find Linux interface {interface}."));
    }
    let protocol = 3_u16.to_be();
    // SAFETY: socket returns a new descriptor, owned immediately below.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            i32::from(protocol),
        )
    };
    if fd < 0 {
        return Err(format!(
            "Could not open the Linux raw socket; run as root or grant CAP_NET_RAW: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fd is newly returned and not owned elsewhere.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: zero is a valid starting state for sockaddr_ll.
    let mut address: libc::sockaddr_ll = unsafe { zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_protocol = protocol;
    address.sll_ifindex = index as i32;
    address.sll_halen = 6;
    address.sll_addr[..6].copy_from_slice(&BROADCAST);
    let mut send = |frame: &[u8], destination: [u8; 6]| -> Result<(), String> {
        address.sll_addr[..6].copy_from_slice(&destination);
        // SAFETY: pointers and lengths refer to live values for the duration of sendto.
        let sent = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                frame.as_ptr().cast(),
                frame.len(),
                0,
                (&raw const address).cast(),
                size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if sent == frame.len() as isize {
            Ok(())
        } else {
            Err(format!(
                "Could not send complete discovery request: {}",
                std::io::Error::last_os_error()
            ))
        }
    };
    for target in targets {
        let frame = request(source_mac, source_ip, *target);
        send(&frame, BROADCAST)?;
    }
    let mut buffer = [0_u8; 2048];
    let replies = collect_replies(targets, source_mac, source_ip, wait, || {
        // SAFETY: buffer is writable and fd remains owned.
        let received =
            unsafe { libc::recv(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
        if received > 0 {
            Ok(Some(buffer[..received as usize].to_vec()))
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::WouldBlock {
                std::thread::sleep(Duration::from_millis(10));
                Ok(None)
            } else {
                Err(format!("ARP capture failed: {error}"))
            }
        }
    })?;
    for (ip, mac) in &replies {
        send(&icmp_request(source_mac, source_ip, *mac, *ip), *mac)?;
    }
    let fingerprints = collect_fingerprints(
        &replies,
        source_mac,
        source_ip,
        Duration::from_secs(2),
        || {
            // SAFETY: buffer is writable and fd remains owned.
            let received =
                unsafe { libc::recv(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) };
            if received > 0 {
                Ok(Some(buffer[..received as usize].to_vec()))
            } else if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
                std::thread::sleep(Duration::from_millis(10));
                Ok(None)
            } else {
                Err(format!(
                    "OS fingerprint capture failed: {}",
                    std::io::Error::last_os_error()
                ))
            }
        },
    )?;
    Ok(replies
        .into_iter()
        .map(|(ip, mac)| (ip, (mac, fingerprints.get(&ip).copied())))
        .collect())
}

#[cfg(not(any(windows, target_os = "linux")))]
fn platform_scan(
    _interface: &str,
    _source_mac: [u8; 6],
    _source_ip: Ipv4Addr,
    _targets: &[Ipv4Addr],
    _wait: Duration,
) -> Result<DiscoveryResults, String> {
    Err("Native discovery is supported on Windows and Linux.".into())
}

#[cfg(any(target_os = "linux", test))]
fn collect_replies(
    targets: &[Ipv4Addr],
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
    wait: Duration,
    mut receive: impl FnMut() -> Result<Option<Vec<u8>>, String>,
) -> Result<BTreeMap<Ipv4Addr, [u8; 6]>, String> {
    let wanted = targets.iter().copied().collect::<BTreeSet<_>>();
    let deadline = Instant::now() + wait;
    let mut replies = BTreeMap::new();
    while Instant::now() < deadline {
        if let Some(frame) = receive()?
            && let Some((ip, mac)) = reply(&frame, &wanted, source_mac, source_ip)
        {
            replies.insert(ip, mac);
        }
    }
    Ok(replies)
}

#[cfg(any(target_os = "linux", test))]
fn icmp_request(
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> [u8; 42] {
    let mut frame = [0_u8; 42];
    frame[..6].copy_from_slice(&target_mac);
    frame[6..12].copy_from_slice(&source_mac);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    frame[14..34].copy_from_slice(&[
        0x45, 0, 0, 28, 0x4f, 0x54, 0x40, 0, 64, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    frame[26..30].copy_from_slice(&source_ip.octets());
    frame[30..34].copy_from_slice(&target_ip.octets());
    let ip_checksum = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    frame[34..42].copy_from_slice(&[8, 0, 0, 0, 0x4f, 0x54, 0, 1]);
    let icmp_checksum = checksum(&frame[34..42]);
    frame[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
    frame
}

#[cfg(any(target_os = "linux", test))]
fn fingerprint(
    frame: &[u8],
    targets: &BTreeMap<Ipv4Addr, [u8; 6]>,
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
) -> Option<(Ipv4Addr, Fingerprint)> {
    if frame.len() < 42
        || frame[..6] != source_mac
        || frame[12..14] != [0x08, 0x00]
        || frame[14] >> 4 != 4
        || frame[23] != 1
    {
        return None;
    }
    let header_length = usize::from(frame[14] & 0x0f) * 4;
    let total_length = u16::from_be_bytes([frame[16], frame[17]]) as usize;
    let icmp = 14 + header_length;
    if header_length < 20
        || total_length < header_length + 8
        || 14 + total_length > frame.len()
        || checksum(&frame[14..icmp]) != 0
        || u16::from_be_bytes([frame[20], frame[21]]) & 0x3fff != 0
        || frame[30..34] != source_ip.octets()
        || frame[icmp] != 0
        || frame[icmp + 4..icmp + 8] != [0x4f, 0x54, 0, 1]
        || checksum(&frame[icmp..14 + total_length]) != 0
    {
        return None;
    }
    let ip = Ipv4Addr::new(frame[26], frame[27], frame[28], frame[29]);
    let target_mac = targets.get(&ip)?;
    (frame[6..12] == *target_mac).then_some((
        ip,
        Fingerprint {
            ttl: frame[22],
            dont_fragment: frame[20] & 0x40 != 0,
        },
    ))
}

#[cfg(any(target_os = "linux", test))]
fn collect_fingerprints(
    targets: &BTreeMap<Ipv4Addr, [u8; 6]>,
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
    wait: Duration,
    mut receive: impl FnMut() -> Result<Option<Vec<u8>>, String>,
) -> Result<BTreeMap<Ipv4Addr, Fingerprint>, String> {
    let deadline = Instant::now() + wait;
    let mut fingerprints = BTreeMap::new();
    while Instant::now() < deadline {
        if let Some(frame) = receive()?
            && let Some((ip, value)) = fingerprint(&frame, targets, source_mac, source_ip)
        {
            fingerprints.insert(ip, value);
        }
    }
    Ok(fingerprints)
}

#[cfg(any(target_os = "linux", test))]
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes.chunks_exact(2).fold(0_u32, |sum, pair| {
        sum + u32::from(u16::from_be_bytes([pair[0], pair[1]]))
    });
    if let Some(byte) = bytes.chunks_exact(2).remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn mac_bytes(value: &str) -> Option<[u8; 6]> {
    let normalized = normalize_mac(value)?;
    let mut bytes = [0; 6];
    for (index, part) in normalized.split(':').enumerate() {
        bytes[index] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(bytes)
}

fn format_mac(value: [u8; 6]) -> String {
    value
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_ipv4_targets_and_rejects_oversized_ranges() {
        assert_eq!(
            expand_targets(&["192.0.2.0/30".into()]).unwrap(),
            [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]
        );
        assert!(expand_targets(&["10.0.0.0/8".into()]).is_err());
        assert!(expand_targets(&["2001:db8::1".into()]).is_err());
    }

    #[test]
    fn builds_and_reads_arp() {
        let frame = request(
            [0, 1, 2, 3, 4, 5],
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 20),
        );
        assert_eq!(&frame[38..42], &[192, 0, 2, 20]);

        let mut response = frame;
        response[..6].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
        response[6..12].copy_from_slice(&[0, 17, 34, 51, 68, 85]);
        response[20..22].copy_from_slice(&[0, 2]);
        response[22..28].copy_from_slice(&[0, 17, 34, 51, 68, 85]);
        response[28..32].copy_from_slice(&[192, 0, 2, 20]);
        response[32..38].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
        response[38..42].copy_from_slice(&[192, 0, 2, 10]);
        assert_eq!(
            reply(
                &response,
                &[Ipv4Addr::new(192, 0, 2, 20)].into(),
                [0, 1, 2, 3, 4, 5],
                Ipv4Addr::new(192, 0, 2, 10)
            ),
            Some((Ipv4Addr::new(192, 0, 2, 20), [0, 17, 34, 51, 68, 85]))
        );
    }

    #[test]
    fn builds_icmp_and_classifies_only_broad_families() {
        let request = icmp_request(
            [0, 1, 2, 3, 4, 5],
            Ipv4Addr::new(192, 0, 2, 10),
            [0, 17, 34, 51, 68, 85],
            Ipv4Addr::new(192, 0, 2, 20),
        );
        assert_eq!(checksum(&request[14..34]), 0);
        assert_eq!(checksum(&request[34..42]), 0);
        let mut response = request;
        response[..6].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
        response[6..12].copy_from_slice(&[0, 17, 34, 51, 68, 85]);
        response[26..30].copy_from_slice(&[192, 0, 2, 20]);
        response[30..34].copy_from_slice(&[192, 0, 2, 10]);
        response[24..26].fill(0);
        let ip_checksum = checksum(&response[14..34]);
        response[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
        response[34] = 0;
        response[36..38].fill(0);
        let icmp_checksum = checksum(&response[34..42]);
        response[36..38].copy_from_slice(&icmp_checksum.to_be_bytes());
        let targets = BTreeMap::from([(Ipv4Addr::new(192, 0, 2, 20), [0, 17, 34, 51, 68, 85])]);
        assert!(
            fingerprint(
                &response,
                &targets,
                [0, 1, 2, 3, 4, 5],
                Ipv4Addr::new(192, 0, 2, 10)
            )
            .is_some()
        );
        response[6] = 1;
        assert!(
            fingerprint(
                &response,
                &targets,
                [0, 1, 2, 3, 4, 5],
                Ipv4Addr::new(192, 0, 2, 10)
            )
            .is_none()
        );
        assert_eq!(
            classify(Fingerprint {
                ttl: 128,
                dont_fragment: true
            }),
            Some("Windows family")
        );
        assert_eq!(
            classify(Fingerprint {
                ttl: 64,
                dont_fragment: false
            }),
            None
        );
    }

    #[test]
    fn exercises_target_edges_device_evidence_and_local_interface_errors() {
        assert_eq!(expand_targets(&["192.0.2.1/32".into()]).unwrap().len(), 1);
        assert_eq!(expand_targets(&["192.0.2.0/31".into()]).unwrap().len(), 2);
        assert!(expand_targets(&["bad/24".into()]).is_err());
        assert!(expand_targets(&["192.0.2.1/33".into()]).is_err());
        assert!(scan("lo", "invalid", &[], Duration::ZERO).is_err());
        #[cfg(target_os = "linux")]
        {
            let _ = scan("lo", "00:11:22:33:44:55", &[], Duration::ZERO);
        }
        assert!(source_ipv4("missing-otserver-interface").is_err());
        #[cfg(target_os = "linux")]
        assert!(
            platform_scan(
                "missing-otserver-interface",
                [0, 1, 2, 3, 4, 5],
                Ipv4Addr::LOCALHOST,
                &[],
                Duration::ZERO,
            )
            .is_err()
        );

        let known = device(
            Ipv4Addr::new(192, 0, 2, 1),
            [0, 0, 0x0c, 0, 0, 1],
            Some(Fingerprint {
                ttl: 64,
                dont_fragment: true,
            }),
        );
        assert_eq!(known.observations.len(), 2);
        assert_eq!(
            known.observations[1].fields["operatingSystem"],
            "Linux/Unix family"
        );
        let unknown = device(
            Ipv4Addr::new(192, 0, 2, 2),
            [2, 0, 0, 0, 0, 1],
            Some(Fingerprint {
                ttl: 64,
                dont_fragment: false,
            }),
        );
        assert!(
            !unknown.observations[1]
                .fields
                .contains_key("operatingSystem")
        );
        assert_eq!(
            format_mac(mac_bytes("00-11-22-33-44-55").unwrap()),
            "00:11:22:33:44:55"
        );
        assert!(mac_bytes("invalid").is_none());
        assert_ne!(checksum(&[1]), 0);
    }

    #[test]
    fn collection_helpers_accept_replies_and_propagate_errors() {
        let source_mac = [0, 1, 2, 3, 4, 5];
        let target_mac = [0, 17, 34, 51, 68, 85];
        let source_ip = Ipv4Addr::new(192, 0, 2, 10);
        let target_ip = Ipv4Addr::new(192, 0, 2, 20);
        let mut arp = request(source_mac, source_ip, target_ip);
        arp[..6].copy_from_slice(&source_mac);
        arp[6..12].copy_from_slice(&target_mac);
        arp[20..22].copy_from_slice(&[0, 2]);
        arp[22..28].copy_from_slice(&target_mac);
        arp[28..32].copy_from_slice(&target_ip.octets());
        arp[32..38].copy_from_slice(&source_mac);
        arp[38..42].copy_from_slice(&source_ip.octets());
        let mut frames = vec![arp.to_vec()];
        let replies = collect_replies(
            &[target_ip],
            source_mac,
            source_ip,
            Duration::from_millis(1),
            || Ok(frames.pop()),
        )
        .unwrap();
        assert_eq!(replies[&target_ip], target_mac);
        assert!(
            collect_replies(
                &[],
                source_mac,
                source_ip,
                Duration::from_millis(1),
                || Err("failed".into())
            )
            .is_err()
        );

        let mut response = icmp_request(source_mac, source_ip, target_mac, target_ip);
        response[..6].copy_from_slice(&source_mac);
        response[6..12].copy_from_slice(&target_mac);
        response[26..30].copy_from_slice(&target_ip.octets());
        response[30..34].copy_from_slice(&source_ip.octets());
        response[24..26].fill(0);
        let value = checksum(&response[14..34]);
        response[24..26].copy_from_slice(&value.to_be_bytes());
        response[34] = 0;
        response[36..38].fill(0);
        let value = checksum(&response[34..42]);
        response[36..38].copy_from_slice(&value.to_be_bytes());
        let mut frames = vec![response.to_vec()];
        let fingerprints = collect_fingerprints(
            &BTreeMap::from([(target_ip, target_mac)]),
            source_mac,
            source_ip,
            Duration::from_millis(1),
            || Ok(frames.pop()),
        )
        .unwrap();
        assert!(fingerprints.contains_key(&target_ip));
        assert!(
            collect_fingerprints(
                &BTreeMap::new(),
                source_mac,
                source_ip,
                Duration::from_millis(1),
                || Err("failed".into())
            )
            .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn tests_windows_source_ipv4_and_platform_scan() {
        let _ = source_ipv4("invalid-iface");
        let scan_res = platform_scan(
            "invalid-iface",
            [0, 1, 2, 3, 4, 5],
            Ipv4Addr::new(127, 0, 0, 1),
            &[],
            Duration::ZERO,
        );
        assert_eq!(scan_res.unwrap().len(), 0);
    }
}
