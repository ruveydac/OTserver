use crate::contract::{
    Endpoint, NetworkInterface, Observation, Port, Source, TopologyLink, normalize_mac,
};
use async_snmp::{
    Auth, AuthProtocol, Client, PrivProtocol, Retry, Transport, Value, VarBind, oid::Oid,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(not(test))]
const SNMP_PORT: u16 = 161;
#[cfg(test)]
const SNMP_PORT: u16 = 1_161;
#[cfg(not(test))]
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(test)]
const QUERY_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_TABLE_ROWS: usize = 512;
const MAX_FDB_ROWS: usize = 4000;
const MAX_V1_FDB_ROWS: usize = 128;

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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Credentials {
    Single(Settings),
    Multiple(Vec<Settings>),
}

impl Credentials {
    pub fn settings(&self) -> Vec<Settings> {
        match self {
            Self::Single(settings) => vec![settings.clone()],
            Self::Multiple(settings) => settings.clone(),
        }
    }
}

pub struct ResultData {
    pub identity_mac: Option<String>,
    pub observation: Option<Observation>,
    pub interfaces: Vec<NetworkInterface>,
    pub ports: Vec<Port>,
    pub links: Vec<TopologyLink>,
    pub warnings: Vec<String>,
    pub inventory_complete: bool,
    pub lldp_complete: bool,
}

#[derive(Debug)]
pub struct QueryError {
    message: String,
    no_response: bool,
}

impl QueryError {
    pub fn is_no_response(&self) -> bool {
        self.no_response
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for QueryError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuerySelection {
    pub inventory: bool,
    pub lldp: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct QueryAttempt {
    pub description: String,
    pub success: bool,
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
    if version.eq_ignore_ascii_case("1") || version.eq_ignore_ascii_case("2c") {
        let community = settings
            .community
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or("public");
        return Ok(if version == "1" {
            Auth::v1(community)
        } else {
            Auth::v2c(community)
        });
    }
    if !version.eq_ignore_ascii_case("3") {
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
            auth_protocol(protocol)?.0,
            password(
                settings.auth_password.as_deref(),
                &format!("SNMPv3 authentication protocol {protocol}"),
            )?,
        );
    }
    if let Some(protocol) = &settings.privacy_protocol {
        builder = builder.privacy(
            privacy_protocol(protocol)?.0,
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
        .filter(|value| value.len() >= 8)
        .ok_or_else(|| format!("{context} needs a password of at least 8 bytes."))
}

fn auth_protocol(value: &str) -> Result<(AuthProtocol, &'static str), String> {
    match value.to_ascii_lowercase().as_str() {
        "md5" => Ok((AuthProtocol::Md5, "MD5")),
        "sha1" => Ok((AuthProtocol::Sha1, "SHA-1")),
        "sha224" => Ok((AuthProtocol::Sha224, "SHA-224")),
        "sha256" => Ok((AuthProtocol::Sha256, "SHA-256")),
        "sha384" => Ok((AuthProtocol::Sha384, "SHA-384")),
        "sha512" => Ok((AuthProtocol::Sha512, "SHA-512")),
        _ => Err(format!("Unsupported SNMP authentication protocol: {value}")),
    }
}

fn privacy_protocol(value: &str) -> Result<(PrivProtocol, &'static str), String> {
    match value.to_ascii_lowercase().as_str() {
        "des" => Ok((PrivProtocol::Des, "DES")),
        "aes128" => Ok((PrivProtocol::Aes128, "AES-128")),
        "aes192" => Ok((PrivProtocol::Aes192, "AES-192")),
        "aes256" => Ok((PrivProtocol::Aes256, "AES-256")),
        _ => Err(format!("Unsupported SNMP privacy protocol: {value}")),
    }
}

fn query_settings(settings: &Settings) -> Vec<Settings> {
    if !resolved_version(settings).eq_ignore_ascii_case("auto") {
        return vec![settings.clone()];
    }

    let mut attempts = Vec::with_capacity(3);
    let mut v3 = settings.clone();
    v3.version = Some("3".into());
    if attempt_description(&v3).is_ok() && auth(&v3).is_ok() {
        attempts.push(v3);
    }
    for version in ["2c", "1"] {
        let mut community = settings.clone();
        community.version = Some(version.into());
        attempts.push(community);
    }
    attempts
}

pub fn attempt_settings(credentials: &[Settings]) -> Vec<Settings> {
    let mut attempts = Vec::new();
    let mut seen = Vec::new();
    for settings in credentials {
        for attempt in query_settings(settings) {
            let key = normalized_attempt(&attempt);
            if !seen.contains(&key) {
                seen.push(key);
                attempts.push(attempt);
            }
        }
    }
    attempts
}

fn normalized_attempt(settings: &Settings) -> Settings {
    let mut normalized = settings.clone();
    normalized.version = Some(resolved_version(settings).to_string());
    if normalized.version.as_deref() == Some("3") {
        normalized.community = None;
    } else {
        normalized.username = None;
        normalized.context_name = None;
        normalized.auth_protocol = None;
        normalized.auth_password = None;
        normalized.privacy_protocol = None;
        normalized.privacy_password = None;
    }
    normalized
}

pub fn attempt_description(settings: &Settings) -> Result<String, String> {
    let version = resolved_version(settings);
    if version.eq_ignore_ascii_case("1") || version.eq_ignore_ascii_case("2c") {
        return Ok(format!(
            "version={} security=community authentication=none encryption=none",
            if version.eq_ignore_ascii_case("1") {
                "1"
            } else {
                "2c"
            }
        ));
    }
    if !version.eq_ignore_ascii_case("3") {
        return Err(format!("Unsupported SNMP version {version}."));
    }

    let authentication = settings
        .auth_protocol
        .as_deref()
        .map(auth_protocol)
        .transpose()?
        .map(|(_, name)| name);
    let encryption = settings
        .privacy_protocol
        .as_deref()
        .map(privacy_protocol)
        .transpose()?
        .map(|(_, name)| name);
    let security = match (authentication, encryption) {
        (None, None) => "noAuthNoPriv",
        (Some(_), None) => "authNoPriv",
        (Some(_), Some(_)) => "authPriv",
        (None, Some(_)) => return Err("SNMPv3 privacy requires authentication.".into()),
    };
    Ok(format!(
        "version=3 security={security} authentication={} encryption={}",
        authentication.unwrap_or("none"),
        encryption.unwrap_or("none")
    ))
}

pub async fn query(
    target: &str,
    local_mac: Option<&str>,
    settings: &Settings,
    selection: QuerySelection,
) -> Result<ResultData, QueryError> {
    query_with_attempts(target, local_mac, std::slice::from_ref(settings), selection)
        .await
        .1
}

pub async fn query_with_attempts(
    target: &str,
    local_mac: Option<&str>,
    settings: &[Settings],
    selection: QuerySelection,
) -> (Vec<QueryAttempt>, Result<ResultData, QueryError>) {
    let settings = attempt_settings(settings);
    let settings_len = settings.len();
    let mut attempts = Vec::with_capacity(settings.len());
    let deadline = tokio::time::Instant::now() + QUERY_TIMEOUT;
    let responded = AtomicBool::new(false);
    let mut network_attempted = false;
    let result = match tokio::time::timeout(QUERY_TIMEOUT, async {
        let mut last_error = None;
        for (index, settings) in settings.into_iter().enumerate() {
            let attempts_left = u32::try_from(settings_len - index).unwrap_or(1);
            let attempt_timeout =
                deadline.saturating_duration_since(tokio::time::Instant::now()) / attempts_left;
            let description = match attempt_description(&settings) {
                Ok(description) => description,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            let authentication = match auth(&settings) {
                Ok(authentication) => authentication,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            network_attempted = true;
            attempts.push(QueryAttempt {
                description,
                success: false,
            });
            match tokio::time::timeout(
                attempt_timeout,
                query_inner(
                    target,
                    local_mac,
                    &settings,
                    selection,
                    authentication,
                    &responded,
                ),
            )
            .await
            {
                Ok(Ok(result)) => {
                    if let Some(attempt) = attempts.last_mut() {
                        attempt.success = true;
                    }
                    return Ok(result);
                }
                Ok(Err(error)) => last_error = Some(error),
                Err(_) => {
                    last_error = Some(format!(
                        "SNMP {target}: query exceeded its {} second version budget.",
                        attempt_timeout.as_secs()
                    ));
                }
            }
        }
        Err(last_error.unwrap_or_else(|| "No usable SNMP version was configured.".into()))
    })
    .await
    {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(message)) => Err(QueryError {
            message,
            no_response: network_attempted && !responded.load(Ordering::Relaxed),
        }),
        Err(_) => Err(QueryError {
            message: format!(
                "SNMP {target}: query exceeded {} seconds.",
                QUERY_TIMEOUT.as_secs()
            ),
            no_response: network_attempted && !responded.load(Ordering::Relaxed),
        }),
    };
    (attempts, result)
}

async fn query_inner(
    target: &str,
    local_mac: Option<&str>,
    settings: &Settings,
    selection: QuerySelection,
    authentication: Auth,
    responded: &AtomicBool,
) -> Result<ResultData, String> {
    let client = Client::builder((target, SNMP_PORT), authentication)
        .timeout(Duration::from_secs(3))
        .retry(Retry::fixed(1, Duration::ZERO))
        .max_repetitions(10)
        .max_walk_results(MAX_FDB_ROWS + 1)
        .connect()
        .await
        .map_err(|error| format!("SNMP {target}: {error}"))?;
    let mut fields = BTreeMap::new();
    let mut raw = Map::new();
    let mut interfaces = BTreeMap::<String, NetworkInterface>::new();
    let mut ports = BTreeMap::<String, Port>::new();
    let mut warnings = vec![];
    let mut inventory_complete = true;
    let mut lldp_complete = true;
    let mut bridge_mac = None;
    let mut siemens = false;
    if selection.inventory {
        let system = client
            .get_many(&[
                Oid::parse("1.3.6.1.2.1.1.1.0").unwrap(),
                Oid::parse("1.3.6.1.2.1.1.5.0").unwrap(),
                Oid::parse("1.3.6.1.2.1.1.6.0").unwrap(),
                Oid::parse("1.3.6.1.2.1.1.2.0").unwrap(),
            ])
            .await
            .map_err(|error| {
                mark_response(&error, responded);
                format!("SNMP {target}: {error}")
            })?;
        responded.store(true, Ordering::Relaxed);
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
                "1.3.6.1.2.1.1.2.0" => {
                    siemens = item
                        .value
                        .as_oid()
                        .is_some_and(|oid| oid.to_string().starts_with("1.3.6.1.4.1.4329."));
                    if siemens {
                        fields.insert("vendor".into(), json!("Siemens"));
                    }
                }
                _ => {}
            }
        }
        if let Ok(item) = client
            .get(&Oid::parse("1.3.6.1.2.1.17.1.1.0").unwrap())
            .await
        {
            let key = item.oid.to_string();
            raw.insert(key, value_json(&item.value));
            bridge_mac = item
                .value
                .as_bytes()
                .filter(|value| value.len() == 6)
                .map(mac);
        }
        if let Ok(values) = client
            .get_many(&[
                Oid::parse("1.3.6.1.2.1.25.1.1.0").unwrap(),
                Oid::parse("1.3.6.1.2.1.25.1.2.0").unwrap(),
                Oid::parse("1.3.6.1.2.1.25.1.5.0").unwrap(),
                Oid::parse("1.3.6.1.2.1.25.1.6.0").unwrap(),
            ])
            .await
        {
            for item in values {
                raw.insert(item.oid.to_string(), value_json(&item.value));
            }
        }
        if siemens {
            match client
                .get_many(&[
                    Oid::parse("1.3.6.1.4.1.4329.6.3.2.1.1.2.0").unwrap(),
                    Oid::parse("1.3.6.1.4.1.4329.6.3.2.1.1.3.0").unwrap(),
                    Oid::parse("1.3.6.1.4.1.4329.6.3.2.1.1.4.0").unwrap(),
                    Oid::parse("1.3.6.1.4.1.4329.6.3.2.1.1.5.0").unwrap(),
                    Oid::parse("1.3.6.1.4.1.4329.6.3.2.1.2.1.0").unwrap(),
                ])
                .await
            {
                Ok(values) => {
                    for item in values {
                        let key = item.oid.to_string();
                        raw.insert(key.clone(), value_json(&item.value));
                        let Some(value) =
                            item.value.as_str().filter(|value| !value.trim().is_empty())
                        else {
                            continue;
                        };
                        match key.as_str() {
                            "1.3.6.1.4.1.4329.6.3.2.1.1.2.0" => {
                                fields.insert("model".into(), json!(value));
                            }
                            "1.3.6.1.4.1.4329.6.3.2.1.1.3.0" => {
                                fields.insert("serialNumber".into(), json!(value));
                            }
                            "1.3.6.1.4.1.4329.6.3.2.1.1.5.0" => {
                                fields.insert("firmwareVersion".into(), json!(value));
                            }
                            _ => {}
                        }
                    }
                }
                Err(error) => warnings.push(format!(
                    "SNMP Siemens AUTOMATION-SYSTEM-MIB {target}: {error}"
                )),
            }
        }
        let if_root = "1.3.6.1.2.1.2.2.1";
        let mut if_values = vec![];
        for column in ["2", "4", "5", "6", "7", "8"] {
            match collect_walk(&client, &format!("{if_root}.{column}"), MAX_TABLE_ROWS).await {
                Ok(values) => if_values.extend(values),
                Err(error) => {
                    inventory_complete = false;
                    warnings.push(format!("SNMP IF-MIB {target} column {column}: {error}"));
                    break;
                }
            }
        }
        for item in if_values {
            let key = item.oid.to_string();
            raw.insert(key.clone(), value_json(&item.value));
            let Some((column, index)) = table_cell(&key, if_root) else {
                continue;
            };
            let interface = interface(&mut interfaces, &index);
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
        let ifx_root = "1.3.6.1.2.1.31.1.1.1";
        let mut ifx_values = vec![];
        for column in ["1", "15", "18"] {
            match collect_walk(&client, &format!("{ifx_root}.{column}"), MAX_TABLE_ROWS).await {
                Ok(values) => ifx_values.extend(values),
                Err(error) => {
                    inventory_complete = false;
                    warnings.push(format!(
                        "SNMP IF-MIB extension {target} column {column}: {error}"
                    ));
                    break;
                }
            }
        }
        for item in ifx_values {
            let key = item.oid.to_string();
            raw.insert(key.clone(), value_json(&item.value));
            let Some((column, index)) = table_cell(&key, ifx_root) else {
                continue;
            };
            let interface = interface(&mut interfaces, &index);
            match column {
                "1" => {
                    interface.name = item
                        .value
                        .as_str()
                        .filter(|value| !value.trim().is_empty())
                        .map(str::to_owned)
                }
                "15" => {
                    if let Some(speed) = item
                        .value
                        .as_u64()
                        .and_then(|value| value.checked_mul(1_000_000))
                        .filter(|speed| *speed > 0)
                    {
                        interface.speed = Some(speed);
                    }
                }
                "18" => {
                    if let Some(alias) =
                        item.value.as_str().filter(|value| !value.trim().is_empty())
                    {
                        if let Some(raw) = interface.raw.as_object_mut() {
                            raw.insert("ifAlias".into(), json!(alias));
                        }
                        if interface.description.is_none() {
                            interface.description = Some(alias.to_owned());
                        }
                    }
                }
                _ => {}
            }
        }
        let ip_root = "1.3.6.1.2.1.4.20.1";
        match collect_walk(&client, &format!("{ip_root}.2"), MAX_TABLE_ROWS).await {
            Ok(values) => {
                responded.store(true, Ordering::Relaxed);
                for item in values {
                    let key = item.oid.to_string();
                    raw.insert(key.clone(), value_json(&item.value));
                    if let Some(("2", ip)) = table_cell(&key, ip_root)
                        && let Some(index) = item.value.as_u64()
                    {
                        let interface = interface(&mut interfaces, &index.to_string());
                        interface.ip_addresses.push(ip);
                    }
                }
            }
            Err(error) => {
                inventory_complete = false;
                warnings.push(format!("SNMP IP-MIB {target}: {error}"));
            }
        }
        let modern_ip_root = "1.3.6.1.2.1.4.34.1";
        match collect_walk(&client, &format!("{modern_ip_root}.3"), MAX_TABLE_ROWS).await {
            Ok(values) => {
                for item in values {
                    let key = item.oid.to_string();
                    raw.insert(key.clone(), value_json(&item.value));
                    if let Some(("3", index)) = table_cell(&key, modern_ip_root)
                        && let Some(ip) = ip_address_index(&index)
                        && let Some(if_index) = item.value.as_u64()
                    {
                        interface(&mut interfaces, &if_index.to_string())
                            .ip_addresses
                            .push(ip);
                    }
                }
            }
            Err(error) => {
                inventory_complete = false;
                warnings.push(format!("SNMP modern IP-MIB {target}: {error}"));
            }
        }
        let entity_root = "1.3.6.1.2.1.47.1.1.1.1";
        let mut entities = BTreeMap::<String, PhysicalEntity>::new();
        let mut entity_values = vec![];
        for column in [
            "2", "4", "5", "7", "8", "9", "10", "11", "12", "13", "14", "15", "17",
        ] {
            match collect_walk(&client, &format!("{entity_root}.{column}"), MAX_TABLE_ROWS).await {
                Ok(values) => entity_values.extend(values),
                Err(error) => {
                    inventory_complete = false;
                    warnings.push(format!("SNMP ENTITY-MIB {target} column {column}: {error}"));
                    break;
                }
            }
        }
        for item in entity_values {
            let key = item.oid.to_string();
            raw.insert(key.clone(), value_json(&item.value));
            let Some((column, index)) = table_cell(&key, entity_root) else {
                continue;
            };
            let entity = entities.entry(index).or_default();
            let text = || {
                item.value
                    .as_str()
                    .filter(|value| !value.trim().is_empty())
                    .map(str::to_owned)
            };
            match column {
                "4" => entity.contained_in = item.value.as_i32(),
                "5" => entity.class = item.value.as_i32(),
                "8" => entity.hardware = text(),
                "9" => entity.firmware = text(),
                "10" => entity.software = text(),
                "11" => entity.serial = text(),
                "12" => entity.vendor = text(),
                "13" => entity.model = text(),
                "15" => entity.asset_id = text(),
                "17" => entity.manufactured_at = text(),
                _ => {}
            }
        }
        if let Some(entity) = preferred_entity(&entities) {
            for (field, value) in [
                ("vendor", entity.vendor.as_ref()),
                ("model", entity.model.as_ref()),
                ("serialNumber", entity.serial.as_ref()),
                (
                    "firmwareVersion",
                    entity.firmware.as_ref().or(entity.software.as_ref()),
                ),
            ] {
                if let Some(value) = value {
                    fields.insert(field.into(), json!(value));
                }
            }
        }
        let bridge_port_root = "1.3.6.1.2.1.17.1.4.1";
        match collect_walk(&client, &format!("{bridge_port_root}.2"), MAX_TABLE_ROWS).await {
            Ok(values) => {
                for item in values {
                    let key = item.oid.to_string();
                    raw.insert(key.clone(), value_json(&item.value));
                    if let Some(("2", bridge_index)) = table_cell(&key, bridge_port_root)
                        && let Some(if_index) = item.value.as_u64()
                    {
                        port(&mut ports, &bridge_index).interface_key =
                            Some(format!("ifIndex:{if_index}"));
                    }
                }
            }
            Err(error) => {
                inventory_complete = false;
                warnings.push(format!("SNMP BRIDGE-MIB {target}: {error}"));
            }
        }
        if !ports.is_empty() {
            let fdb_root = "1.3.6.1.2.1.17.4.3.1";
            let fdb_limit = if resolved_version(settings) == "1" {
                MAX_V1_FDB_ROWS
            } else {
                MAX_FDB_ROWS
            };
            let mut fdb_values = vec![];
            for column in ["2", "3"] {
                match collect_walk(&client, &format!("{fdb_root}.{column}"), fdb_limit).await {
                    Ok(values) => fdb_values.extend(values),
                    Err(error) => {
                        inventory_complete = false;
                        warnings.push(format!(
                            "SNMP BRIDGE-MIB forwarding table {target}: {error}"
                        ));
                        fdb_values.clear();
                        break;
                    }
                }
            }
            if !fdb_values.is_empty() {
                let mut entries = BTreeMap::<String, (Option<u64>, Option<i32>)>::new();
                for item in fdb_values {
                    let key = item.oid.to_string();
                    let Some((column, index)) = table_cell(&key, fdb_root) else {
                        continue;
                    };
                    let entry = entries.entry(index).or_default();
                    match column {
                        "2" => entry.0 = item.value.as_u64().filter(|port| *port > 0),
                        "3" => entry.1 = item.value.as_i32(),
                        _ => {}
                    }
                }
                let mut forwarding_macs = BTreeMap::<String, BTreeSet<String>>::new();
                for (index, (bridge_index, status)) in entries {
                    if matches!(status, Some(3 | 5))
                        && let Some(bridge_index) = bridge_index
                        && let Some(address) = indexed_mac(&index)
                    {
                        forwarding_macs
                            .entry(bridge_index.to_string())
                            .or_default()
                            .insert(address);
                    }
                }
                for (bridge_index, addresses) in forwarding_macs {
                    port(&mut ports, &bridge_index).raw = json!({ "forwardingMacs": addresses });
                }
            }

            let vlan_root = "1.3.6.1.2.1.17.7.1.4.2.1";
            match collect_walk(&client, &format!("{vlan_root}.4"), MAX_TABLE_ROWS).await {
                Ok(values) => {
                    for item in values {
                        let key = item.oid.to_string();
                        raw.insert(key.clone(), value_json(&item.value));
                        let Some(("4", index)) = table_cell(&key, vlan_root) else {
                            continue;
                        };
                        let Some(vlan) = index
                            .rsplit('.')
                            .next()
                            .and_then(|value| value.parse::<u16>().ok())
                            .filter(|vlan| *vlan <= 4095)
                        else {
                            continue;
                        };
                        if let Some(bitmap) = item.value.as_bytes() {
                            for bridge_index in bitmap_ports(bitmap) {
                                port(&mut ports, &bridge_index.to_string()).vlans.push(vlan);
                            }
                        }
                    }
                }
                Err(error) => {
                    inventory_complete = false;
                    warnings.push(format!("SNMP Q-BRIDGE-MIB VLAN table {target}: {error}"));
                }
            }
            let pvid_root = "1.3.6.1.2.1.17.7.1.4.5.1";
            match collect_walk(&client, &format!("{pvid_root}.1"), MAX_TABLE_ROWS).await {
                Ok(values) => {
                    for item in values {
                        let key = item.oid.to_string();
                        raw.insert(key.clone(), value_json(&item.value));
                        if let Some(("1", bridge_index)) = table_cell(&key, pvid_root)
                            && let Some(vlan) = item
                                .value
                                .as_u64()
                                .and_then(|value| u16::try_from(value).ok())
                                .filter(|vlan| *vlan <= 4095)
                        {
                            port(&mut ports, &bridge_index).vlans.push(vlan);
                        }
                    }
                }
                Err(error) => {
                    inventory_complete = false;
                    warnings.push(format!("SNMP Q-BRIDGE-MIB PVID table {target}: {error}"));
                }
            }
            for port in ports.values_mut() {
                port.vlans.sort_unstable();
                port.vlans.dedup();
            }
        }
        for interface in interfaces.values_mut() {
            interface.ip_addresses.sort();
            interface.ip_addresses.dedup();
        }
    }

    let mut neighbors = BTreeMap::<String, Neighbor>::new();
    let mut local_ports = BTreeMap::<String, LocalPort>::new();
    let mut lldp_chassis_mac = None;
    let mut local_system_name = None;
    if selection.lldp {
        match client
            .get_many(&[
                Oid::parse("1.0.8802.1.1.2.1.3.1.0").unwrap(),
                Oid::parse("1.0.8802.1.1.2.1.3.2.0").unwrap(),
                Oid::parse("1.0.8802.1.1.2.1.3.3.0").unwrap(),
                Oid::parse("1.0.8802.1.1.2.1.3.4.0").unwrap(),
                Oid::parse("1.0.8802.1.1.2.1.3.5.0").unwrap(),
                Oid::parse("1.0.8802.1.1.2.1.3.6.0").unwrap(),
            ])
            .await
        {
            Ok(values) => {
                responded.store(true, Ordering::Relaxed);
                let mut chassis_subtype = None;
                let mut chassis_id = None;
                for item in values {
                    let key = item.oid.to_string();
                    raw.insert(key.clone(), value_json(&item.value));
                    match key.as_str() {
                        "1.0.8802.1.1.2.1.3.1.0" => chassis_subtype = item.value.as_i32(),
                        "1.0.8802.1.1.2.1.3.2.0" => {
                            chassis_id = item.value.as_bytes().map(<[u8]>::to_vec)
                        }
                        "1.0.8802.1.1.2.1.3.3.0" => {
                            local_system_name = item.value.as_str().map(str::to_owned)
                        }
                        _ => {}
                    }
                }
                if chassis_subtype == Some(4) {
                    lldp_chassis_mac = chassis_id
                        .as_deref()
                        .filter(|value| value.len() == 6)
                        .map(mac);
                }
            }
            Err(error) => {
                mark_response(&error, responded);
                lldp_complete = false;
                warnings.push(format!("SNMP LLDP local system {target}: {error}"));
            }
        }

        let local_port_root = "1.0.8802.1.1.2.1.3.7.1";
        for column in ["2", "3", "4"] {
            match collect_walk(
                &client,
                &format!("{local_port_root}.{column}"),
                MAX_TABLE_ROWS,
            )
            .await
            {
                Ok(values) => {
                    for item in values {
                        let key = item.oid.to_string();
                        raw.insert(key.clone(), value_json(&item.value));
                        let Some((column, index)) = table_cell(&key, local_port_root) else {
                            continue;
                        };
                        let port = local_ports.entry(index).or_default();
                        match column {
                            "2" => port.id_subtype = item.value.as_i32(),
                            "3" => {
                                port.id = if port.id_subtype == Some(3) {
                                    item.value
                                        .as_bytes()
                                        .filter(|value| value.len() == 6)
                                        .map(mac)
                                } else {
                                    item.value.as_str().map(str::to_owned)
                                }
                            }
                            "4" => port.description = item.value.as_str().map(str::to_owned),
                            _ => {}
                        }
                    }
                }
                Err(error) => {
                    lldp_complete = false;
                    warnings.push(format!(
                        "SNMP LLDP local port {target} column {column}: {error}"
                    ));
                    break;
                }
            }
        }
        for (index, local_port) in &mut local_ports {
            let mut matches = interfaces.values().filter(|interface| {
                let Some(id) = &local_port.id else {
                    return false;
                };
                match local_port.id_subtype {
                    Some(1) => interface.raw["ifAlias"].as_str() == Some(id),
                    Some(3) => interface.mac_address.as_ref() == Some(id),
                    Some(5) => interface.name.as_ref() == Some(id),
                    _ => false,
                }
            });
            let matched = matches.next();
            local_port.interface_key = if matches.next().is_none() {
                matched.map(|interface| interface.key.clone())
            } else {
                None
            };
            let existing = local_port.interface_key.as_ref().and_then(|key| {
                ports.iter().find_map(|(port_key, port)| {
                    (port.interface_key.as_ref() == Some(key)).then(|| port_key.clone())
                })
            });
            let port = ports
                .entry(existing.unwrap_or_else(|| format!("lldp:{index}")))
                .or_insert_with(|| Port {
                    key: format!("lldpPort:{index}"),
                    source: "snmp".into(),
                    interface_key: local_port.interface_key.clone(),
                    port_id: None,
                    description: None,
                    mac_address: None,
                    vlans: vec![],
                    raw: json!({}),
                });
            if port.port_id.is_none() {
                port.port_id.clone_from(&local_port.id);
            }
            if port.description.is_none() {
                port.description.clone_from(&local_port.description);
            }
        }

        let local_management_root = "1.0.8802.1.1.2.1.3.8.1";
        match collect_walk(
            &client,
            &format!("{local_management_root}.3"),
            MAX_TABLE_ROWS,
        )
        .await
        {
            Ok(values) => {
                for item in values {
                    raw.insert(item.oid.to_string(), value_json(&item.value));
                }
            }
            Err(error) => {
                lldp_complete = false;
                warnings.push(format!(
                    "SNMP LLDP local management table {target}: {error}"
                ));
            }
        }

        let remote_root = "1.0.8802.1.1.2.1.4.1.1";
        let mut lldp = vec![];
        for column in ["4", "5", "6", "7", "8", "9", "10", "11", "12"] {
            match collect_walk(&client, &format!("{remote_root}.{column}"), MAX_TABLE_ROWS).await {
                Ok(values) => lldp.extend(values),
                Err(error) if selection.inventory => {
                    lldp_complete = false;
                    warnings.push(format!("SNMP LLDP-MIB {target} column {column}: {error}"));
                    lldp.clear();
                    break;
                }
                Err(error) => {
                    return Err(format!("SNMP LLDP-MIB {target} column {column}: {error}"));
                }
            }
        }
        for item in lldp {
            let key = item.oid.to_string();
            raw.insert(key.clone(), value_json(&item.value));
            let Some((column, index)) = table_cell(&key, remote_root) else {
                continue;
            };
            let local_port = index.split('.').nth(1).map(str::to_owned);
            let neighbor = neighbors.entry(index).or_default();
            neighbor.local_port = local_port;
            match column {
                "4" => neighbor.chassis_subtype = item.value.as_i32(),
                "5" => neighbor.chassis_id = item.value.as_bytes().map(<[u8]>::to_vec),
                "6" => neighbor.port_subtype = item.value.as_i32(),
                "7" => {
                    neighbor.port = if neighbor.port_subtype == Some(3) {
                        item.value
                            .as_bytes()
                            .filter(|value| value.len() == 6)
                            .map(mac)
                    } else {
                        item.value.as_str().map(str::to_owned)
                    }
                }
                "8" => neighbor.port_description = item.value.as_str().map(str::to_owned),
                "9" => neighbor.name = item.value.as_str().map(str::to_owned),
                "10" => neighbor.description = item.value.as_str().map(str::to_owned),
                "11" => neighbor.capabilities_supported = Some(value_json(&item.value)),
                "12" => neighbor.capabilities_enabled = Some(value_json(&item.value)),
                _ => {}
            }
        }
        let remote_management_root = "1.0.8802.1.1.2.1.4.2.1";
        match collect_walk(
            &client,
            &format!("{remote_management_root}.3"),
            MAX_TABLE_ROWS,
        )
        .await
        {
            Ok(values) => {
                for item in values {
                    let key = item.oid.to_string();
                    raw.insert(key.clone(), value_json(&item.value));
                    if let Some(("3", index)) = table_cell(&key, remote_management_root)
                        && let Some((neighbor_index, address)) = lldp_management_address(&index)
                        && let Some(neighbor) = neighbors.get_mut(&neighbor_index)
                    {
                        neighbor.management_addresses.insert(address);
                    }
                }
            }
            Err(error) => {
                lldp_complete = false;
                warnings.push(format!(
                    "SNMP LLDP remote management table {target}: {error}"
                ));
            }
        }
    }
    let identity_mac = local_mac
        .and_then(normalize_mac)
        .or_else(|| bridge_mac.as_deref().and_then(normalize_mac))
        .or_else(|| {
            interfaces
                .values()
                .find(|interface| interface.ip_addresses.iter().any(|ip| ip == target))
                .and_then(|interface| interface.mac_address.as_deref())
                .and_then(normalize_mac)
        })
        .or_else(|| lldp_chassis_mac.as_deref().and_then(normalize_mac));
    let observed_at = crate::now();
    let links = if let Some(local) = &identity_mac {
        neighbors
            .into_values()
            .filter_map(|neighbor| {
                let remote_mac = neighbor.chassis_mac()?;
                let local_port = neighbor
                    .local_port
                    .as_ref()
                    .and_then(|index| local_ports.get(index));
                Some(TopologyLink {
                    source: Source::Lldp,
                    observed_at: observed_at.clone(),
                    local: Endpoint {
                        mac_address: local.clone(),
                        station_name: local_system_name.clone(),
                        interface_key: local_port.and_then(|port| port.interface_key.clone()),
                        port_id: local_port
                            .and_then(|port| port.id.clone())
                            .or(neighbor.local_port),
                        port_mac: None,
                    },
                    remote: Endpoint {
                        mac_address: remote_mac,
                        station_name: neighbor.name,
                        interface_key: None,
                        port_id: neighbor.port,
                        port_mac: None,
                    },
                    raw: json!({
                        "version": resolved_version(settings),
                        "remotePortDescription": neighbor.port_description,
                        "remoteSystemDescription": neighbor.description,
                        "remoteCapabilitiesSupported": neighbor.capabilities_supported,
                        "remoteCapabilitiesEnabled": neighbor.capabilities_enabled,
                        "remoteManagementAddresses": neighbor.management_addresses,
                    }),
                })
            })
            .collect()
    } else {
        vec![]
    };
    Ok(ResultData {
        identity_mac: identity_mac.clone(),
        observation: selection.inventory.then(|| Observation {
            source: Source::Snmp,
            observed_at,
            ip_address: Some(target.into()),
            mac_address: identity_mac,
            fields,
            raw: raw.into(),
            warnings: warnings.clone(),
        }),
        interfaces: interfaces.into_values().collect(),
        ports: ports.into_values().collect(),
        links,
        warnings,
        inventory_complete,
        lldp_complete,
    })
}

async fn collect_walk<T: Transport + 'static>(
    client: &Client<T>,
    oid: &str,
    limit: usize,
) -> Result<Vec<VarBind>, String> {
    let mut walk = client
        .walk(Oid::parse(oid).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let mut values = vec![];
    // All callers walk tables; avoid collect()'s scalar GET fallback for an empty table.
    while let Some(value) = walk.next().await {
        let value = value.map_err(|error| error.to_string())?;
        if values.len() == limit {
            return Err(format!("table exceeded safe limit of {limit} rows"));
        }
        values.push(value);
    }
    Ok(values)
}

fn mark_response(error: &async_snmp::Error, responded: &AtomicBool) {
    if !matches!(
        error,
        async_snmp::Error::Timeout { .. }
            | async_snmp::Error::Network { .. }
            | async_snmp::Error::Closed { .. }
    ) {
        responded.store(true, Ordering::Relaxed);
    }
}

fn port<'a>(ports: &'a mut BTreeMap<String, Port>, index: &str) -> &'a mut Port {
    ports
        .entry(format!("bridge:{index}"))
        .or_insert_with(|| Port {
            key: format!("bridgePort:{index}"),
            source: "snmp".into(),
            interface_key: None,
            port_id: None,
            description: None,
            mac_address: None,
            vlans: vec![],
            raw: json!({}),
        })
}

fn interface<'a>(
    interfaces: &'a mut BTreeMap<String, NetworkInterface>,
    index: &str,
) -> &'a mut NetworkInterface {
    interfaces
        .entry(index.to_owned())
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
        })
}

#[derive(Default)]
struct PhysicalEntity {
    contained_in: Option<i32>,
    class: Option<i32>,
    hardware: Option<String>,
    firmware: Option<String>,
    software: Option<String>,
    serial: Option<String>,
    vendor: Option<String>,
    model: Option<String>,
    asset_id: Option<String>,
    manufactured_at: Option<String>,
}

fn preferred_entity(entities: &BTreeMap<String, PhysicalEntity>) -> Option<&PhysicalEntity> {
    entities.values().max_by_key(|entity| {
        let root = u8::from(entity.contained_in == Some(0));
        let class = match entity.class {
            Some(3) => 3,  // chassis
            Some(11) => 2, // stack
            Some(9) => 1,  // module
            _ => 0,
        };
        let populated = [
            &entity.firmware,
            &entity.hardware,
            &entity.software,
            &entity.serial,
            &entity.vendor,
            &entity.model,
            &entity.asset_id,
            &entity.manufactured_at,
        ]
        .into_iter()
        .filter(|value| value.is_some())
        .count();
        (root, class, populated)
    })
}

#[derive(Default)]
struct LocalPort {
    id_subtype: Option<i32>,
    id: Option<String>,
    description: Option<String>,
    interface_key: Option<String>,
}

#[derive(Default)]
struct Neighbor {
    local_port: Option<String>,
    chassis_subtype: Option<i32>,
    chassis_id: Option<Vec<u8>>,
    name: Option<String>,
    port_subtype: Option<i32>,
    port: Option<String>,
    port_description: Option<String>,
    description: Option<String>,
    capabilities_supported: Option<serde_json::Value>,
    capabilities_enabled: Option<serde_json::Value>,
    management_addresses: BTreeSet<String>,
}

impl Neighbor {
    fn chassis_mac(&self) -> Option<String> {
        let value = self.chassis_id.as_deref()?;
        (self.chassis_subtype == Some(4) && value.len() == 6).then(|| mac(value))
    }
}

fn table_cell<'a>(oid: &'a str, prefix: &str) -> Option<(&'a str, String)> {
    let suffix = oid.strip_prefix(prefix)?.strip_prefix('.')?;
    let (column, index) = suffix.split_once('.')?;
    Some((column, index.to_owned()))
}

fn ip_address_index(index: &str) -> Option<String> {
    let values = index
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    match values.as_slice() {
        [1, 4, a, b, c, d] => Some(Ipv4Addr::new(*a, *b, *c, *d).to_string()),
        [3, 8, a, b, c, d, _, _, _, _] => Some(Ipv4Addr::new(*a, *b, *c, *d).to_string()),
        [2, 16, address @ ..] if address.len() == 16 => {
            let bytes: [u8; 16] = address.try_into().ok()?;
            Some(Ipv6Addr::from(bytes).to_string())
        }
        [4, 20, address @ ..] if address.len() == 20 => {
            let bytes: [u8; 16] = address[..16].try_into().ok()?;
            Some(Ipv6Addr::from(bytes).to_string())
        }
        _ => None,
    }
}

fn indexed_mac(index: &str) -> Option<String> {
    let bytes = index
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (bytes.len() == 6).then(|| mac(&bytes))
}

fn bitmap_ports(bitmap: &[u8]) -> Vec<u64> {
    bitmap
        .iter()
        .enumerate()
        .flat_map(|(byte_index, byte)| {
            (0..8).filter_map(move |bit| {
                (byte & (0x80 >> bit) != 0).then_some((byte_index * 8 + bit + 1) as u64)
            })
        })
        .collect()
}

fn lldp_management_address(index: &str) -> Option<(String, String)> {
    let values = index
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    if values.len() < 5 {
        return None;
    }
    let neighbor = values[..3]
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".");
    let length = usize::try_from(values[4]).ok()?;
    let address = values.get(5..5 + length)?;
    let address = match (values[3], address) {
        (1, [a, b, c, d]) => Some(
            Ipv4Addr::new(
                u8::try_from(*a).ok()?,
                u8::try_from(*b).ok()?,
                u8::try_from(*c).ok()?,
                u8::try_from(*d).ok()?,
            )
            .to_string(),
        ),
        (2, address) if address.len() == 16 => {
            let bytes = address
                .iter()
                .map(|value| u8::try_from(*value))
                .collect::<Result<Vec<_>, _>>()
                .ok()?;
            Some(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?).to_string())
        }
        _ => None,
    }?;
    Some((neighbor, address))
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
    } else if let Some(oid) = value.as_oid() {
        json!(oid.to_string())
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
    use std::sync::{Arc, Mutex};
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
        let malformed = Neighbor {
            chassis_subtype: Some(4),
            chassis_id: Some(vec![0, 1, 2, 3, 4, 5, 6]),
            ..Neighbor::default()
        };
        assert_eq!(malformed.chassis_mac(), None);
    }

    #[test]
    fn builds_auth_from_inline_settings() {
        assert!(auth(&settings("unsupported")).is_err());
        assert!(auth(&settings("1")).is_ok());

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
        v3.auth_password = Some("short".into());
        assert!(auth(&v3).is_err());
        v3.auth_password = Some("auth-secret".into());
        v3.privacy_protocol = Some("aes128".into());
        assert!(auth(&v3).is_err());
        v3.privacy_password = Some("short".into());
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

    #[test]
    fn auto_orders_only_usable_protocol_versions() {
        let mut auto = settings("auto");
        assert_eq!(
            query_settings(&auto)
                .iter()
                .map(resolved_version)
                .collect::<Vec<_>>(),
            ["2c", "1"]
        );
        auto.username = Some("inventory".into());
        assert_eq!(
            query_settings(&auto)
                .iter()
                .map(resolved_version)
                .collect::<Vec<_>>(),
            ["3", "2c", "1"]
        );
        auto.auth_protocol = Some("sha256".into());
        assert_eq!(
            query_settings(&auto)
                .iter()
                .map(resolved_version)
                .collect::<Vec<_>>(),
            ["2c", "1"]
        );
        auto.auth_protocol = None;
        auto.privacy_protocol = Some("aes128".into());
        auto.privacy_password = Some("privacy-secret".into());
        assert_eq!(
            query_settings(&auto)
                .iter()
                .map(resolved_version)
                .collect::<Vec<_>>(),
            ["2c", "1"]
        );
        assert_eq!(
            query_settings(&Settings::default())
                .iter()
                .map(resolved_version)
                .collect::<Vec<_>>(),
            ["2c"]
        );
    }

    #[test]
    fn credentials_accept_object_or_list() {
        let single: Credentials =
            serde_json::from_str(r#"{"version":"2c","community":"public"}"#).unwrap();
        assert_eq!(
            single.settings(),
            [Settings {
                version: Some("2c".into()),
                community: Some("public".into()),
                ..Settings::default()
            }]
        );
        let multiple: Credentials =
            serde_json::from_str(r#"[{"community":"first"},{"version":"3","username":"ops"}]"#)
                .unwrap();
        let settings = multiple.settings();
        assert_eq!(settings.len(), 2);
        assert_eq!(settings[0].community.as_deref(), Some("first"));
        assert_eq!(settings[1].username.as_deref(), Some("ops"));
        assert_eq!(
            serde_json::to_value(&single).unwrap()["community"],
            "public"
        );
        assert!(serde_json::to_value(&multiple).unwrap().is_array());
        assert!(
            serde_json::from_str::<Credentials>(r#"{"community":"a","unknown":true}"#).is_err()
        );
    }

    #[test]
    fn attempt_settings_expands_and_dedupes_credentials() {
        let mut auto = settings("auto");
        auto.username = Some("inventory".into());
        assert_eq!(
            attempt_settings(&[auto.clone(), settings("2c"), settings("2c")])
                .iter()
                .map(resolved_version)
                .collect::<Vec<_>>(),
            ["3", "2c", "1"]
        );
        let other = Settings {
            community: Some("other".into()),
            ..Settings::default()
        };
        let attempts = attempt_settings(&[settings("2c"), other]);
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[1].community.as_deref(), Some("other"));
        assert!(attempt_settings(&[]).is_empty());
    }

    #[test]
    fn describes_snmp_security_without_credentials() {
        let settings = Settings {
            version: Some("3".into()),
            community: Some("private-community".into()),
            username: Some("inventory-user".into()),
            context_name: Some("private-context".into()),
            auth_protocol: Some("sha256".into()),
            auth_password: Some("auth-secret".into()),
            privacy_protocol: Some("aes128".into()),
            privacy_password: Some("privacy-secret".into()),
        };

        assert_eq!(
            attempt_description(&settings).unwrap(),
            "version=3 security=authPriv authentication=SHA-256 encryption=AES-128"
        );
    }

    #[test]
    fn decodes_standard_mib_index_values() {
        assert_eq!(
            ip_address_index("1.4.192.0.2.1").as_deref(),
            Some("192.0.2.1")
        );
        assert_eq!(
            ip_address_index("2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1").as_deref(),
            Some("2001:db8::1")
        );
        assert_eq!(
            ip_address_index("4.20.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.7").as_deref(),
            Some("fe80::1")
        );
        assert_eq!(
            indexed_mac("0.1.2.3.4.5").as_deref(),
            Some("00:01:02:03:04:05")
        );
        assert_eq!(bitmap_ports(&[0x82]), [1, 7]);
        assert_eq!(
            lldp_management_address("0.7.1.1.4.192.0.2.2"),
            Some(("0.7.1".into(), "192.0.2.2".into()))
        );
        assert_eq!(
            lldp_management_address("4294967295.7.1.1.4.192.0.2.2"),
            Some(("4294967295.7.1".into(), "192.0.2.2".into()))
        );
    }

    #[tokio::test]
    async fn queries_system_interfaces_inventory_and_lldp() {
        let string = |value: &'static str| Value::OctetString(value.into());
        let mut entries = vec![
            ("1.0.8802.1.1.2.1.3.1.0", Value::Integer(4)),
            (
                "1.0.8802.1.1.2.1.3.2.0",
                Value::OctetString(vec![6, 7, 8, 9, 10, 11].into()),
            ),
            ("1.0.8802.1.1.2.1.3.3.0", string("plc-1")),
            ("1.0.8802.1.1.2.1.3.4.0", string("Industrial switch")),
            (
                "1.0.8802.1.1.2.1.3.5.0",
                Value::OctetString(vec![0x14].into()),
            ),
            (
                "1.0.8802.1.1.2.1.3.6.0",
                Value::OctetString(vec![0x14].into()),
            ),
            ("1.0.8802.1.1.2.1.3.7.1.2.7", Value::Integer(5)),
            ("1.0.8802.1.1.2.1.3.7.1.3.7", string("port-1")),
            ("1.0.8802.1.1.2.1.3.7.1.4.7", string("uplink")),
            ("1.0.8802.1.1.2.1.4.1.1.4.0.7.1", Value::Integer(4)),
            (
                "1.0.8802.1.1.2.1.4.1.1.5.0.7.1",
                Value::OctetString(vec![0, 1, 2, 3, 4, 5].into()),
            ),
            ("1.0.8802.1.1.2.1.4.1.1.6.0.7.1", Value::Integer(5)),
            ("1.0.8802.1.1.2.1.4.1.1.7.0.7.1", string("Gi1")),
            ("1.0.8802.1.1.2.1.4.1.1.8.0.7.1", string("peer uplink")),
            ("1.0.8802.1.1.2.1.4.1.1.9.0.7.1", string("peer")),
            ("1.0.8802.1.1.2.1.4.1.1.10.0.7.1", string("peer switch")),
            (
                "1.0.8802.1.1.2.1.4.2.1.3.0.7.1.1.4.192.0.2.2",
                Value::Integer(2),
            ),
            ("1.0.8802.1.1.2.1.5.1", Value::IpAddress([192, 0, 2, 1])),
            ("1.3.6.1.2.1.1.1.0", string("Linux industrial controller")),
            (
                "1.3.6.1.2.1.1.2.0",
                Value::ObjectIdentifier(Oid::parse("1.3.6.1.4.1.4329.6.3.2").unwrap()),
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
            (
                "1.3.6.1.2.1.4.34.1.3.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.1",
                Value::Integer(1),
            ),
            ("1.3.6.1.2.1.4.20.1.2.10.10.10.1", Value::Integer(1)),
            (
                "1.3.6.1.2.1.17.1.1.0",
                Value::OctetString(vec![6, 7, 8, 9, 10, 11].into()),
            ),
            ("1.3.6.1.2.1.17.1.4.1.2.7", Value::Integer(1)),
            ("1.3.6.1.2.1.17.4.3.1.2.0.1.2.3.4.5", Value::Integer(7)),
            ("1.3.6.1.2.1.17.4.3.1.2.0.1.2.3.4.6", Value::Integer(0)),
            ("1.3.6.1.2.1.17.4.3.1.3.0.1.2.3.4.5", Value::Integer(3)),
            ("1.3.6.1.2.1.17.4.3.1.3.0.1.2.3.4.6", Value::Integer(2)),
            (
                "1.3.6.1.2.1.17.7.1.4.2.1.4.0.100",
                Value::OctetString(vec![0x02].into()),
            ),
            (
                "1.3.6.1.2.1.17.7.1.4.2.1.4.0.5000",
                Value::OctetString(vec![0x02].into()),
            ),
            ("1.3.6.1.2.1.17.7.1.4.5.1.1.7", Value::Integer(100)),
            ("1.3.6.1.2.1.31.1.1.1.1.1", string("port-1")),
            ("1.3.6.1.2.1.31.1.1.1.15.1", Value::Gauge32(1000)),
            ("1.3.6.1.2.1.47.1.1.1.1.4.1", Value::Integer(3)),
            ("1.3.6.1.2.1.47.1.1.1.1.4.2", Value::Integer(3)),
            ("1.3.6.1.2.1.47.1.1.1.1.4.3", Value::Integer(0)),
            ("1.3.6.1.2.1.47.1.1.1.1.5.1", Value::Integer(6)),
            ("1.3.6.1.2.1.47.1.1.1.1.5.2", Value::Integer(3)),
            ("1.3.6.1.2.1.47.1.1.1.1.5.3", Value::Integer(11)),
            ("1.3.6.1.2.1.47.1.1.1.1.9.3", string("FW8.1")),
            ("1.3.6.1.2.1.47.1.1.1.1.10.2", string("V8.0")),
            ("1.3.6.1.2.1.47.1.1.1.1.10.3", string("SW8.0")),
            ("1.3.6.1.2.1.47.1.1.1.1.11.2", string("SERIAL")),
            ("1.3.6.1.2.1.47.1.1.1.1.12.2", string("Siemens")),
            ("1.3.6.1.2.1.47.1.1.1.1.13.1", string("Power supply")),
            ("1.3.6.1.2.1.47.1.1.1.1.13.2", string("SCALANCE X")),
            ("1.3.6.1.2.1.47.1.1.1.1.13.3", string("SCALANCE stack")),
            (
                "1.3.6.1.4.1.4329.6.3.2.1.1.2.0",
                string("6GK5008-0BA10-1AB2"),
            ),
            ("1.3.6.1.4.1.4329.6.3.2.1.1.3.0", string("S123")),
            ("1.3.6.1.4.1.4329.6.3.2.1.1.4.0", string("HW2")),
            ("1.3.6.1.4.1.4329.6.3.2.1.1.5.0", string("V9.0")),
            ("1.3.6.1.4.1.4329.6.3.2.1.2.1.0", Value::Integer(1)),
        ]
        .into_iter()
        .map(|(oid, value)| (Oid::parse(oid).unwrap(), value))
        .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        let socket = UdpSocket::bind(("127.0.0.1", SNMP_PORT)).await.unwrap();
        let requested_oids = Arc::new(Mutex::new(Vec::new()));
        let server_requests = Arc::clone(&requested_oids);
        let failed_oid = Arc::new(Mutex::new(None::<String>));
        let server_failure = Arc::clone(&failed_oid);
        let task = tokio::spawn(async move {
            let mut buffer = [0; 65_535];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let message = CommunityMessage::decode(buffer[..length].to_vec().into()).unwrap();
                let request = message.pdu.standard().unwrap();
                server_requests
                    .lock()
                    .unwrap()
                    .extend(request.varbinds.iter().map(|item| item.oid.to_string()));
                let fail = server_failure.lock().unwrap().as_ref().is_some_and(|oid| {
                    request
                        .varbinds
                        .iter()
                        .any(|item| item.oid.to_string().starts_with(oid))
                });
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
                let response = CommunityMessage::new(
                    message.version,
                    message.community,
                    Pdu {
                        pdu_type: PduType::Response,
                        request_id: request.request_id,
                        error_status: i32::from(fail) * 5,
                        error_index: i32::from(fail),
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
        assert_eq!(observation.fields["model"], "SCALANCE stack");
        assert_eq!(observation.fields["firmwareVersion"], "FW8.1");
        assert!(result.inventory_complete);
        assert!(result.lldp_complete);
        assert_eq!(result.interfaces[0].name.as_deref(), Some("port-1"));
        assert_eq!(
            result.interfaces[0].ip_addresses,
            ["10.10.10.1", "2001:db8::1"]
        );
        assert_eq!(result.interfaces[0].speed, Some(1_000_000_000));
        assert_eq!(result.interfaces[0].oper_status.as_deref(), Some("down"));
        assert_eq!(result.links[0].remote.mac_address, "00:01:02:03:04:05");
        assert_eq!(result.links[0].local.port_id.as_deref(), Some("port-1"));
        assert_eq!(
            result.links[0].raw["remoteManagementAddresses"][0],
            "192.0.2.2"
        );
        assert_eq!(result.ports.len(), 1);
        assert_eq!(result.ports[0].key, "bridgePort:7");
        assert_eq!(result.ports[0].vlans, [100]);
        assert_eq!(
            result.ports[0].raw["forwardingMacs"][0],
            "00:01:02:03:04:05"
        );

        let routed = query(
            "127.0.0.1",
            None,
            &settings("2c"),
            QuerySelection {
                inventory: true,
                lldp: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(routed.identity_mac.as_deref(), Some("06:07:08:09:0A:0B"));
        assert_eq!(
            routed.observation.unwrap().mac_address.as_deref(),
            Some("06:07:08:09:0A:0B")
        );

        let v1 = query(
            "127.0.0.1",
            None,
            &settings("1"),
            QuerySelection {
                inventory: true,
                lldp: false,
            },
        )
        .await
        .unwrap();
        assert_eq!(v1.identity_mac.as_deref(), Some("06:07:08:09:0A:0B"));

        let auto = Settings {
            version: Some("auto".into()),
            community: Some("public".into()),
            username: Some("inventory".into()),
            auth_protocol: Some("sha256".into()),
            ..Settings::default()
        };
        let (attempts, auto_result) = query_with_attempts(
            "127.0.0.1",
            None,
            &[auto],
            QuerySelection {
                inventory: true,
                lldp: false,
            },
        )
        .await;
        assert!(auto_result.is_ok());
        assert_eq!(
            attempts,
            [QueryAttempt {
                description: "version=2c security=community authentication=none encryption=none"
                    .into(),
                success: true,
            }]
        );

        let (multi_attempts, multi_result) = query_with_attempts(
            "127.0.0.1",
            None,
            &[
                settings("2c"),
                Settings {
                    community: Some("other".into()),
                    ..Settings::default()
                },
            ],
            QuerySelection {
                inventory: false,
                lldp: true,
            },
        )
        .await;
        assert!(multi_result.is_ok());
        assert_eq!(multi_attempts.len(), 1);
        assert!(multi_attempts[0].success);

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
        *failed_oid.lock().unwrap() = Some("1.3.6.1.2.1.2.2.1.2".into());
        let partial = query(
            "127.0.0.1",
            Some("00:11:22:33:44:55"),
            &settings("2c"),
            QuerySelection {
                inventory: true,
                lldp: false,
            },
        )
        .await
        .unwrap();
        assert!(!partial.inventory_complete);
        assert!(partial.observation.is_some());
        assert!(!partial.warnings.is_empty());
        assert!(
            !requested_oids
                .lock()
                .unwrap()
                .iter()
                .any(|oid| oid.starts_with("1.0.8802.1.1.2.1.5"))
        );

        task.abort();
    }

    #[tokio::test]
    async fn bounds_the_whole_query_time() {
        let _sink = UdpSocket::bind(("127.0.0.2", SNMP_PORT)).await.unwrap();
        let mut auto = settings("auto");
        auto.username = Some("inventory".into());
        let (attempts, result) = query_with_attempts(
            "127.0.0.2",
            None,
            &[auto],
            QuerySelection {
                inventory: false,
                lldp: true,
            },
        )
        .await;
        let Err(error) = result else {
            panic!("query unexpectedly completed")
        };

        assert!(error.to_string().contains("query exceeded"));
        assert!(error.is_no_response());
        assert_eq!(attempts.len(), 3);
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
        assert_eq!(
            value_json(&Value::ObjectIdentifier(
                Oid::parse("1.3.6.1.4.1.4329.6.3.2").unwrap()
            )),
            json!("1.3.6.1.4.1.4329.6.3.2")
        );
        assert!(value_json(&Value::Null).is_string());
        assert_eq!(table_cell("1.2", "1.2"), None);
    }
}
