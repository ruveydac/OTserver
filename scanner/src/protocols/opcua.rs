//! Read-only OPC UA asset discovery built on the `async-opcua` client stack.
//!
//! The scanner opens an unsecured (`SecurityPolicy` None) channel and asks the server which
//! endpoints and user token policies it supports via `GetEndpoints`. It only activates a session
//! when the server offers anonymous access, or username access with explicitly configured
//! credentials; certificate authentication is never attempted. Asset identity is resolved through
//! the standardized `Objects/Aliases/Assets` alias categories with the read-only `FindAlias`
//! method, falling back to the OPC UA DI `DeviceSet` when no aliases exist. Only the
//! identification, revision, health, location, documentation, and counter variables named by the
//! OPC UA asset model are read, in one bounded batch. The scanner never writes values, never
//! calls mutating methods, and never walks the full node tree.

use super::{Finding, port};
use crate::contract::Source;
use opcua::client::{Client, ClientBuilder, IdentityToken, Session};
use opcua::crypto::SecurityPolicy;
use opcua::types::{
    AliasNameDataType, AttributeId, BrowseDescription, BrowseDirection, CallMethodRequest,
    EndpointDescription, Error as UaError, ExtensionObject, MessageSecurityMode, NodeClass, NodeId,
    NumericRange, ObjectId, QualifiedName, ReadValueId, ReferenceTypeId, StatusCode,
    TimeZoneDataType, TimestampsToReturn, UAString, UserTokenType, Variant,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::time::timeout;

pub const DEFAULT_PORTS: [u16; 3] = [4840, 4841, 48_400];
const ENDPOINTS_TIMEOUT: Duration = Duration::from_secs(4);
const SESSION_TIMEOUT: Duration = Duration::from_secs(5);
const SERVICE_TIMEOUT: Duration = Duration::from_secs(4);
const PORT_PAUSE: Duration = Duration::from_millis(250);
const MAX_CATEGORY_CALLS: usize = 4;
const MAX_ASSETS: usize = 8;
const MAX_CHILDREN: u32 = 64;
const MAX_READS: usize = 64;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Credential {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Credentials {
    Single(Credential),
    Multiple(Vec<Credential>),
}

impl Credentials {
    pub fn credentials(&self) -> Vec<Credential> {
        match self {
            Self::Single(credential) => vec![credential.clone()],
            Self::Multiple(credentials) => credentials.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProbeSettings {
    pub ports: Vec<u16>,
    pub credentials: Vec<Credential>,
}

impl ProbeSettings {
    pub fn ports_or_default(ports: Option<Vec<u16>>) -> Vec<u16> {
        match ports {
            Some(ports) if !ports.is_empty() => ports,
            _ => DEFAULT_PORTS.to_vec(),
        }
    }
}

fn build_client() -> Result<Client, String> {
    ClientBuilder::new()
        .application_name("OTserver Scanner")
        .application_uri("urn:otserver:scanner")
        .product_uri("urn:otserver:scanner:product")
        .session_name("OTserver Scanner")
        .session_retry_limit(0)
        .request_timeout(Duration::from_secs(3))
        .client()
        .map_err(|errors| format!("OPC UA client configuration failed: {}", errors.join(", ")))
}

pub async fn probe(target: Ipv4Addr, settings: &ProbeSettings) -> Result<Option<Finding>, String> {
    let ports = if settings.ports.is_empty() {
        DEFAULT_PORTS.as_slice()
    } else {
        settings.ports.as_slice()
    };
    let mut client = build_client()?;
    for (index, port_number) in ports.iter().enumerate() {
        if index > 0 {
            tokio::time::sleep(PORT_PAUSE).await;
        }
        if let Some(finding) = probe_port(&mut client, target, *port_number, settings).await? {
            return Ok(Some(finding));
        }
    }
    Ok(None)
}

async fn probe_port(
    client: &mut Client,
    target: Ipv4Addr,
    port_number: u16,
    settings: &ProbeSettings,
) -> Result<Option<Finding>, String> {
    let url = format!("opc.tcp://{target}:{port_number}");

    // Slow presence check: GetEndpoints performs the HEL/ACK handshake, opens an unsecured
    // channel, and enumerates the endpoints with their user token policies.
    let endpoints = match timeout(
        ENDPOINTS_TIMEOUT,
        client.get_endpoints(url.as_str(), &[], &[]),
    )
    .await
    {
        Ok(Ok(endpoints)) => endpoints,
        Ok(Err(error)) => return Ok(endpoint_failure_finding(&url, port_number, error)),
        Err(_) => return Ok(None),
    };
    if endpoints.is_empty() {
        return Ok(None);
    }

    let mut raw = Map::new();
    let mut warnings = Vec::new();
    let server = &endpoints[0].server;
    raw.insert(
        "applicationUri".into(),
        json!(server.application_uri.as_ref()),
    );
    raw.insert("productUri".into(), json!(server.product_uri.as_ref()));
    raw.insert(
        "applicationName".into(),
        json!(server.application_name.text.as_ref()),
    );
    raw.insert("userTokenPolicies".into(), json!(token_labels(&endpoints)));

    // Anonymous access is always tried first; the configured credentials are only
    // used, in order, when it fails and the server supports username authentication.
    let username_supported = has_policy(&endpoints, UserTokenType::UserName);
    let anonymous_supported = has_policy(&endpoints, UserTokenType::Anonymous);
    let mut attempts = Vec::new();
    if anonymous_supported {
        attempts.push(IdentityToken::Anonymous);
    }
    if username_supported {
        for credential in &settings.credentials {
            let username = credential
                .username
                .as_deref()
                .filter(|value| !value.is_empty());
            let password = credential
                .password
                .as_deref()
                .filter(|value| !value.is_empty());
            if let (Some(username), Some(password)) = (username, password) {
                attempts.push(IdentityToken::UserName(
                    username.to_owned(),
                    password.to_owned().into(),
                ));
            }
        }
    }
    if attempts.is_empty() {
        let supported = token_labels(&endpoints).join(", ");
        warnings.push(format!(
            "OPC UA server offers no usable authentication (supported: {supported}); configure opcuaCredentials with a username and password for username authentication."
        ));
        return Ok(Some(finding(
            &url,
            port_number,
            base_fields(),
            raw,
            warnings,
        )));
    }

    // The scanner only uses unsecured channels. The endpoint a server advertises may carry a
    // hostname that is unreachable from the scanned address, so the client substitutes the host
    // it actually connected to.
    let Some(endpoint) = Client::find_matching_endpoint(
        &endpoints,
        &url,
        SecurityPolicy::None,
        MessageSecurityMode::None,
    ) else {
        warnings.push(
            "OPC UA server offers no endpoint with SecurityPolicy None; asset details were not read."
                .into(),
        );
        return Ok(Some(finding(
            &url,
            port_number,
            base_fields(),
            raw,
            warnings,
        )));
    };

    let mut connected_pair = None;
    for identity in attempts {
        if matches!(identity, IdentityToken::UserName(_, _)) {
            warnings.push(
                "OPC UA username credentials are transmitted over an unencrypted channel because SecurityPolicy None is used."
                    .into(),
            );
        }
        let (session, event_loop) = match timeout(
            SESSION_TIMEOUT,
            client.connect_to_matching_endpoint(endpoint.clone(), identity),
        )
        .await
        {
            Ok(Ok(pair)) => pair,
            Ok(Err(error)) => {
                warnings.push(format!("OPC UA session: {error}"));
                continue;
            }
            Err(_) => {
                warnings.push("OPC UA session establishment timed out.".into());
                continue;
            }
        };
        let handle = event_loop.spawn();
        let connected = timeout(SESSION_TIMEOUT, session.wait_for_connection())
            .await
            .unwrap_or(false);
        if connected {
            connected_pair = Some((session, handle));
            break;
        }
        warnings.push("OPC UA session could not be established.".into());
        handle.abort();
    }
    let Some((session, handle)) = connected_pair else {
        return Ok(Some(finding(
            &url,
            port_number,
            base_fields(),
            raw,
            warnings,
        )));
    };
    let abort_handle = handle.abort_handle();

    let mut fields = base_fields();
    match collect_assets(&session, &mut warnings).await {
        Ok((asset_fields, assets)) => {
            fields.extend(asset_fields);
            raw.insert("assets".into(), Value::Array(assets));
        }
        Err(error) => warnings.push(format!("OPC UA asset discovery: {error}")),
    }

    let _ = timeout(Duration::from_secs(2), session.disconnect()).await;
    drop(session);
    if timeout(Duration::from_secs(1), handle).await.is_err() {
        abort_handle.abort();
    }
    Ok(Some(finding(&url, port_number, fields, raw, warnings)))
}

fn endpoint_failure_finding(url: &str, port_number: u16, error: UaError) -> Option<Finding> {
    let status = error.status();
    let absent = matches!(
        status,
        StatusCode::BadCommunicationError
            | StatusCode::BadNoCommunication
            | StatusCode::BadNotConnected
            | StatusCode::BadConnectionRejected
            | StatusCode::BadConnectionClosed
            | StatusCode::BadTimeout
    );
    if absent {
        return None;
    }
    Some(finding(
        url,
        port_number,
        base_fields(),
        Map::new(),
        vec![format!("OPC UA endpoint query failed: {status}")],
    ))
}

fn has_policy(endpoints: &[EndpointDescription], token_type: UserTokenType) -> bool {
    endpoints
        .iter()
        .any(|endpoint| endpoint.find_policy(token_type).is_some())
}

fn token_labels(endpoints: &[EndpointDescription]) -> Vec<String> {
    let mut labels: Vec<String> = endpoints
        .iter()
        .filter_map(|endpoint| endpoint.user_identity_tokens.as_ref())
        .flatten()
        .map(|policy| match policy.token_type {
            UserTokenType::Anonymous => "anonymous".to_string(),
            UserTokenType::UserName => "username".to_string(),
            UserTokenType::Certificate => "certificate".to_string(),
            _ => "issued-token".to_string(),
        })
        .collect();
    labels.sort();
    labels.dedup();
    labels
}

#[derive(Clone, Debug)]
struct Reference {
    node: NodeId,
    browse_name: String,
    display_name: String,
    node_class: NodeClass,
}

async fn browse_children(session: &Session, node: &NodeId) -> Result<Vec<Reference>, String> {
    let description = BrowseDescription {
        node_id: node.clone(),
        browse_direction: BrowseDirection::Forward,
        reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
        include_subtypes: true,
        node_class_mask: 0,
        result_mask: 63,
    };
    let results = timeout(
        SERVICE_TIMEOUT,
        session.browse(&[description], MAX_CHILDREN, None),
    )
    .await
    .map_err(|_| "OPC UA browse timed out".to_string())?
    .map_err(|error| format!("OPC UA browse: {error}"))?;
    let Some(result) = results.into_iter().next() else {
        return Ok(Vec::new());
    };
    if result.status_code.is_bad() {
        return Err(format!("OPC UA browse failed: {}", result.status_code));
    }
    if !result.continuation_point.is_null() {
        return Err("OPC UA browse continuation points are not followed".into());
    }
    Ok(result
        .references
        .unwrap_or_default()
        .into_iter()
        .map(|reference| Reference {
            node: reference.node_id.node_id,
            browse_name: reference.browse_name.name.as_ref().to_string(),
            display_name: reference.display_name.text.as_ref().to_string(),
            node_class: reference.node_class,
        })
        .collect())
}

async fn find_alias(
    session: &Session,
    category: &NodeId,
    method: &NodeId,
) -> Result<Vec<NodeId>, String> {
    let request = CallMethodRequest {
        object_id: category.clone(),
        method_id: method.clone(),
        input_arguments: Some(vec![Variant::String(UAString::from(""))]),
    };
    let result = timeout(SERVICE_TIMEOUT, session.call_one(request))
        .await
        .map_err(|_| "OPC UA FindAlias timed out".to_string())?
        .map_err(|error| format!("OPC UA FindAlias: {error}"))?;
    if result.status_code.is_bad() {
        return Err(format!("OPC UA FindAlias failed: {}", result.status_code));
    }
    let mut nodes = Vec::new();
    for argument in result.output_arguments.unwrap_or_default() {
        let Variant::Array(array) = argument else {
            continue;
        };
        for value in &array.values {
            let Variant::ExtensionObject(object) = value else {
                continue;
            };
            let Some(alias) = object.inner_as::<AliasNameDataType>() else {
                continue;
            };
            for referenced in alias.referenced_nodes.clone().unwrap_or_default() {
                nodes.push(referenced.node_id);
            }
        }
    }
    Ok(nodes)
}

const IDENTIFICATION_KEYS: [&str; 11] = [
    "ProductInstanceUri",
    "Manufacturer",
    "Model",
    "SerialNumber",
    "AssetId",
    "DeviceClass",
    "HardwareRevision",
    "SoftwareRevision",
    "RevisionCounter",
    "PatchIdentifiers",
    "DeviceHealth",
];

const LOCATION_KEYS: [&str; 4] = [
    "HierarchicalLocation",
    "OperationalLocation",
    "DigitalLocation",
    "LocalTime",
];

const DEVICE_HEALTH_LABELS: [&str; 5] = [
    "NORMAL",
    "FAILURE",
    "CHECK_FUNCTION",
    "OFF_SPEC",
    "MAINTENANCE_REQUIRED",
];

struct ReadTarget {
    node: NodeId,
    key: String,
    section: String,
}

struct AssetEntry {
    node_id: NodeId,
    display_name: String,
    identification: Map<String, Value>,
    locations: Map<String, Value>,
    documentation_links: Vec<Value>,
    operation_counters: Map<String, Value>,
    health: Option<u32>,
    health_timestamp: Option<String>,
}

fn find_reference<'a>(references: &'a [Reference], name: &str) -> Option<&'a Reference> {
    references
        .iter()
        .find(|reference| reference.browse_name == name)
}

async fn collect_asset(
    session: &Session,
    node: &NodeId,
    display_name: &str,
) -> Result<AssetEntry, String> {
    let references = browse_children(session, node).await?;
    let mut targets = Vec::new();
    for reference in references.iter().take(MAX_CHILDREN as usize) {
        if reference.node_class == NodeClass::Variable {
            if IDENTIFICATION_KEYS.contains(&reference.browse_name.as_str()) {
                targets.push(ReadTarget {
                    node: reference.node.clone(),
                    key: reference.browse_name.clone(),
                    section: "identification".into(),
                });
            } else if LOCATION_KEYS.contains(&reference.browse_name.as_str()) {
                targets.push(ReadTarget {
                    node: reference.node.clone(),
                    key: reference.browse_name.clone(),
                    section: "location".into(),
                });
            }
        }
    }
    if let Some(group) = find_reference(&references, "Identification") {
        for reference in browse_children(session, &group.node)
            .await?
            .into_iter()
            .take(MAX_CHILDREN as usize)
        {
            if reference.node_class == NodeClass::Variable
                && IDENTIFICATION_KEYS.contains(&reference.browse_name.as_str())
                && !targets
                    .iter()
                    .any(|target| target.key == reference.browse_name)
            {
                targets.push(ReadTarget {
                    node: reference.node,
                    key: reference.browse_name,
                    section: "identification".into(),
                });
            }
        }
    }
    if let Some(links) = find_reference(&references, "DocumentationLinks") {
        for reference in browse_children(session, &links.node)
            .await?
            .into_iter()
            .take(8)
        {
            if reference.node_class == NodeClass::Variable {
                targets.push(ReadTarget {
                    node: reference.node,
                    key: reference.browse_name,
                    section: "documentation".into(),
                });
            }
        }
    }
    if let Some(counters) = find_reference(&references, "OperationCounters") {
        for reference in browse_children(session, &counters.node)
            .await?
            .into_iter()
            .take(8)
        {
            if reference.node_class == NodeClass::Variable {
                targets.push(ReadTarget {
                    node: reference.node,
                    key: reference.browse_name,
                    section: "counters".into(),
                });
            }
        }
    }
    targets.truncate(MAX_READS);
    let mut entry = AssetEntry {
        node_id: node.clone(),
        display_name: display_name.to_owned(),
        identification: Map::new(),
        locations: Map::new(),
        documentation_links: Vec::new(),
        operation_counters: Map::new(),
        health: None,
        health_timestamp: None,
    };
    if targets.is_empty() {
        return Ok(entry);
    }
    let reads: Vec<ReadValueId> = targets
        .iter()
        .map(|target| ReadValueId {
            node_id: target.node.clone(),
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
            data_encoding: QualifiedName::null(),
        })
        .collect();
    let values = timeout(
        SERVICE_TIMEOUT,
        session.read(&reads, TimestampsToReturn::Source, 0.0),
    )
    .await
    .map_err(|_| "OPC UA read timed out".to_string())?
    .map_err(|error| format!("OPC UA read: {error}"))?;
    if values.len() != targets.len() {
        return Err("OPC UA read result count mismatch".into());
    }
    for (target, value) in targets.iter().zip(values) {
        if value.status.is_some_and(|status| status.is_bad()) {
            continue;
        }
        let Some(variant) = &value.value else {
            continue;
        };
        let read = variant_to_value(variant);
        match target.section.as_str() {
            "identification" => {
                if target.key == "DeviceHealth"
                    && let Some(code) = read.as_u64()
                {
                    entry.health = Some(code as u32);
                    entry.health_timestamp = value
                        .source_timestamp
                        .map(|timestamp| timestamp.as_chrono().to_rfc3339());
                }
                entry.identification.insert(target.key.clone(), read);
            }
            "location" => {
                entry.locations.insert(target.key.clone(), read);
            }
            "documentation" => entry.documentation_links.push(read),
            _ => {
                entry.operation_counters.insert(target.key.clone(), read);
            }
        }
    }
    Ok(entry)
}

async fn collect_assets(
    session: &Session,
    warnings: &mut Vec<String>,
) -> Result<(BTreeMap<String, Value>, Vec<Value>), String> {
    let objects = browse_children(session, &ObjectId::ObjectsFolder.into()).await?;
    let aliases = find_reference(&objects, "Aliases").map(|reference| reference.node.clone());
    let device_set = find_reference(&objects, "DeviceSet").map(|reference| reference.node.clone());

    let mut asset_nodes: Vec<(NodeId, String)> = Vec::new();
    if let Some(aliases) = aliases {
        let children = browse_children(session, &aliases).await?;
        let mut candidates = Vec::new();
        match find_reference(&children, "Assets") {
            Some(assets) => {
                candidates.push(assets.node.clone());
                candidates.extend(
                    browse_children(session, &assets.node)
                        .await?
                        .into_iter()
                        .map(|reference| reference.node),
                );
            }
            None => candidates.extend(children.iter().map(|reference| reference.node.clone())),
        }
        for candidate in candidates.into_iter().take(MAX_CATEGORY_CALLS) {
            let members = match browse_children(session, &candidate).await {
                Ok(members) => members,
                Err(error) => {
                    warnings.push(format!("OPC UA alias category browse: {error}"));
                    continue;
                }
            };
            let Some(method) = members
                .iter()
                .find(|reference| {
                    reference.browse_name == "FindAlias"
                        && reference.node_class == NodeClass::Method
                })
                .map(|reference| reference.node.clone())
            else {
                continue;
            };
            match find_alias(session, &candidate, &method).await {
                Ok(found) => {
                    for node in found {
                        if !asset_nodes.iter().any(|(existing, _)| *existing == node) {
                            asset_nodes.push((node, String::new()));
                        }
                    }
                }
                Err(error) => warnings.push(format!("OPC UA FindAlias: {error}")),
            }
        }
    }
    if asset_nodes.is_empty()
        && let Some(device_set) = device_set
    {
        for reference in browse_children(session, &device_set).await? {
            if reference.node_class == NodeClass::Object {
                asset_nodes.push((reference.node, reference.display_name));
            }
        }
    }
    if asset_nodes.is_empty() {
        warnings.push(
            "OPC UA server exposes no asset entry points under Aliases/Assets or DeviceSet.".into(),
        );
        return Ok((BTreeMap::new(), Vec::new()));
    }
    asset_nodes.truncate(MAX_ASSETS);

    let mut entries = Vec::new();
    for (node, display_name) in asset_nodes {
        match collect_asset(session, &node, &display_name).await {
            Ok(entry) => entries.push(entry),
            Err(error) => warnings.push(format!("OPC UA asset {node}: {error}")),
        }
    }
    let fields = asset_fields(&entries);
    let raw = entries.iter().map(asset_raw).collect();
    Ok((fields, raw))
}

fn variant_to_value(variant: &Variant) -> Value {
    match variant {
        Variant::Empty => Value::Null,
        Variant::Boolean(value) => json!(value),
        Variant::SByte(value) => json!(value),
        Variant::Byte(value) => json!(value),
        Variant::Int16(value) => json!(value),
        Variant::UInt16(value) => json!(value),
        Variant::Int32(value) => json!(value),
        Variant::UInt32(value) => json!(value),
        Variant::Int64(value) => json!(value),
        Variant::UInt64(value) => json!(value),
        Variant::Float(value) => json!(value),
        Variant::Double(value) => json!(value),
        Variant::String(value) => json!(value.as_ref()),
        Variant::DateTime(value) => json!(value.as_chrono().to_rfc3339()),
        Variant::Guid(value) => json!(value.to_string()),
        Variant::ByteString(value) => json!(super::hex(value.as_ref())),
        Variant::QualifiedName(value) => json!(value.name.as_ref()),
        Variant::LocalizedText(value) => json!(value.text.as_ref()),
        Variant::NodeId(value) => json!(value.to_string()),
        Variant::ExpandedNodeId(value) => json!(value.node_id.to_string()),
        Variant::StatusCode(value) => json!(format!("{value}")),
        Variant::ExtensionObject(value) => extension_object_value(value),
        Variant::Array(array) => Value::Array(array.values.iter().map(variant_to_value).collect()),
        _ => Value::Null,
    }
}

fn extension_object_value(object: &ExtensionObject) -> Value {
    if let Some(local_time) = object.inner_as::<TimeZoneDataType>() {
        return json!({
            "offsetMinutes": local_time.offset,
            "daylightSavingInOffset": local_time.daylight_saving_in_offset,
        });
    }
    Value::Null
}

fn text_of(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            let text = text.trim();
            (!text.is_empty()).then(|| text.to_owned())
        }
        _ => None,
    }
}

fn insert_once(fields: &mut BTreeMap<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value
        && !fields.contains_key(key)
    {
        fields.insert(key.to_string(), json!(value));
    }
}

fn asset_fields(entries: &[AssetEntry]) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    for entry in entries {
        let identification = &entry.identification;
        let asset_id = identification.get("AssetId").and_then(text_of);
        let product_uri = identification.get("ProductInstanceUri").and_then(text_of);
        insert_once(
            &mut fields,
            "name",
            asset_id
                .or_else(|| (!entry.display_name.is_empty()).then(|| entry.display_name.clone()))
                .or(product_uri),
        );
        insert_once(
            &mut fields,
            "vendor",
            identification.get("Manufacturer").and_then(text_of),
        );
        insert_once(
            &mut fields,
            "model",
            identification.get("Model").and_then(text_of),
        );
        insert_once(
            &mut fields,
            "serialNumber",
            identification.get("SerialNumber").and_then(text_of),
        );
        insert_once(
            &mut fields,
            "firmwareVersion",
            identification.get("SoftwareRevision").and_then(text_of),
        );
        insert_once(
            &mut fields,
            "description",
            identification.get("DeviceClass").and_then(text_of),
        );
        insert_once(
            &mut fields,
            "location",
            entry
                .locations
                .get("HierarchicalLocation")
                .and_then(text_of)
                .or_else(|| entry.locations.get("OperationalLocation").and_then(text_of)),
        );
        if let Some(code) = entry.health {
            let status = match code {
                0 => "online",
                1 => "offline",
                4 => "maintenance",
                _ => "unknown",
            };
            insert_once(&mut fields, "status", Some(status.to_string()));
        }
    }
    fields
}

fn asset_raw(entry: &AssetEntry) -> Value {
    let health = entry.health.map(|code| {
        json!({
            "code": code,
            "label": DEVICE_HEALTH_LABELS
                .get(code as usize)
                .copied()
                .unwrap_or("UNKNOWN"),
            "sourceTimestamp": entry.health_timestamp,
        })
    });
    json!({
        "nodeId": entry.node_id.to_string(),
        "displayName": entry.display_name,
        "identification": entry.identification,
        "locations": entry.locations,
        "deviceHealth": health,
        "documentationLinks": entry.documentation_links,
        "operationCounters": entry.operation_counters,
    })
}

fn base_fields() -> BTreeMap<String, Value> {
    BTreeMap::from([("protocols".into(), json!(["opc-ua"]))])
}

fn finding(
    endpoint_url: &str,
    port_number: u16,
    fields: BTreeMap<String, Value>,
    mut raw: Map<String, Value>,
    warnings: Vec<String>,
) -> Finding {
    raw.insert("endpointUrl".into(), json!(endpoint_url));
    Finding {
        source: Source::OpcUa,
        fields,
        ports: vec![port(
            "tcp",
            port_number,
            Source::OpcUa,
            json!({ "state": "open" }),
        )],
        raw: Value::Object(raw),
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua::server::{
        ServerBuilder, ServerEndpoint, ServerUserToken,
        address_space::{AddressSpace, MethodBuilder, ObjectBuilder, VariableBuilder},
        diagnostics::NamespaceMetadata,
        node_manager::memory::{InMemoryNodeManager, SimpleNodeManagerImpl, simple_node_manager},
    };
    use opcua::types::{
        AccessRestrictionType, Array, DataTypeId, ExpandedNodeId, LocalizedText,
        VariantScalarTypeId, argument::Argument,
    };
    use tokio::net::TcpListener;

    #[test]
    fn resolves_ports_or_default() {
        assert_eq!(ProbeSettings::ports_or_default(None), DEFAULT_PORTS);
        assert_eq!(ProbeSettings::ports_or_default(Some(vec![])), DEFAULT_PORTS);
        assert_eq!(
            ProbeSettings::ports_or_default(Some(vec![4841])),
            vec![4841]
        );
    }

    #[test]
    fn converts_variants_to_json() {
        assert_eq!(variant_to_value(&Variant::Empty), Value::Null);
        assert_eq!(variant_to_value(&Variant::Boolean(true)), json!(true));
        assert_eq!(variant_to_value(&Variant::Int32(-7)), json!(-7));
        assert_eq!(variant_to_value(&Variant::Double(1.5)), json!(1.5));
        assert_eq!(
            variant_to_value(&Variant::String(UAString::from("text"))),
            json!("text")
        );
        assert_eq!(
            variant_to_value(&Variant::LocalizedText(Box::new(LocalizedText::from(
                "label"
            )))),
            json!("label")
        );
        let array = Variant::Array(Box::new(Array {
            value_type: VariantScalarTypeId::String,
            values: vec![
                Variant::String(UAString::from("a")),
                Variant::String(UAString::from("b")),
            ],
            dimensions: None,
        }));
        assert_eq!(variant_to_value(&array), json!(["a", "b"]));
        let local_time = TimeZoneDataType {
            offset: 120,
            daylight_saving_in_offset: true,
        };
        let object = ExtensionObject::from_message(local_time);
        assert_eq!(
            variant_to_value(&Variant::ExtensionObject(object)),
            json!({ "offsetMinutes": 120, "daylightSavingInOffset": true })
        );
    }

    #[test]
    fn maps_asset_fields_with_first_value_priority() {
        let mut identification = Map::new();
        identification.insert("AssetId".into(), json!("LAB-ASSET-1"));
        identification.insert("Manufacturer".into(), json!("Lab Manufacturer"));
        identification.insert("DeviceHealth".into(), json!(4));
        let mut locations = Map::new();
        locations.insert("HierarchicalLocation".into(), json!("Plant1/Line3"));
        let first = AssetEntry {
            node_id: NodeId::new(2, 300),
            display_name: "First".into(),
            identification,
            locations,
            documentation_links: vec![],
            operation_counters: Map::new(),
            health: Some(4),
            health_timestamp: None,
        };
        let mut identification = Map::new();
        identification.insert("Model".into(), json!("Lab Model 42"));
        identification.insert("AssetId".into(), json!("ignored"));
        let second = AssetEntry {
            node_id: NodeId::new(1, 301),
            display_name: "Second".into(),
            identification,
            locations: Map::new(),
            documentation_links: vec![],
            operation_counters: Map::new(),
            health: None,
            health_timestamp: None,
        };
        let fields = asset_fields(&[first, second]);
        assert_eq!(fields["name"], "LAB-ASSET-1");
        assert_eq!(fields["vendor"], "Lab Manufacturer");
        assert_eq!(fields["model"], "Lab Model 42");
        assert_eq!(fields["location"], "Plant1/Line3");
        assert_eq!(fields["status"], "maintenance");

        let raw = asset_raw(&AssetEntry {
            node_id: NodeId::new(2, 300),
            display_name: "First".into(),
            identification: Map::new(),
            locations: Map::new(),
            documentation_links: vec![json!("https://example.test")],
            operation_counters: Map::from_iter([("OperatingHours".into(), json!(12.5))]),
            health: Some(1),
            health_timestamp: Some("2026-08-16T00:00:00Z".into()),
        });
        assert_eq!(raw["deviceHealth"]["label"], "FAILURE");
        assert_eq!(raw["operationCounters"]["OperatingHours"], 12.5);
    }

    #[test]
    fn token_labels_are_sorted_and_deduplicated() {
        let endpoint = EndpointDescription::from((
            "opc.tcp://lab:4840",
            "None",
            MessageSecurityMode::None,
            opcua::types::UserTokenPolicy::anonymous(),
        ));
        assert_eq!(token_labels(&[endpoint]), vec!["anonymous"]);
        assert_eq!(token_labels(&[]), Vec::<String>::new());
    }

    #[tokio::test]
    async fn refused_ports_return_none() {
        let settings = ProbeSettings {
            ports: vec![1], // port 1 refuses connections on loopback
            ..ProbeSettings::default()
        };
        assert!(
            probe(Ipv4Addr::LOCALHOST, &settings)
                .await
                .unwrap()
                .is_none()
        );
    }

    // ------------------------------------------------------------------
    // In-process OPC UA server for end-to-end probe tests.
    // ------------------------------------------------------------------

    struct LabServer {
        port: u16,
        _task: tokio::task::JoinHandle<()>,
    }

    struct LabConfig {
        username: bool,
        aliases: bool,
        require_username: bool,
    }

    fn namespace_metadata(index: u16, uri: &str) -> NamespaceMetadata {
        NamespaceMetadata {
            default_access_restrictions: AccessRestrictionType::empty(),
            default_role_permissions: None,
            default_user_role_permissions: None,
            is_namespace_subset: None,
            namespace_publication_date: None,
            namespace_uri: uri.to_string(),
            namespace_version: None,
            static_node_id_types: None,
            static_numeric_node_id_range: None,
            static_string_node_id_pattern: None,
            namespace_index: index,
        }
    }

    fn add_variables(space: &mut AddressSpace, ns: u16) {
        let identification = NodeId::new(ns, 310);
        let string: NodeId = DataTypeId::String.into();
        let localized: NodeId = DataTypeId::LocalizedText.into();
        let int32: NodeId = DataTypeId::Int32.into();
        let double: NodeId = DataTypeId::Double.into();
        let variables: Vec<(u32, &str, NodeId, Variant, NodeId)> = vec![
            (
                301,
                "AssetId",
                NodeId::new(ns, 300),
                "LAB-ASSET-1".into(),
                string.clone(),
            ),
            (
                311,
                "Manufacturer",
                identification.clone(),
                LocalizedText::from("Lab Manufacturer").into(),
                localized.clone(),
            ),
            (
                312,
                "Model",
                identification.clone(),
                LocalizedText::from("Lab Model 42").into(),
                localized,
            ),
            (
                313,
                "SerialNumber",
                identification.clone(),
                "SN12345".into(),
                string.clone(),
            ),
            (
                314,
                "SoftwareRevision",
                identification.clone(),
                "2.1.0".into(),
                string.clone(),
            ),
            (
                315,
                "DeviceClass",
                identification.clone(),
                "Test Device".into(),
                string.clone(),
            ),
            (
                316,
                "ProductInstanceUri",
                identification.clone(),
                "urn:lab:device:SN12345".into(),
                string.clone(),
            ),
            (
                317,
                "DeviceHealth",
                identification.clone(),
                Variant::Int32(0),
                int32,
            ),
            (
                318,
                "HardwareRevision",
                identification,
                "A1".into(),
                string.clone(),
            ),
            (
                320,
                "HierarchicalLocation",
                NodeId::new(ns, 300),
                "Plant1/Line3/Cell2".into(),
                string.clone(),
            ),
            (
                331,
                "Manual",
                NodeId::new(ns, 330),
                "https://example.test/manual.pdf".into(),
                string,
            ),
            (
                341,
                "OperatingHours",
                NodeId::new(ns, 340),
                Variant::Double(1234.5),
                double,
            ),
        ];
        for (id, name, parent, value, data_type) in variables {
            VariableBuilder::new(&NodeId::new(ns, id), name, name)
                .value(value)
                .data_type(data_type)
                .component_of(parent.clone())
                .insert(space);
        }
    }

    async fn spawn_lab_server(config: LabConfig) -> LabServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let lab_namespace = namespace_metadata(2, "urn:otserver:lab:opcua");
        let mut builder = ServerBuilder::new()
            .application_name("OT Lab OPC UA Server")
            .application_uri("urn:otserver:lab:opcua:server")
            .product_uri("urn:otserver:lab:opcua:product")
            .host("127.0.0.1")
            .port(port)
            .discovery_urls(vec!["/".to_owned()])
            .with_node_manager(simple_node_manager(lab_namespace, "lab"));
        let token_ids = if config.require_username {
            vec!["lab-user-token".to_string()]
        } else {
            let mut ids = vec![opcua::client::ANONYMOUS_USER_TOKEN_ID.to_string()];
            if config.username {
                ids.push("lab-user-token".to_string());
            }
            ids
        };
        builder = builder.add_endpoint("none", ServerEndpoint::new_none("/", &token_ids));
        if config.username || config.require_username {
            builder = builder.add_user_token(
                "lab-user-token",
                ServerUserToken::user_pass("lab-user", "lab-password"),
            );
        }
        let (server, handle) = builder.build().unwrap();

        let manager = handle
            .node_managers()
            .get_of_type::<InMemoryNodeManager<SimpleNodeManagerImpl>>()
            .unwrap();
        let ns = 2u16;
        {
            let mut space = manager.address_space().write();
            space.add_namespace("urn:otserver:lab:opcua", ns);
            // Extend the standard Objects/Aliases category (i=23470) with an Assets category,
            // mirroring the OPC UA asset management companion specification layout.
            ObjectBuilder::new(&NodeId::new(ns, 110), "Assets", "Assets")
                .organized_by(NodeId::new(0, 23470))
                .insert(&mut *space);
            ObjectBuilder::new(&NodeId::new(ns, 111), "AssetsByAssetId", "AssetsByAssetId")
                .organized_by(NodeId::new(ns, 110))
                .insert(&mut *space);
            space.add_folder(
                &NodeId::new(ns, 200),
                "DeviceSet",
                "DeviceSet",
                &ObjectId::ObjectsFolder.into(),
            );
            if config.aliases {
                MethodBuilder::new(&NodeId::new(ns, 121), "FindAlias", "FindAlias")
                    .component_of(NodeId::new(ns, 111))
                    .input_args(
                        &mut *space,
                        &NodeId::new(ns, 122),
                        &[Argument::from((
                            "AliasNameSearchPattern",
                            DataTypeId::String,
                        ))],
                    )
                    .insert(&mut *space);
            }
            ObjectBuilder::new(&NodeId::new(ns, 300), "LabAsset", "OT Lab Asset")
                .organized_by(NodeId::new(ns, 200))
                .insert(&mut *space);
            ObjectBuilder::new(&NodeId::new(ns, 310), "Identification", "Identification")
                .component_of(NodeId::new(ns, 300))
                .insert(&mut *space);
            ObjectBuilder::new(
                &NodeId::new(ns, 330),
                "DocumentationLinks",
                "DocumentationLinks",
            )
            .component_of(NodeId::new(ns, 300))
            .insert(&mut *space);
            ObjectBuilder::new(
                &NodeId::new(ns, 340),
                "OperationCounters",
                "OperationCounters",
            )
            .component_of(NodeId::new(ns, 300))
            .insert(&mut *space);
            add_variables(&mut space, ns);
        }
        if config.aliases {
            manager
                .inner()
                .add_method_callback(NodeId::new(ns, 121), move |_| {
                    let alias = AliasNameDataType {
                        alias_name: QualifiedName::new(ns, "LAB-ASSET-1"),
                        referenced_nodes: Some(vec![ExpandedNodeId {
                            node_id: NodeId::new(ns, 300),
                            namespace_uri: UAString::null(),
                            server_index: 0,
                        }]),
                    };
                    let array = Variant::Array(Box::new(Array {
                        value_type: VariantScalarTypeId::ExtensionObject,
                        values: vec![Variant::ExtensionObject(ExtensionObject::from_message(
                            alias,
                        ))],
                        dimensions: None,
                    }));
                    Ok(vec![array])
                });
        }

        let task = tokio::spawn(async move {
            let _ = server.run_with(listener).await;
        });
        // Give the server a moment to start accepting connections.
        tokio::time::sleep(Duration::from_millis(200)).await;
        LabServer { port, _task: task }
    }

    fn settings_for(server: &LabServer) -> ProbeSettings {
        ProbeSettings {
            ports: vec![server.port],
            ..ProbeSettings::default()
        }
    }

    #[tokio::test]
    async fn find_alias_resolves_referenced_nodes() {
        let server = spawn_lab_server(LabConfig {
            username: false,
            aliases: true,
            require_username: false,
        })
        .await;
        let mut client = build_client().unwrap();
        let url = format!("opc.tcp://127.0.0.1:{}", server.port);
        let endpoints = client.get_endpoints(url.as_str(), &[], &[]).await.unwrap();
        let endpoint = Client::find_matching_endpoint(
            &endpoints,
            &url,
            SecurityPolicy::None,
            MessageSecurityMode::None,
        )
        .unwrap();
        let (session, event_loop) = client
            .connect_to_matching_endpoint(endpoint, IdentityToken::Anonymous)
            .await
            .unwrap();
        let handle = event_loop.spawn();
        session.wait_for_connection().await;
        let nodes = find_alias(&session, &NodeId::new(2, 111), &NodeId::new(2, 121))
            .await
            .unwrap();
        assert_eq!(nodes, vec![NodeId::new(2, 300)]);
        let _ = session.disconnect().await;
        handle.abort();
    }

    #[tokio::test]
    async fn probes_opcua_asset_identity_anonymously() {
        let server = spawn_lab_server(LabConfig {
            username: true,
            aliases: true,
            require_username: false,
        })
        .await;
        let finding = probe(Ipv4Addr::LOCALHOST, &settings_for(&server))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finding.fields["protocols"], json!(["opc-ua"]));
        assert_eq!(finding.fields["name"], "LAB-ASSET-1");
        assert_eq!(finding.fields["vendor"], "Lab Manufacturer");
        assert_eq!(finding.fields["model"], "Lab Model 42");
        assert_eq!(finding.fields["serialNumber"], "SN12345");
        assert_eq!(finding.fields["firmwareVersion"], "2.1.0");
        assert_eq!(finding.fields["location"], "Plant1/Line3/Cell2");
        assert_eq!(finding.fields["description"], "Test Device");
        assert_eq!(finding.fields["status"], "online");
        assert_eq!(finding.ports.len(), 1);
        assert_eq!(finding.ports[0].key, format!("tcp:{}", server.port));
        assert!(
            finding.raw["endpointUrl"]
                .as_str()
                .unwrap()
                .starts_with("opc.tcp://")
        );
        assert_eq!(
            finding.raw["applicationUri"],
            "urn:otserver:lab:opcua:server"
        );
        assert_eq!(
            finding.raw["userTokenPolicies"],
            json!(["anonymous", "username"])
        );
        let asset = &finding.raw["assets"][0];
        assert_eq!(asset["identification"]["HardwareRevision"], "A1");
        assert_eq!(asset["deviceHealth"]["label"], "NORMAL");
        assert_eq!(
            asset["documentationLinks"],
            json!(["https://example.test/manual.pdf"])
        );
        assert_eq!(asset["operationCounters"]["OperatingHours"], 1234.5);
        assert!(finding.warnings.is_empty());
    }

    #[tokio::test]
    async fn falls_back_to_device_set_without_aliases() {
        let server = spawn_lab_server(LabConfig {
            username: false,
            aliases: false,
            require_username: false,
        })
        .await;
        let finding = probe(Ipv4Addr::LOCALHOST, &settings_for(&server))
            .await
            .unwrap()
            .unwrap();
        // Without a FindAlias method the asset is discovered through the DeviceSet fallback.
        // The configured AssetId still wins as the name, but the DeviceSet display name is
        // retained on the raw asset record.
        assert_eq!(finding.fields["name"], "LAB-ASSET-1");
        assert_eq!(finding.fields["vendor"], "Lab Manufacturer");
        assert_eq!(finding.raw["assets"][0]["displayName"], "OT Lab Asset");
    }

    #[tokio::test]
    async fn requires_configured_username_credentials() {
        let server = spawn_lab_server(LabConfig {
            username: false,
            aliases: true,
            require_username: true,
        })
        .await;
        let finding = probe(Ipv4Addr::LOCALHOST, &settings_for(&server))
            .await
            .unwrap()
            .unwrap();
        assert!(finding.raw.get("assets").is_none());
        assert!(
            finding
                .warnings
                .iter()
                .any(|warning| warning.contains("opcuaCredentials"))
        );

        let mut settings = settings_for(&server);
        settings.credentials = vec![Credential {
            username: Some("lab-user".into()),
            password: Some("lab-password".into()),
        }];
        let finding = probe(Ipv4Addr::LOCALHOST, &settings)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finding.fields["vendor"], "Lab Manufacturer");
        assert!(
            finding
                .warnings
                .iter()
                .any(|warning| warning.contains("unencrypted channel"))
        );
    }

    #[tokio::test]
    async fn reports_failed_username_authentication() {
        let server = spawn_lab_server(LabConfig {
            username: true,
            aliases: true,
            require_username: true,
        })
        .await;
        let mut settings = settings_for(&server);
        settings.credentials = vec![Credential {
            username: Some("lab-user".into()),
            password: Some("wrong-password".into()),
        }];
        let finding = probe(Ipv4Addr::LOCALHOST, &settings)
            .await
            .unwrap()
            .unwrap();
        assert!(finding.raw.get("assets").is_none());
        assert!(
            finding
                .warnings
                .iter()
                .any(|warning| warning.contains("OPC UA session"))
        );
    }

    #[tokio::test]
    async fn prefers_anonymous_over_configured_credentials() {
        let server = spawn_lab_server(LabConfig {
            username: true,
            aliases: true,
            require_username: false,
        })
        .await;
        let mut settings = settings_for(&server);
        settings.credentials = vec![Credential {
            username: Some("lab-user".into()),
            password: Some("wrong-password".into()),
        }];
        let finding = probe(Ipv4Addr::LOCALHOST, &settings)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finding.fields["name"], "LAB-ASSET-1");
        assert!(
            finding
                .warnings
                .iter()
                .all(|warning| !warning.contains("OPC UA session"))
        );
        assert!(
            finding
                .warnings
                .iter()
                .all(|warning| !warning.contains("unencrypted channel"))
        );
    }

    #[tokio::test]
    async fn tries_configured_credentials_in_order() {
        let server = spawn_lab_server(LabConfig {
            username: false,
            aliases: true,
            require_username: true,
        })
        .await;
        let mut settings = settings_for(&server);
        settings.credentials = vec![
            Credential {
                username: Some("lab-user".into()),
                password: Some("wrong-password".into()),
            },
            Credential {
                username: Some("lab-user".into()),
                password: Some("lab-password".into()),
            },
        ];
        let finding = probe(Ipv4Addr::LOCALHOST, &settings)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(finding.fields["name"], "LAB-ASSET-1");
        assert!(
            finding
                .warnings
                .iter()
                .any(|warning| warning.contains("OPC UA session"))
        );
    }

    #[test]
    fn opcua_credentials_accept_object_or_list() {
        let single: Credentials =
            serde_json::from_str(r#"{"username":"ops","password":"secret"}"#).unwrap();
        assert_eq!(
            single.credentials(),
            [Credential {
                username: Some("ops".into()),
                password: Some("secret".into()),
            }]
        );
        let multiple: Credentials =
            serde_json::from_str(r#"[{"username":"a"},{"username":"b","password":"p"}]"#).unwrap();
        assert_eq!(multiple.credentials().len(), 2);
        assert!(serde_json::from_str::<Credentials>(r#"{"unknown":true}"#).is_err());
        assert!(serde_json::to_value(&multiple).unwrap().is_array());
    }
}
