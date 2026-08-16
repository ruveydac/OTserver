pub mod gui;
pub mod win10pcap_install;

use clap::{ArgAction, Args, Parser, Subcommand};
use otserver_scanner::contract::{
    InterfaceRef, ScanExport, ScanInfo, ScannerInfo, merge_devices, validate,
};
use otserver_scanner::{discovery, profinet, protocols, snmp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

pub trait LogOutput: Send + Sync {
    fn log(&self, msg: String);
}

pub struct StdoutLogger;
impl LogOutput for StdoutLogger {
    fn log(&self, msg: String) {
        println!("{msg}");
    }
}

#[derive(Parser)]
#[command(
    name = "otserver-scanner",
    version,
    about = "Read-only OT discovery for OTserver — https://otserver.org"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Doctor,
    InstallWin10pcap,
    Interfaces {
        #[arg(long)]
        json: bool,
    },
    Scan(ScanArgs),
    Validate {
        file: PathBuf,
    },
    Gui,
}

#[derive(Args, Clone)]
pub struct ScanArgs {
    #[arg(long = "target")]
    pub targets: Vec<String>,
    #[arg(long)]
    pub interface: Option<String>,
    #[arg(long)]
    pub source_mac: Option<String>,
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    #[arg(long = "snmp-config")]
    pub snmp_profile: Option<PathBuf>,
    #[arg(long, action = ArgAction::SetTrue, required = true)]
    pub ack_authorized: bool,
    #[arg(long, hide = true)]
    pub no_protocols: bool,
    #[arg(long)]
    pub no_arp: bool,
    #[arg(long)]
    pub no_profinet: bool,
    #[arg(long)]
    pub no_s7: bool,
    #[arg(long)]
    pub no_enip: bool,
    #[arg(long)]
    pub no_bacnet: bool,
    #[arg(long)]
    pub no_fins: bool,
    #[arg(long)]
    pub no_fox: bool,
    #[arg(long)]
    pub no_opcua: bool,
    #[arg(long)]
    pub no_snmp: bool,
    #[arg(long)]
    pub no_lldp: bool,
    #[arg(long)]
    pub server_url: Option<String>,
    #[arg(long)]
    pub site: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ScannerConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snmp_config: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_protocols: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_arp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_profinet: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_s7: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_enip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_bacnet: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_fins: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_fox: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_opcua: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_snmp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_lldp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcua_ports: Option<Vec<u16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcua_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opcua_password_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

pub struct UploadOptions {
    pub endpoint: reqwest::Url,
    pub site: String,
    pub api_key: String,
}

pub struct ScanOptions {
    pub targets: Vec<String>,
    pub interface: String,
    pub source_mac: String,
    pub output: PathBuf,
    pub snmp_profile: Option<PathBuf>,
    pub protocols: ProtocolOptions,
    pub snmp_credentials: snmp::CredentialOverrides,
    pub opcua: otserver_scanner::protocols::OpcuaSettings,
    pub upload: Option<UploadOptions>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolOptions {
    pub arp: bool,
    pub profinet: bool,
    pub s7: bool,
    pub enip: bool,
    pub bacnet: bool,
    pub fins: bool,
    pub fox: bool,
    pub opcua: bool,
    pub snmp: bool,
    pub lldp: bool,
}

impl Default for ProtocolOptions {
    fn default() -> Self {
        Self {
            arp: true,
            profinet: true,
            s7: true,
            enip: true,
            bacnet: true,
            fins: true,
            fox: true,
            opcua: true,
            snmp: true,
            lldp: true,
        }
    }
}

#[derive(Deserialize)]
struct CreateImportResponse {
    doc: ImportDocument,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportDocument {
    id: serde_json::Value,
    status: String,
    created_assets: Option<u64>,
    updated_assets: Option<u64>,
    skipped_assets: Option<u64>,
    error: Option<String>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    match Cli::parse().command {
        Some(Commands::Doctor) => doctor(),
        Some(Commands::InstallWin10pcap) => {
            println!("{}", win10pcap_install::install()?);
            Ok(())
        }
        Some(Commands::Interfaces { json }) => {
            let devices = profinet::interfaces()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&devices).map_err(|error| error.to_string())?
                );
                return Ok(());
            }
            for device in devices {
                let addresses = device.addresses.join(", ");
                println!("{}\t{}\t{}", device.name, device.description, addresses);
            }
            Ok(())
        }
        Some(Commands::Validate { file }) => {
            let value: serde_json::Value = serde_json::from_slice(
                &tokio::fs::read(file)
                    .await
                    .map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            if value["format"] != "otserver-scan" || value["schemaVersion"] != 2 {
                return Err(
                    "Unsupported scanner file. Expected otserver-scan schemaVersion 2. Run a new scan with OTserver Scanner."
                        .into(),
                );
            }
            let scan: ScanExport =
                serde_json::from_value(value).map_err(|error| error.to_string())?;
            validate(&scan)?;
            println!(
                "Valid otserver-scan v2 file with {} device(s).",
                scan.devices.len()
            );
            Ok(())
        }
        Some(Commands::Scan(args)) => {
            let config = load_config().await?;
            let options = resolve_scan(args, config, std::env::var("OTSERVER_API_KEY").ok())?;
            let logger = StdoutLogger;
            let partial = scan(&options, &logger).await?;
            if let Some(upload) = &options.upload {
                upload_scan(upload, &options.output, &logger).await?;
            }
            if partial {
                std::process::exit(2);
            }
            Ok(())
        }
        Some(Commands::Gui) | None => gui::run_gui(),
    }
}

pub fn get_config_path() -> Result<PathBuf, String> {
    if let Ok(exe) = std::env::current_exe() {
        Ok(exe.with_file_name("otscanner.json"))
    } else {
        Ok(PathBuf::from("otscanner.json"))
    }
}

pub async fn load_config() -> Result<ScannerConfig, String> {
    let path = get_config_path()?;
    match tokio::fs::read(&path).await {
        Ok(data) => parse_config(&data)
            .map_err(|error| format!("Could not read {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ScannerConfig::default()),
        Err(error) => Err(format!("Could not read {}: {error}", path.display())),
    }
}

pub fn load_config_sync() -> Result<ScannerConfig, String> {
    let path = get_config_path()?;
    match std::fs::read(&path) {
        Ok(data) => parse_config(&data)
            .map_err(|error| format!("Could not read {}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ScannerConfig::default()),
        Err(error) => Err(format!("Could not read {}: {error}", path.display())),
    }
}

pub fn save_config_sync(config: &ScannerConfig) -> Result<(), String> {
    let path = get_config_path()?;
    let data = serde_json::to_vec_pretty(config)
        .map_err(|error| format!("Could not serialize config: {error}"))?;
    std::fs::write(&path, data)
        .map_err(|error| format!("Could not write {}: {error}", path.display()))
}

pub fn parse_config(data: &[u8]) -> Result<ScannerConfig, String> {
    serde_json::from_slice(data).map_err(|error| error.to_string())
}

pub fn resolve_scan(
    args: ScanArgs,
    config: ScannerConfig,
    environment_api_key: Option<String>,
) -> Result<ScanOptions, String> {
    let no_native_protocols = args.no_protocols || config.no_protocols.unwrap_or(false);
    let protocols = ProtocolOptions {
        arp: !(args.no_arp || config.no_arp.unwrap_or(false)),
        profinet: !(args.no_profinet || config.no_profinet.unwrap_or(false)),
        s7: !(no_native_protocols || args.no_s7 || config.no_s7.unwrap_or(false)),
        enip: !(no_native_protocols || args.no_enip || config.no_enip.unwrap_or(false)),
        bacnet: !(no_native_protocols || args.no_bacnet || config.no_bacnet.unwrap_or(false)),
        fins: !(no_native_protocols || args.no_fins || config.no_fins.unwrap_or(false)),
        fox: !(no_native_protocols || args.no_fox || config.no_fox.unwrap_or(false)),
        opcua: !(no_native_protocols || args.no_opcua || config.no_opcua.unwrap_or(false)),
        snmp: !(args.no_snmp || config.no_snmp.unwrap_or(false)),
        lldp: !(args.no_lldp || config.no_lldp.unwrap_or(false)),
    };
    let opcua = opcua_probe_settings(&config);
    let targets = if args.targets.is_empty() {
        config.targets.unwrap_or_default()
    } else {
        args.targets
    };
    if targets.is_empty() {
        return Err("At least one --target or config targets entry is required.".into());
    }

    let interface = nonempty(args.interface.or(config.interface), "interface")?;
    let source_mac = nonempty(args.source_mac.or(config.source_mac), "sourceMac")?;
    let server_url = optional_nonempty(args.server_url.or(config.server_url), "serverUrl")?;
    let site = optional_nonempty(args.site.or(config.site), "site")?;
    let api_key = optional_nonempty(environment_api_key.or(config.api_key), "apiKey")?;
    let upload = match (server_url, site, api_key) {
        (None, None, None) => None,
        (Some(server_url), Some(site), Some(api_key)) => Some(UploadOptions {
            endpoint: import_endpoint(&server_url)?,
            site,
            api_key,
        }),
        _ => {
            return Err(
                "Upload requires serverUrl, site, and OTSERVER_API_KEY or config apiKey.".into(),
            );
        }
    };

    Ok(ScanOptions {
        targets,
        interface,
        source_mac,
        output: args
            .output
            .or(config.output)
            .unwrap_or_else(|| PathBuf::from("otserver-scan.json")),
        snmp_profile: args.snmp_profile.or(config.snmp_config),
        protocols,
        snmp_credentials: snmp::CredentialOverrides::default(),
        opcua,
        upload,
    })
}

fn opcua_probe_settings(config: &ScannerConfig) -> otserver_scanner::protocols::OpcuaSettings {
    let env = |name: &str| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    let config_value = |value: Option<&str>| {
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let username =
        env("OTSERVER_OPCUA_USERNAME").or_else(|| config_value(config.opcua_username.as_deref()));
    let password = env("OTSERVER_OPCUA_PASSWORD").or_else(|| {
        config
            .opcua_password_env
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .and_then(env)
    });
    otserver_scanner::protocols::OpcuaSettings {
        ports: otserver_scanner::protocols::OpcuaSettings::ports_or_default(
            config.opcua_ports.clone(),
        ),
        username,
        password,
    }
}

pub fn nonempty(value: Option<String>, name: &str) -> Result<String, String> {
    optional_nonempty(value, name)?.ok_or_else(|| format!("--{name} or config {name} is required."))
}

pub fn optional_nonempty(value: Option<String>, name: &str) -> Result<Option<String>, String> {
    value
        .map(|value| {
            let value = value.trim().to_owned();
            if value.is_empty() {
                Err(format!("{name} must not be empty."))
            } else {
                Ok(value)
            }
        })
        .transpose()
}

pub fn nonempty_opt(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn import_endpoint(server_url: &str) -> Result<reqwest::Url, String> {
    let mut endpoint = reqwest::Url::parse(server_url)
        .map_err(|error| format!("serverUrl is invalid: {error}"))?;
    if !matches!(endpoint.scheme(), "http" | "https")
        || endpoint.cannot_be_a_base()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err("serverUrl must be an HTTP(S) base URL without a query or fragment.".into());
    }
    endpoint.set_path(&format!(
        "{}/api/asset-imports",
        endpoint.path().trim_end_matches('/')
    ));
    Ok(endpoint)
}

fn doctor() -> Result<(), String> {
    println!("Capture interfaces: {}", profinet::interfaces()?.len());
    println!("Native ARP and OT protocol modules: available");
    #[cfg(windows)]
    println!(
        "Win10Pcap active PROFINET backend: {}",
        if profinet::win10pcap_available() {
            "available"
        } else {
            "not available (pktmon passive fallback only)"
        }
    );
    Ok(())
}

pub async fn scan(options: &ScanOptions, logger: &dyn LogOutput) -> Result<bool, String> {
    let started_at = otserver_scanner::now();
    let mut devices = Vec::new();
    let mut links = Vec::new();
    let mut unresolved = Vec::new();
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    logger.log(format!(
        "Starting discovery for target(s): {}",
        options.targets.join(", ")
    ));
    logger.log(format!(
        "Interface: {}, Source MAC: {}",
        options.interface, options.source_mac
    ));

    let target_addresses = discovery::expand_targets(&options.targets)?;

    if options.protocols.arp {
        logger.log("Executing ARP discovery...".into());
        match discover(&options.interface, &options.source_mac, &target_addresses).await {
            Ok(found) => {
                logger.log(format!("ARP discovery found {} device(s).", found.len()));
                devices.extend(found);
            }
            Err(error) => {
                logger.log(format!("ARP discovery error: {error}"));
                errors.push(error);
            }
        }
    } else {
        logger.log("ARP discovery disabled.".into());
    }

    if options.protocols.profinet {
        #[cfg(windows)]
        if profinet::win10pcap_available() {
            logger.log(
                "Using the installed Win10Pcap packet driver for active PROFINET DCP; the selected adapter will be bound directly by GUID."
                    .into(),
            );
        } else {
            logger.log(
                "Win10Pcap is not available. Windows will use passive pktmon PROFINET capture. Run the explicit Win10Pcap installer as Administrator to enable active DCP Identify. Driver installation is never a scan side effect."
                    .into(),
            );
        }
        logger.log("Scanning PROFINET DCP...".into());
        let selected = options.interface.clone();
        let mac = options.source_mac.clone();
        match tokio::task::spawn_blocking(move || {
            profinet::scan(&selected, &mac, Duration::from_secs(4))
        })
        .await
        .map_err(|error| error.to_string())?
        {
            Ok(found) => {
                logger.log(format!("PROFINET DCP found {} device(s).", found.len()));
                devices.extend(found);
            }
            Err(error) => {
                logger.log(format!("PROFINET DCP error: {error}"));
                errors.push(error);
            }
        }
    }
    devices = merge_devices(devices);
    logger.log(format!(
        "Unique devices after Layer 2 discovery: {}",
        devices.len()
    ));

    let native_selection = protocols::Selection {
        s7: options.protocols.s7,
        enip: options.protocols.enip,
        bacnet: options.protocols.bacnet,
        fins: options.protocols.fins,
        fox: options.protocols.fox,
        opcua: options.protocols.opcua,
    };
    if native_selection.any() {
        logger.log(format!(
            "Probing native protocols ({})...",
            native_selection.labels().join(", ")
        ));
        probe_protocols(
            &mut devices,
            &mut warnings,
            native_selection,
            &options.opcua,
        )
        .await;
    }

    if (options.protocols.snmp || options.protocols.lldp)
        && let Some(path) = &options.snmp_profile
    {
        let snmp_selection = snmp::QuerySelection {
            inventory: options.protocols.snmp,
            lldp: options.protocols.lldp,
        };
        logger.log(format!(
            "Querying {} profile: {}",
            match (snmp_selection.inventory, snmp_selection.lldp) {
                (true, true) => "SNMP and LLDP",
                (true, false) => "SNMP",
                (false, true) => "LLDP",
                (false, false) => unreachable!("guard requires one query type"),
            },
            path.display()
        ));
        let profiles = snmp::load(path).await?;
        let ip_to_mac = unique_ip_identities(&devices);
        let ips = devices
            .iter()
            .flat_map(|device| device.ip_addresses.iter().cloned())
            .collect::<BTreeSet<_>>();
        for ip in ips {
            for profile in &profiles {
                let local_mac = ip_to_mac.get(&ip).map(String::as_str);
                match snmp::query(
                    &ip,
                    local_mac,
                    profile,
                    snmp_selection,
                    &options.snmp_credentials,
                )
                .await
                {
                    Ok(result) => {
                        links.extend(result.links);
                        if let Some(mac) = local_mac {
                            if let Some(device) =
                                devices.iter_mut().find(|device| device.mac_address == mac)
                            {
                                if let Some(observation) = result.observation {
                                    device.observations.push(observation);
                                }
                                device.interfaces.extend(result.interfaces);
                            }
                        } else if let Some(observation) = result.observation {
                            unresolved.push(observation);
                        }
                    }
                    Err(error) => warnings.push(error),
                }
            }
        }
    }

    let scan = ScanExport {
        format: "otserver-scan".into(),
        schema_version: 2,
        scanner: ScannerInfo {
            name: "OTserver Scanner".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            npcap_version: None,
        },
        scan: ScanInfo {
            id: Uuid::new_v4().to_string(),
            started_at,
            finished_at: otserver_scanner::now(),
            targets: options.targets.clone(),
            interface: InterfaceRef {
                id: options.interface.clone(),
                name: options.interface.clone(),
                mac_address: otserver_scanner::contract::normalize_mac(&options.source_mac),
                addresses: vec![],
            },
            partial: !errors.is_empty(),
        },
        devices: merge_devices(devices),
        links,
        unresolved,
        warnings,
        errors,
    };
    validate(&scan)?;
    write_atomic(
        &options.output,
        &serde_json::to_vec_pretty(&scan).map_err(|error| error.to_string())?,
    )
    .await?;
    logger.log(format!(
        "Wrote {} device(s) to {}.",
        scan.devices.len(),
        options.output.display()
    ));
    Ok(scan.scan.partial)
}

pub async fn upload_scan(
    options: &UploadOptions,
    path: &Path,
    logger: &dyn LogOutput,
) -> Result<(), String> {
    logger.log(format!(
        "Uploading export {} to OTserver at {}...",
        path.display(),
        options.endpoint
    ));
    let data = tokio::fs::read(path)
        .await
        .map_err(|error| format!("Could not read {} for upload: {error}", path.display()))?;
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("otserver-scan.json");
    let imported = send_import(options, data, filename).await?;
    let id = match &imported.id {
        serde_json::Value::String(value) => value.clone(),
        value => value.to_string(),
    };
    logger.log(format!(
        "Imported as {id}: {} created, {} updated, {} skipped.",
        imported.created_assets.unwrap_or(0),
        imported.updated_assets.unwrap_or(0),
        imported.skipped_assets.unwrap_or(0)
    ));
    Ok(())
}

async fn send_import(
    options: &UploadOptions,
    data: Vec<u8>,
    filename: &str,
) -> Result<ImportDocument, String> {
    let file = reqwest::multipart::Part::bytes(data)
        .file_name(filename.to_owned())
        .mime_str("application/json")
        .map_err(|error| error.to_string())?;
    let form = reqwest::multipart::Form::new()
        .text(
            "_payload",
            serde_json::json!({
                "site": options.site,
                "source": "otserver-scanner",
                "sourceVersion": env!("CARGO_PKG_VERSION"),
                "status": "pending"
            })
            .to_string(),
        )
        .part("file", file);
    let response = reqwest::Client::new()
        .post(options.endpoint.clone())
        .header(
            reqwest::header::AUTHORIZATION,
            format!("users API-Key {}", options.api_key),
        )
        .multipart(form)
        .send()
        .await
        .map_err(|error| format!("Could not upload scan: {error}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| format!("Could not read OTserver response: {error}"))?;
    if !status.is_success() {
        return Err(format!(
            "OTserver import failed ({status}): {}",
            body.chars().take(500).collect::<String>()
        ));
    }
    let response: CreateImportResponse = serde_json::from_str(&body)
        .map_err(|error| format!("OTserver returned an invalid import response: {error}"))?;
    if response.doc.status != "completed" {
        return Err(response.doc.error.clone().unwrap_or_else(|| {
            format!("OTserver import ended with status {}.", response.doc.status)
        }));
    }
    Ok(response.doc)
}

async fn discover(
    interface: &str,
    source_mac: &str,
    targets: &[Ipv4Addr],
) -> Result<Vec<otserver_scanner::contract::Device>, String> {
    let interface = interface.to_owned();
    let source_mac = source_mac.to_owned();
    let targets = targets.to_vec();
    tokio::task::spawn_blocking(move || {
        discovery::scan(&interface, &source_mac, &targets, Duration::from_secs(3))
    })
    .await
    .map_err(|error| error.to_string())?
}

async fn probe_protocols(
    devices: &mut [otserver_scanner::contract::Device],
    warnings: &mut Vec<String>,
    selection: protocols::Selection,
    opcua: &otserver_scanner::protocols::OpcuaSettings,
) {
    let identities = unique_ip_identities(devices)
        .into_iter()
        .filter_map(|(ip, mac)| Some((ip.parse::<Ipv4Addr>().ok()?, mac)))
        .collect::<Vec<_>>();
    let mut tasks = tokio::task::JoinSet::new();
    for (ip, mac) in identities {
        if tasks.len() == 32 {
            apply_probe(devices, warnings, tasks.join_next().await);
        }
        let opcua = opcua.clone();
        tasks.spawn(async move {
            let result = protocols::scan(ip, &mac, selection, &opcua).await;
            (mac, result)
        });
    }
    while let Some(result) = tasks.join_next().await {
        apply_probe(devices, warnings, Some(result));
    }
}

fn apply_probe(
    devices: &mut [otserver_scanner::contract::Device],
    warnings: &mut Vec<String>,
    result: Option<Result<(String, protocols::ProbeResult), tokio::task::JoinError>>,
) {
    let Some(result) = result else { return };
    let Ok((mac, mut result)) = result else {
        warnings.push("A native protocol probe task failed.".into());
        return;
    };
    warnings.append(&mut result.warnings);
    if let Some(device) = devices.iter_mut().find(|device| device.mac_address == mac) {
        device.observations.append(&mut result.observations);
        device.ports.append(&mut result.ports);
    }
}

fn unique_ip_identities(
    devices: &[otserver_scanner::contract::Device],
) -> BTreeMap<String, String> {
    let mut values = BTreeMap::<String, Vec<String>>::new();
    for device in devices {
        for ip in &device.ip_addresses {
            values
                .entry(ip.clone())
                .or_default()
                .push(device.mac_address.clone());
        }
    }
    values
        .into_iter()
        .filter_map(|(ip, mut macs)| {
            macs.sort();
            macs.dedup();
            (macs.len() == 1).then(|| (ip, macs.remove(0)))
        })
        .collect()
}

async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temporary = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("json")
    ));
    tokio::fs::write(&temporary, bytes)
        .await
        .map_err(|error| format!("Could not write export: {error}"))?;
    tokio::fs::rename(&temporary, path)
        .await
        .map_err(|error| format!("Could not finalize export: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn args() -> ScanArgs {
        ScanArgs {
            targets: vec![],
            interface: None,
            source_mac: None,
            output: None,
            snmp_profile: None,
            ack_authorized: true,
            no_protocols: false,
            no_arp: false,
            no_profinet: false,
            no_s7: false,
            no_enip: false,
            no_bacnet: false,
            no_fins: false,
            no_fox: false,
            no_opcua: false,
            no_snmp: false,
            no_lldp: false,
            server_url: None,
            site: None,
        }
    }

    #[test]
    fn resolves_config_with_cli_and_environment_precedence() {
        let config = parse_config(
            br#"{
                "targets":["192.0.2.0/24"],
                "interface":"config-interface",
                "sourceMac":"00:11:22:33:44:55",
                "output":"configured.json",
                "noProtocols":true,
                "serverUrl":"https://otserver.example/base/",
                "site":"site-1",
                "apiKey":"config-key"
            }"#,
        )
        .unwrap();
        let mut cli = args();
        cli.interface = Some("cli-interface".into());
        let resolved = resolve_scan(cli, config, Some("environment-key".into())).unwrap();

        assert_eq!(resolved.targets, ["192.0.2.0/24"]);
        assert_eq!(resolved.interface, "cli-interface");
        assert_eq!(resolved.output, PathBuf::from("configured.json"));
        assert!(resolved.protocols.arp);
        assert!(resolved.protocols.profinet);
        assert!(!resolved.protocols.s7);
        assert!(!resolved.protocols.enip);
        assert!(!resolved.protocols.bacnet);
        assert!(!resolved.protocols.fins);
        assert!(!resolved.protocols.fox);
        assert!(!resolved.protocols.opcua);
        assert!(resolved.protocols.snmp);
        assert!(resolved.protocols.lldp);
        let upload = resolved.upload.unwrap();
        assert_eq!(
            upload.endpoint.as_str(),
            "https://otserver.example/base/api/asset-imports"
        );
        assert_eq!(upload.api_key, "environment-key");
        assert_eq!(upload.site, "site-1");
    }

    #[test]
    fn serializes_and_deserializes_config_roundtrip() {
        let config = ScannerConfig {
            targets: Some(vec!["192.168.1.0/24".into()]),
            interface: Some("eth0".into()),
            source_mac: Some("00:11:22:33:44:55".into()),
            output: Some(PathBuf::from("output.json")),
            snmp_config: Some(PathBuf::from("snmp.json")),
            no_protocols: None,
            no_arp: Some(true),
            no_profinet: None,
            no_s7: Some(true),
            no_enip: None,
            no_bacnet: Some(true),
            no_fins: None,
            no_fox: Some(true),
            no_opcua: Some(true),
            no_snmp: Some(true),
            no_lldp: Some(true),
            opcua_ports: Some(vec![4840, 4841]),
            opcua_username: Some("opc-user".into()),
            opcua_password_env: Some("OTSERVER_LAB_OPCUA_PASSWORD".into()),
            server_url: Some("https://otserver.example".into()),
            site: Some("site-1".into()),
            api_key: Some("key-123".into()),
        };
        let bytes = serde_json::to_vec_pretty(&config).unwrap();
        let parsed = parse_config(&bytes).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn resolves_opcua_settings_from_config() {
        let config = ScannerConfig {
            opcua_ports: Some(vec![4841, 48400]),
            opcua_username: Some("opc-user".into()),
            opcua_password_env: Some("OTSERVER_OPCUA_PASSWORD_NOT_SET_FOR_TEST".into()),
            ..ScannerConfig::default()
        };
        let settings = opcua_probe_settings(&config);
        assert_eq!(settings.ports, [4841, 48400]);
        assert_eq!(settings.username.as_deref(), Some("opc-user"));
        assert_eq!(settings.password, None);

        let settings = opcua_probe_settings(&ScannerConfig::default());
        assert_eq!(
            settings.ports,
            otserver_scanner::protocols::OPCUA_DEFAULT_PORTS
        );
    }

    #[test]
    fn rejects_unknown_or_incomplete_config() {
        assert!(parse_config(br#"{"unknown":true}"#).is_err());
        let mut cli = args();
        cli.targets.push("192.0.2.1".into());
        cli.interface = Some("eth0".into());
        cli.source_mac = Some("00:11:22:33:44:55".into());
        cli.server_url = Some("https://otserver.example".into());
        assert!(resolve_scan(cli, ScannerConfig::default(), None).is_err());
    }

    #[test]
    fn cli_exposes_individual_protocol_disable_flags() {
        let cli = Cli::try_parse_from([
            "otserver-scanner",
            "scan",
            "--ack-authorized",
            "--no-arp",
            "--no-profinet",
            "--no-s7",
            "--no-enip",
            "--no-bacnet",
            "--no-fins",
            "--no-fox",
            "--no-opcua",
            "--no-snmp",
            "--no-lldp",
        ])
        .unwrap();
        let Some(Commands::Scan(args)) = cli.command else {
            panic!("expected scan command");
        };
        assert!(args.no_arp);
        assert!(args.no_profinet);
        assert!(args.no_s7);
        assert!(args.no_enip);
        assert!(args.no_bacnet);
        assert!(args.no_fins);
        assert!(args.no_fox);
        assert!(args.no_opcua);
        assert!(args.no_snmp);
        assert!(args.no_lldp);
    }

    #[test]
    fn all_protocols_are_enabled_by_default() {
        let mut cli = args();
        cli.targets.push("192.0.2.1".into());
        cli.interface = Some("eth0".into());
        cli.source_mac = Some("00:11:22:33:44:55".into());
        let resolved = resolve_scan(cli, ScannerConfig::default(), None).unwrap();
        assert_eq!(resolved.protocols, ProtocolOptions::default());
    }

    #[tokio::test]
    async fn uploads_payload_multipart_with_api_key() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let read = socket.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                let Some(header_end) = request.windows(4).position(|value| value == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap();
                if request.len() >= header_end + 4 + length {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.starts_with("POST /api/asset-imports HTTP/1.1"));
            assert!(request.contains("users API-Key secret-key"));
            assert!(request.contains("name=\"_payload\""));
            assert!(request.contains("\"site\":\"site-1\""));
            assert!(request.contains("filename=\"scan.json\""));

            let body = r#"{"doc":{"id":"import-1","status":"completed","createdAssets":2,"updatedAssets":1,"skippedAssets":0}}"#;
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let upload = UploadOptions {
            endpoint: reqwest::Url::parse(&format!("http://{address}/api/asset-imports")).unwrap(),
            site: "site-1".into(),
            api_key: "secret-key".into(),
        };

        let imported = send_import(
            &upload,
            br#"{"format":"otserver-scan"}"#.to_vec(),
            "scan.json",
        )
        .await
        .unwrap();
        assert_eq!(imported.status, "completed");
        assert_eq!(imported.created_assets, Some(2));
        server.await.unwrap();
    }
}
