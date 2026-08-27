#[cfg(windows)]
use crate::win10pcap_install;
use crate::{
    BatchResult, LogOutput, ScanArgs, ScannerConfig, ScannerConfigs, format_log_line,
    load_config_sync, nonempty_opt, prepare_scans, run_scan_batch, save_config_sync,
};
use eframe::egui;
use otserver_scanner::contract::normalize_mac;
use otserver_scanner::profinet::{self, CaptureInterface};
use otserver_scanner::snmp::Settings as SnmpSettings;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};

pub struct GuiLogger {
    sender: Sender<ScanMessage>,
}

enum ScanMessage {
    Log(String),
    Finished(BatchResult),
}

impl LogOutput for GuiLogger {
    fn write(&self, msg: String) {
        let _ = self.sender.send(ScanMessage::Log(msg));
    }
}

fn bound_ip_addresses(interfaces: &[CaptureInterface], selected: &str) -> Vec<String> {
    interfaces
        .iter()
        .find(|item| item.name == selected)
        .map(|item| {
            item.addresses
                .iter()
                .filter(|address| address.parse::<IpAddr>().is_ok())
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn interface_mac(interface: &CaptureInterface) -> Option<String> {
    interface
        .addresses
        .iter()
        .find_map(|address| normalize_mac(address))
}

fn with_added_configuration(
    configs: &ScannerConfigs,
    selected: usize,
    edited: ScannerConfig,
) -> ScannerConfigs {
    let mut values = configs.configs().to_vec();
    values[selected] = edited;
    if !configs.is_multiple() && values[0].name.is_none() {
        values[0].name = Some("Configuration 1".into());
    }

    let mut number = values.len() + 1;
    let name = loop {
        let candidate = format!("Configuration {number}");
        if values
            .iter()
            .all(|config| config.name.as_deref() != Some(&candidate))
        {
            break candidate;
        }
        number += 1;
    };

    let mut added = values[selected].clone();
    added.name = Some(name);
    let base = added
        .output
        .as_deref()
        .unwrap_or_else(|| Path::new("otserver-scan.json"));
    for suffix in 2.. {
        let stem = base
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("otserver-scan");
        let filename = match base.extension().and_then(|value| value.to_str()) {
            Some(extension) => format!("{stem}-{suffix}.{extension}"),
            None => format!("{stem}-{suffix}"),
        };
        let candidate = base.with_file_name(filename);
        if values.iter().all(|config| {
            config
                .output
                .as_deref()
                .unwrap_or_else(|| Path::new("otserver-scan.json"))
                != candidate
        }) {
            added.output = Some(candidate);
            break;
        }
    }
    values.push(added);
    ScannerConfigs::Multiple(values)
}

fn protocol_combo(
    ui: &mut egui::Ui,
    id: &str,
    value: &mut String,
    options: &[(&str, &str)],
) -> bool {
    let selected = options
        .iter()
        .find(|(option, _)| *option == value.as_str())
        .map(|(_, label)| *label)
        .unwrap_or("None");
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected)
        .show_ui(ui, |ui| {
            for (option, label) in options {
                ui.selectable_value(value, (*option).to_string(), *label);
            }
        })
        .response
        .changed()
}

pub struct GuiApp {
    configs: ScannerConfigs,
    selected_config: usize,
    config_name: String,
    targets: String,
    interface: String,
    source_mac: String,
    output: String,
    snmp_version: String,
    snmp_community: String,
    snmp_username: String,
    snmp_context: String,
    snmp_auth_protocol: String,
    snmp_auth_password: String,
    snmp_privacy_protocol: String,
    snmp_privacy_password: String,
    opcua_username: String,
    opcua_password: String,
    arp_enabled: bool,
    profinet_enabled: bool,
    s7_enabled: bool,
    enip_enabled: bool,
    bacnet_enabled: bool,
    fins_enabled: bool,
    fox_enabled: bool,
    opcua_enabled: bool,
    snmp_enabled: bool,
    lldp_enabled: bool,
    server_url: String,
    site: String,
    api_key: String,
    ack_authorized: bool,

    interfaces: Vec<CaptureInterface>,
    log_text: String,
    status: String,
    config_save_result: Option<Result<String, String>>,
    is_scanning: bool,
    cancellation: Option<Arc<AtomicBool>>,
    log_rx: Option<Receiver<ScanMessage>>,
    install_rx: Option<Receiver<Result<String, String>>>,
    is_installing: bool,
    #[cfg(windows)]
    win10pcap_available: bool,
    #[cfg(windows)]
    win10pcap_interface_available: bool,
}

impl GuiApp {
    pub fn new(configs: ScannerConfigs) -> Self {
        let interfaces = profinet::interfaces().unwrap_or_default();
        #[cfg(windows)]
        let win10pcap_available = profinet::win10pcap_available();
        let mut app = Self {
            configs,
            selected_config: 0,
            config_name: String::new(),
            targets: String::new(),
            interface: String::new(),
            source_mac: String::new(),
            output: String::new(),
            snmp_version: "2c".into(),
            snmp_community: String::new(),
            snmp_username: String::new(),
            snmp_context: String::new(),
            snmp_auth_protocol: String::new(),
            snmp_auth_password: String::new(),
            snmp_privacy_protocol: String::new(),
            snmp_privacy_password: String::new(),
            opcua_username: String::new(),
            opcua_password: String::new(),
            arp_enabled: true,
            profinet_enabled: true,
            s7_enabled: true,
            enip_enabled: true,
            bacnet_enabled: true,
            fins_enabled: true,
            fox_enabled: true,
            opcua_enabled: true,
            snmp_enabled: true,
            lldp_enabled: true,
            server_url: String::new(),
            site: String::new(),
            api_key: String::new(),
            ack_authorized: false,
            interfaces,
            log_text: format!("{}\n", format_log_line("OTserver Scanner GUI ready.")),
            status: "Ready".to_string(),
            config_save_result: None,
            is_scanning: false,
            cancellation: None,
            log_rx: None,
            install_rx: None,
            is_installing: false,
            #[cfg(windows)]
            win10pcap_available,
            #[cfg(windows)]
            win10pcap_interface_available: false,
        };
        app.apply_selected_config();
        app
    }

    fn apply_selected_config(&mut self) {
        let config = self.configs.configs()[self.selected_config].clone();
        self.config_name = config.name.clone().unwrap_or_default();
        self.targets = config
            .targets
            .as_ref()
            .map(|targets| targets.join(", "))
            .unwrap_or_else(|| "192.168.1.0/24".into());
        self.interface = config
            .interface
            .clone()
            .or_else(|| self.interfaces.first().map(|item| item.name.clone()))
            .unwrap_or_default();
        self.source_mac = config
            .source_mac
            .clone()
            .or_else(|| {
                self.interfaces
                    .iter()
                    .find(|item| item.name == self.interface)
                    .and_then(interface_mac)
            })
            .unwrap_or_default();
        self.output = config
            .output
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|| "otserver-scan.json".into());

        let snmp = config.snmp.unwrap_or_default();
        self.snmp_version = otserver_scanner::snmp::resolved_version(&snmp).to_string();
        self.snmp_community = snmp.community.unwrap_or_default();
        self.snmp_username = snmp.username.unwrap_or_default();
        self.snmp_context = snmp.context_name.unwrap_or_default();
        self.snmp_auth_protocol = snmp.auth_protocol.unwrap_or_default();
        self.snmp_auth_password = snmp.auth_password.unwrap_or_default();
        self.snmp_privacy_protocol = snmp.privacy_protocol.unwrap_or_default();
        self.snmp_privacy_password = snmp.privacy_password.unwrap_or_default();

        let legacy_native_disabled = config.no_protocols.unwrap_or(false);
        self.arp_enabled = !config.no_arp.unwrap_or(false);
        self.profinet_enabled = !config.no_profinet.unwrap_or(false);
        self.s7_enabled = !(legacy_native_disabled || config.no_s7.unwrap_or(false));
        self.enip_enabled = !(legacy_native_disabled || config.no_enip.unwrap_or(false));
        self.bacnet_enabled = !(legacy_native_disabled || config.no_bacnet.unwrap_or(false));
        self.fins_enabled = !(legacy_native_disabled || config.no_fins.unwrap_or(false));
        self.fox_enabled = !(legacy_native_disabled || config.no_fox.unwrap_or(false));
        self.opcua_enabled = !(legacy_native_disabled || config.no_opcua.unwrap_or(false));
        self.snmp_enabled = !config.no_snmp.unwrap_or(false);
        self.lldp_enabled = !config.no_lldp.unwrap_or(false);
        self.opcua_username = config.opcua_username.unwrap_or_default();
        self.opcua_password = config.opcua_password.unwrap_or_default();
        self.server_url = config.server_url.unwrap_or_default();
        self.site = config.site.unwrap_or_default();
        self.api_key = config.api_key.unwrap_or_default();
        #[cfg(windows)]
        self.refresh_win10pcap();
    }

    fn snmp_settings(&self) -> Option<SnmpSettings> {
        let settings = SnmpSettings {
            version: (self.snmp_version != "2c").then(|| self.snmp_version.clone()),
            community: nonempty_opt(&self.snmp_community),
            username: nonempty_opt(&self.snmp_username),
            context_name: nonempty_opt(&self.snmp_context),
            auth_protocol: nonempty_opt(&self.snmp_auth_protocol),
            auth_password: nonempty_opt(&self.snmp_auth_password),
            privacy_protocol: nonempty_opt(&self.snmp_privacy_protocol),
            privacy_password: nonempty_opt(&self.snmp_privacy_password),
        };
        (settings != SnmpSettings::default()).then_some(settings)
    }

    fn to_config(&self) -> ScannerConfig {
        let targets_vec: Vec<String> = self
            .targets
            .split(&[',', '\n', ';'][..])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let mut config = self.configs.configs()[self.selected_config].clone();
        config.name = nonempty_opt(&self.config_name);
        config.targets = (!targets_vec.is_empty()).then_some(targets_vec);
        config.interface = nonempty_opt(&self.interface);
        config.source_mac = nonempty_opt(&self.source_mac);
        config.output = nonempty_opt(&self.output).map(PathBuf::from);
        config.snmp = self.snmp_settings();
        config.no_protocols = None;
        config.no_arp = (!self.arp_enabled).then_some(true);
        config.no_profinet = (!self.profinet_enabled).then_some(true);
        config.no_s7 = (!self.s7_enabled).then_some(true);
        config.no_enip = (!self.enip_enabled).then_some(true);
        config.no_bacnet = (!self.bacnet_enabled).then_some(true);
        config.no_fins = (!self.fins_enabled).then_some(true);
        config.no_fox = (!self.fox_enabled).then_some(true);
        config.no_opcua = (!self.opcua_enabled).then_some(true);
        config.no_snmp = (!self.snmp_enabled).then_some(true);
        config.no_lldp = (!self.lldp_enabled).then_some(true);
        config.opcua_username = nonempty_opt(&self.opcua_username);
        config.opcua_password = nonempty_opt(&self.opcua_password);
        config.server_url = nonempty_opt(&self.server_url);
        config.site = nonempty_opt(&self.site);
        config.api_key = nonempty_opt(&self.api_key);
        config
    }

    fn save_config(&mut self) -> bool {
        let mut configs = self.configs.clone();
        configs.configs_mut()[self.selected_config] = self.to_config();
        self.persist_configs(configs)
    }

    fn persist_configs(&mut self, configs: ScannerConfigs) -> bool {
        match save_config_sync(&configs) {
            Ok(_) => {
                self.configs = configs;
                self.config_save_result = Some(Ok(format_log_line(
                    "Configuration saved to otscanner.json.",
                )));
                true
            }
            Err(err) => {
                self.config_save_result = Some(Err(format_log_line(&format!(
                    "Configuration save failed: {err}",
                ))));
                false
            }
        }
    }

    fn add_configuration(&mut self) {
        let configs =
            with_added_configuration(&self.configs, self.selected_config, self.to_config());
        let selected = configs.configs().len() - 1;
        if self.persist_configs(configs) {
            self.selected_config = selected;
            self.apply_selected_config();
            self.config_save_result = Some(Ok(format_log_line(
                "Configuration added to otscanner.json.",
            )));
        }
    }

    fn append_log(&mut self, message: &str) {
        self.log_text.push_str(&format_log_line(message));
        self.log_text.push('\n');
    }

    #[cfg(windows)]
    fn refresh_win10pcap(&mut self) {
        self.win10pcap_available = profinet::win10pcap_available();
        self.win10pcap_interface_available =
            self.win10pcap_available && profinet::win10pcap_interface_available(&self.interface);
    }

    fn start_scan(&mut self, run_all: bool) {
        if !self.ack_authorized {
            self.status = "Error: --ack-authorized required to start scan!".to_string();
            self.append_log("Error: You must check the authorization box before scanning.");
            return;
        }

        if !self.save_config() {
            self.status = "Configuration could not be saved.".into();
            self.append_log("Configuration could not be saved; scan not started.");
            return;
        }

        let configs = if run_all {
            self.configs.named_configs()
        } else {
            let config = self.configs.configs()[self.selected_config].clone();
            vec![(
                config
                    .name
                    .clone()
                    .unwrap_or_else(|| "Configuration".into()),
                config,
            )]
        };
        let args = ScanArgs {
            ack_authorized: true,
            ..ScanArgs::default()
        };
        let env_key = std::env::var("OTSERVER_API_KEY").ok();
        let (scans, failures) = match prepare_scans(args, configs, env_key) {
            Ok(prepared) => prepared,
            Err(err) => {
                self.status = format!("Configuration error: {err}");
                self.append_log(&format!("Configuration error: {err}"));
                return;
            }
        };

        let scan_count = scans.len();
        let (tx, rx) = mpsc::channel::<ScanMessage>();
        let cancellation = Arc::new(AtomicBool::new(false));
        self.log_rx = Some(rx);
        self.cancellation = Some(Arc::clone(&cancellation));
        self.is_scanning = true;
        self.status = format!("Running {scan_count} configuration(s)...");
        self.append_log(&format!("Starting {scan_count} configuration(s)."));

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to build tokio runtime for scan thread");

            let logger = GuiLogger { sender: tx.clone() };
            for failure in &failures {
                logger.log(failure.clone());
            }
            let mut result = rt.block_on(run_scan_batch(&scans, &logger, &cancellation));
            let mut all_failures = failures;
            all_failures.append(&mut result.failures);
            result.failures = all_failures;
            let _ = tx.send(ScanMessage::Finished(result));
        });
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let scan_messages: Vec<_> = self
            .log_rx
            .as_ref()
            .map(|rx| rx.try_iter().collect())
            .unwrap_or_default();
        for message in scan_messages {
            match message {
                ScanMessage::Log(message) => {
                    self.log_text.push_str(&message);
                    self.log_text.push('\n');
                }
                ScanMessage::Finished(result) => {
                    self.is_scanning = false;
                    self.cancellation = None;
                    self.log_rx = None;
                    let summary = format!(
                        "{} complete, {} partial, {} failed.",
                        result.completed,
                        result.partial,
                        result.failures.len()
                    );
                    if result.cancelled {
                        self.status = format!("Batch stopped: {summary}");
                        self.append_log(&format!(
                            "Batch stopped; pending configurations were skipped. {summary}"
                        ));
                    } else {
                        self.status = format!("Batch finished: {summary}");
                        self.append_log(&format!("Batch finished: {summary}"));
                    }
                }
            }
        }

        let install_result = self.install_rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some(result) = install_result {
            self.install_rx = None;
            self.is_installing = false;
            match result {
                Ok(message) => {
                    self.append_log(&message);
                    self.interfaces = profinet::interfaces().unwrap_or_default();
                    #[cfg(windows)]
                    self.refresh_win10pcap();
                    self.status = "Win10Pcap installation completed.".into();
                }
                Err(error) => {
                    self.append_log(&format!("Win10Pcap installation error: {error}"));
                    self.status = "Win10Pcap installation failed.".into();
                }
            }
        }

        if self.is_scanning || self.is_installing {
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("app-header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("OTserver Scanner");
                ui.weak(concat!("Version ", env!("CARGO_PKG_VERSION")));
            });
            ui.label("Read-only OT asset discovery tool");
        });

        egui::TopBottomPanel::bottom("app-controls").show(ctx, |ui| {
            let controls_enabled = !self.is_scanning && !self.is_installing;
            ui.horizontal_wrapped(|ui| {
                ui.add_enabled(
                    controls_enabled,
                    egui::Checkbox::new(
                        &mut self.ack_authorized,
                        "I confirm I am authorized to scan these networks (--ack-authorized)",
                    ),
                );

                if self.configs.is_multiple() {
                    if ui
                        .add_enabled(
                            controls_enabled && self.ack_authorized,
                            egui::Button::new("Run Selected"),
                        )
                        .clicked()
                    {
                        self.start_scan(false);
                    }
                    if ui
                        .add_enabled(
                            controls_enabled && self.ack_authorized,
                            egui::Button::new("Run All"),
                        )
                        .clicked()
                    {
                        self.start_scan(true);
                    }
                } else if ui
                    .add_enabled(
                        controls_enabled && self.ack_authorized,
                        egui::Button::new("Start Scan"),
                    )
                    .clicked()
                {
                    self.start_scan(false);
                }
                if ui
                    .add_enabled(self.is_scanning, egui::Button::new("Stop Scan"))
                    .clicked()
                    && let Some(cancellation) = &self.cancellation
                {
                    cancellation.store(true, Ordering::Relaxed);
                    self.status = "Stopping scan...".to_string();
                }
                if ui
                    .add_enabled(controls_enabled, egui::Button::new("Save Config"))
                    .clicked()
                {
                    self.save_config();
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("Status: {}", self.status));
                if let Some(result) = &self.config_save_result {
                    ui.separator();
                    match result {
                        Ok(message) => {
                            ui.colored_label(
                                egui::Color32::LIGHT_GREEN,
                                format!("Config: {message}"),
                            );
                        }
                        Err(message) => {
                            ui.colored_label(
                                egui::Color32::LIGHT_RED,
                                format!("Config error: {message}"),
                            );
                        }
                    }
                }
            });
        });

        egui::SidePanel::right("scan-log")
            .default_width(400.0)
            .min_width(300.0)
            .max_width(650.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.heading("Scan Log");
                    if ui
                        .add_enabled(!self.log_text.is_empty(), egui::Button::new("Clear Log"))
                        .clicked()
                    {
                        self.log_text.clear();
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("scan-log-scroll")
                    .stick_to_bottom(true)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(self.log_text.as_str()).monospace(),
                            )
                            .selectable(true)
                            .wrap(),
                        );
                    });
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.is_scanning || self.is_installing {
                ui.disable();
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("Configurations");
                    if self.configs.is_multiple() {
                        let names: Vec<_> = self
                            .configs
                            .configs()
                            .iter()
                            .filter_map(|config| config.name.clone())
                            .collect();
                        let mut selected = self.selected_config;
                        ui.horizontal(|ui| {
                            ui.label("Selected:");
                            egui::ComboBox::from_id_salt("scanner-configuration")
                                .selected_text(&names[self.selected_config])
                                .show_ui(ui, |ui| {
                                    for (index, name) in names.iter().enumerate() {
                                        ui.selectable_value(&mut selected, index, name);
                                    }
                                });
                        });
                        if selected != self.selected_config && self.save_config() {
                            self.selected_config = selected;
                            self.apply_selected_config();
                        }
                        ui.horizontal(|ui| {
                            ui.label("Name:");
                            if ui
                                .add(egui::TextEdit::singleline(&mut self.config_name))
                                .changed()
                            {
                                self.save_config();
                            }
                        });
                    } else {
                        ui.label("This file currently contains one configuration.");
                    }
                    if ui.button("Add Configuration").clicked() {
                        self.add_configuration();
                    }
                });
                ui.add_space(8.0);
                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("Network Target Settings");
                    ui.horizontal(|ui| {
                        ui.label("Targets (CIDR / IP):");
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.targets)
                                    .hint_text("192.168.1.0/24"),
                            )
                            .changed()
                        {
                            self.save_config();
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Capture Interface:");
                        egui::ComboBox::from_label("Interface Selection")
                            .selected_text(
                                self.interfaces
                                    .iter()
                                    .find(|i| i.name == self.interface)
                                    .map(|i| format!("{} ({})", i.description, i.name))
                                    .unwrap_or_else(|| self.interface.clone()),
                            )
                            .show_ui(ui, |ui| {
                                let mut selected_changed = None;
                                for iface in &self.interfaces {
                                    let label = format!("{} ({})", iface.description, iface.name);
                                    if ui
                                        .selectable_value(
                                            &mut self.interface,
                                            iface.name.clone(),
                                            label,
                                        )
                                        .clicked()
                                    {
                                        selected_changed = Some(iface.name.clone());
                                    }
                                }
                                if let Some(selected) = selected_changed {
                                    if let Some(mac) = self
                                        .interfaces
                                        .iter()
                                        .find(|iface| iface.name == selected)
                                        .and_then(interface_mac)
                                    {
                                        self.source_mac = mac;
                                    }
                                    #[cfg(windows)]
                                    self.refresh_win10pcap();
                                    self.save_config();
                                }
                            });
                        if ui.button("Refresh").clicked() {
                            self.interfaces = profinet::interfaces().unwrap_or_default();
                            #[cfg(windows)]
                            self.refresh_win10pcap();
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Bound IP Address(es):");
                        let addresses = bound_ip_addresses(&self.interfaces, &self.interface);
                        if addresses.is_empty() {
                            ui.weak("No IP address assigned");
                        } else {
                            ui.monospace(addresses.join(", "));
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Custom Interface ID:");
                        if ui
                            .add(egui::TextEdit::singleline(&mut self.interface))
                            .changed()
                        {
                            #[cfg(windows)]
                            self.refresh_win10pcap();
                            self.save_config();
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Source MAC Address:");
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.source_mac)
                                    .hint_text("00:11:22:33:44:55"),
                            )
                            .changed()
                        {
                            self.save_config();
                        }
                        if ui.button("Auto-fill from Interface").clicked()
                            && let Some(iface) =
                                self.interfaces.iter().find(|i| i.name == self.interface)
                            && let Some(mac) = interface_mac(iface)
                        {
                            self.source_mac = mac;
                            self.save_config();
                        }
                    });

                    ui.label("Enabled protocols:");
                    let mut protocol_changed = false;
                    ui.add_enabled_ui(!self.is_scanning, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            protocol_changed |=
                                ui.toggle_value(&mut self.arp_enabled, "ARP").changed();
                            protocol_changed |= ui
                                .toggle_value(&mut self.profinet_enabled, "PROFINET DCP")
                                .changed();
                            protocol_changed |=
                                ui.toggle_value(&mut self.s7_enabled, "S7").changed();
                            protocol_changed |= ui
                                .toggle_value(&mut self.enip_enabled, "EtherNet/IP")
                                .changed();
                            protocol_changed |= ui
                                .toggle_value(&mut self.bacnet_enabled, "BACnet")
                                .changed();
                            protocol_changed |=
                                ui.toggle_value(&mut self.fins_enabled, "FINS").changed();
                            protocol_changed |=
                                ui.toggle_value(&mut self.fox_enabled, "Fox").changed();
                            protocol_changed |= ui
                                .toggle_value(&mut self.opcua_enabled, "OPC UA")
                                .changed();
                            protocol_changed |=
                                ui.toggle_value(&mut self.snmp_enabled, "SNMP").changed();
                            protocol_changed |=
                                ui.toggle_value(&mut self.lldp_enabled, "LLDP").changed();
                        });
                    });
                    ui.small("Highlighted protocols are enabled. All protocols are enabled by default.");
                    if protocol_changed {
                        self.save_config();
                    }

                    #[cfg(windows)]
                    if self.profinet_enabled && !self.win10pcap_available {
                        ui.separator();
                        ui.label(
                            "Win10Pcap is not available. Windows will use passive pktmon PROFINET capture. Active DCP requires the GPLv2 Win10Pcap packet driver. Installation is explicit and never occurs during a scan.",
                        );
                        ui.hyperlink_to(
                            "Win10Pcap project and GPLv2 source",
                            "https://www.win10pcap.org/",
                        );
                        if ui
                            .add_enabled(
                                !self.is_installing && !self.is_scanning,
                                egui::Button::new("Install Win10Pcap (Administrator)"),
                            )
                            .clicked()
                        {
                            self.is_installing = true;
                            self.status = "Installing Win10Pcap...".into();
                            self.append_log(
                                "Installing the bundled, signed Win10Pcap GPLv2 package...",
                            );
                            let (tx, rx) = mpsc::channel();
                            self.install_rx = Some(rx);
                            std::thread::spawn(move || {
                                let _ = tx.send(win10pcap_install::install());
                            });
                        }
                    } else if self.profinet_enabled && self.win10pcap_interface_available {
                        ui.label(
                            "Active Windows PROFINET DCP is ready through Win10Pcap on the selected physical interface.",
                        );
                    } else if self.profinet_enabled {
                        ui.colored_label(
                            egui::Color32::YELLOW,
                            "Win10Pcap is installed, but the selected interface is not usable for direct DCP. Remove any obsolete Windows Network Bridge, refresh, select the physical Ethernet adapter, and verify its Win10Pcap binding.",
                        );
                    }
                });

                ui.add_space(8.0);

                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("Output Settings");
                    ui.horizontal(|ui| {
                        ui.label("Output File:");
                        if ui
                            .add(egui::TextEdit::singleline(&mut self.output))
                            .changed()
                        {
                            self.save_config();
                        }
                        if ui.button("Browse...").clicked() {
                            let path = Path::new(&self.output);
                            let mut dialog = rfd::FileDialog::new()
                                .add_filter("OTserver scan", &["json"]);
                            if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                                dialog = dialog.set_file_name(name);
                            }
                            if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                                dialog = dialog.set_directory(parent);
                            }
                            if let Some(path) = dialog.save_file() {
                                self.output = path.to_string_lossy().into_owned();
                                self.save_config();
                            }
                        }
                    });
                });

                ui.add_space(8.0);

                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("SNMP Settings");
                    ui.small(
                        "Stored in otscanner.json. Without settings, SNMPv2c with community \"public\" is used.",
                    );
                    ui.horizontal(|ui| {
                        ui.label("Version:");
                        if protocol_combo(
                            ui,
                            "snmp-version",
                            &mut self.snmp_version,
                            &[
                                ("auto", "Auto (v3, v2c, v1)"),
                                ("1", "SNMPv1"),
                                ("2c", "SNMPv2c"),
                                ("3", "SNMPv3"),
                            ],
                        ) {
                            self.save_config();
                        }
                    });
                    if self.snmp_version == "auto" {
                        ui.small(
                            "Auto tries configured SNMPv3 credentials when present, then SNMPv2c and SNMPv1 with the configured community.",
                        );
                    }
                    if self.snmp_version == "3" || self.snmp_version == "auto" {
                        ui.horizontal(|ui| {
                            ui.label("Username:");
                            if ui
                                .add(egui::TextEdit::singleline(&mut self.snmp_username))
                                .changed()
                            {
                                self.save_config();
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label("Context Name:");
                            if ui
                                .add(egui::TextEdit::singleline(&mut self.snmp_context))
                                .changed()
                            {
                                self.save_config();
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.label("Authentication Protocol:");
                            if protocol_combo(
                                ui,
                                "snmp-auth-protocol",
                                &mut self.snmp_auth_protocol,
                                &[
                                    ("", "None"),
                                    ("md5", "MD5"),
                                    ("sha1", "SHA-1"),
                                    ("sha224", "SHA-224"),
                                    ("sha256", "SHA-256"),
                                    ("sha384", "SHA-384"),
                                    ("sha512", "SHA-512"),
                                ],
                            ) {
                                self.save_config();
                            }
                        });
                        if !self.snmp_auth_protocol.is_empty() {
                            ui.horizontal(|ui| {
                                ui.label("Authentication Password:");
                                if ui
                                    .add(
                                        egui::TextEdit::singleline(&mut self.snmp_auth_password)
                                            .password(true),
                                    )
                                    .changed()
                                {
                                    self.save_config();
                                }
                            });
                        }
                        ui.horizontal(|ui| {
                            ui.label("Privacy Protocol:");
                            if protocol_combo(
                                ui,
                                "snmp-privacy-protocol",
                                &mut self.snmp_privacy_protocol,
                                &[
                                    ("", "None"),
                                    ("des", "DES"),
                                    ("aes128", "AES-128"),
                                    ("aes192", "AES-192"),
                                    ("aes256", "AES-256"),
                                ],
                            ) {
                                self.save_config();
                            }
                        });
                        if !self.snmp_privacy_protocol.is_empty() {
                            ui.horizontal(|ui| {
                                ui.label("Privacy Password:");
                                if ui
                                    .add(
                                        egui::TextEdit::singleline(
                                            &mut self.snmp_privacy_password,
                                        )
                                        .password(true),
                                    )
                                    .changed()
                                {
                                    self.save_config();
                                }
                            });
                        }
                    }
                    if self.snmp_version != "3" {
                        ui.horizontal(|ui| {
                            ui.label("Community:");
                            if ui
                                .add(
                                    egui::TextEdit::singleline(&mut self.snmp_community)
                                        .password(true)
                                        .hint_text("public"),
                                )
                                .changed()
                            {
                                self.save_config();
                            }
                        });
                    }
                });

                ui.add_space(8.0);

                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("OPC UA Credentials");
                    ui.small(
                        "Stored in otscanner.json. Used only when a server requires username authentication. Passwords travel unencrypted because the scanner uses SecurityPolicy None.",
                    );
                    ui.horizontal(|ui| {
                        ui.label("Username:");
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.opcua_username)
                                    .hint_text("Use anonymous access when blank"),
                            )
                            .changed()
                        {
                            self.save_config();
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Password:");
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.opcua_password)
                                    .password(true),
                            )
                            .changed()
                        {
                            self.save_config();
                        }
                    });
                });

                ui.add_space(8.0);

                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("OTserver Direct Upload (Optional)");
                    ui.horizontal(|ui| {
                        ui.label("Server Base URL:");
                        if ui
                            .add(
                                egui::TextEdit::singleline(&mut self.server_url)
                                    .hint_text("https://otserver.example"),
                            )
                            .changed()
                        {
                            self.save_config();
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("Site ID:");
                        if ui.add(egui::TextEdit::singleline(&mut self.site)).changed() {
                            self.save_config();
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label("API Key:");
                        if ui
                            .add(egui::TextEdit::singleline(&mut self.api_key).password(true))
                            .changed()
                        {
                            self.save_config();
                        }
                    });
                });
                });
        });
    }
}

pub fn run_gui() -> Result<(), String> {
    let configs = load_config_sync()?;
    #[cfg(windows)]
    unsafe {
        // SAFETY: FreeConsole has no arguments or pointer preconditions.
        windows_sys::Win32::System::Console::FreeConsole();
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 760.0])
            .with_min_inner_size([500.0, 500.0])
            .with_title(concat!("OTserver Scanner v", env!("CARGO_PKG_VERSION"))),
        ..Default::default()
    };

    eframe::run_native(
        "OTserver Scanner",
        options,
        Box::new(move |_cc| Ok(Box::new(GuiApp::new(configs)))),
    )
    .map_err(|err| {
        let message = format!("GUI error: {err}");
        rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Error)
            .set_title("OTserver Scanner")
            .set_description(&message)
            .show();
        message
    })
}

#[cfg(test)]
mod tests {
    use super::{GuiApp, bound_ip_addresses, interface_mac, with_added_configuration};
    use crate::{ScannerConfig, ScannerConfigs};
    use otserver_scanner::profinet::CaptureInterface;

    #[test]
    fn displays_only_ip_addresses_for_the_selected_interface() {
        let interfaces = vec![CaptureInterface {
            name: "interface-1".into(),
            friendly_name: "Ethernet".into(),
            description: "Physical Ethernet".into(),
            addresses: vec![
                "00:11:22:33:44:55".into(),
                "192.0.2.10".into(),
                "2001:db8::10".into(),
            ],
        }];
        assert_eq!(
            bound_ip_addresses(&interfaces, "interface-1"),
            ["192.0.2.10", "2001:db8::10"]
        );
        assert!(bound_ip_addresses(&interfaces, "missing").is_empty());
        assert_eq!(
            interface_mac(&interfaces[0]).as_deref(),
            Some("00:11:22:33:44:55")
        );
    }

    #[test]
    fn editing_selected_config_preserves_other_configs_and_hidden_fields() {
        let first = ScannerConfig {
            name: Some("Line A".into()),
            targets: Some(vec!["192.0.2.1".into()]),
            interface: Some("interface-1".into()),
            source_mac: Some("00:11:22:33:44:55".into()),
            output: Some("line-a.json".into()),
            opcua_ports: Some(vec![4841, 48400]),
            ..ScannerConfig::default()
        };
        let second = ScannerConfig {
            name: Some("Line B".into()),
            targets: Some(vec!["192.0.2.2".into()]),
            interface: Some("interface-2".into()),
            source_mac: Some("00:11:22:33:44:66".into()),
            output: Some("line-b.json".into()),
            ..ScannerConfig::default()
        };
        let mut app = GuiApp::new(ScannerConfigs::Multiple(vec![
            first.clone(),
            second.clone(),
        ]));
        app.targets = "198.51.100.1".into();

        let mut saved = app.configs.clone();
        saved.configs_mut()[app.selected_config] = app.to_config();

        assert_eq!(saved.configs()[0].opcua_ports, first.opcua_ports);
        assert_eq!(saved.configs()[1], second);
    }

    #[test]
    fn adding_to_single_config_creates_named_array_with_unique_output() {
        let original = ScannerConfig {
            output: Some("scan.json".into()),
            opcua_ports: Some(vec![4841]),
            ..ScannerConfig::default()
        };
        let configs = ScannerConfigs::Single(Box::new(original.clone()));

        let added = with_added_configuration(&configs, 0, original);

        assert!(added.is_multiple());
        assert_eq!(added.configs()[0].name.as_deref(), Some("Configuration 1"));
        assert_eq!(added.configs()[1].name.as_deref(), Some("Configuration 2"));
        assert_eq!(
            added.configs()[1].output.as_deref(),
            Some(std::path::Path::new("scan-2.json"))
        );
        assert_eq!(added.configs()[1].opcua_ports, Some(vec![4841]));
    }
}
