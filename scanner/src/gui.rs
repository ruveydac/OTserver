#[cfg(windows)]
use crate::win10pcap_install;
use crate::{
    LogOutput, ScanArgs, ScanOptions, ScannerConfig, load_config_sync, nonempty_opt, resolve_scan,
    save_config_sync, scan, upload_scan,
};
use eframe::egui;
use otserver_scanner::profinet::{self, CaptureInterface};
use otserver_scanner::snmp::Settings as SnmpSettings;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};

pub struct GuiLogger {
    sender: Sender<String>,
}

impl LogOutput for GuiLogger {
    fn log(&self, msg: String) {
        let _ = self.sender.send(msg);
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
    is_scanning: bool,
    cancellation: Option<Arc<AtomicBool>>,
    log_rx: Option<Receiver<String>>,
    install_rx: Option<Receiver<Result<String, String>>>,
    is_installing: bool,
    #[cfg(windows)]
    win10pcap_available: bool,
    #[cfg(windows)]
    win10pcap_interface_available: bool,
}

impl GuiApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let config = load_config_sync().unwrap_or_default();
        let interfaces = profinet::interfaces().unwrap_or_default();

        let targets = config
            .targets
            .as_ref()
            .map(|t| t.join(", "))
            .unwrap_or_else(|| "192.168.1.0/24".to_string());

        let interface = config
            .interface
            .clone()
            .or_else(|| interfaces.first().map(|i| i.name.clone()))
            .unwrap_or_default();

        let source_mac = config
            .source_mac
            .clone()
            .or_else(|| {
                interfaces
                    .iter()
                    .find(|i| i.name == interface)
                    .and_then(|i| i.addresses.first().cloned())
            })
            .unwrap_or_default();

        let output = config
            .output
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "otserver-scan.json".to_string());

        let snmp = config.snmp.unwrap_or_default();
        let snmp_version = otserver_scanner::snmp::resolved_version(&snmp).to_string();
        let snmp_community = snmp.community.unwrap_or_default();
        let snmp_username = snmp.username.unwrap_or_default();
        let snmp_context = snmp.context_name.unwrap_or_default();
        let snmp_auth_protocol = snmp.auth_protocol.unwrap_or_default();
        let snmp_auth_password = snmp.auth_password.unwrap_or_default();
        let snmp_privacy_protocol = snmp.privacy_protocol.unwrap_or_default();
        let snmp_privacy_password = snmp.privacy_password.unwrap_or_default();

        let legacy_native_disabled = config.no_protocols.unwrap_or(false);
        let arp_enabled = !config.no_arp.unwrap_or(false);
        let profinet_enabled = !config.no_profinet.unwrap_or(false);
        let s7_enabled = !(legacy_native_disabled || config.no_s7.unwrap_or(false));
        let enip_enabled = !(legacy_native_disabled || config.no_enip.unwrap_or(false));
        let bacnet_enabled = !(legacy_native_disabled || config.no_bacnet.unwrap_or(false));
        let fins_enabled = !(legacy_native_disabled || config.no_fins.unwrap_or(false));
        let fox_enabled = !(legacy_native_disabled || config.no_fox.unwrap_or(false));
        let opcua_enabled = !(legacy_native_disabled || config.no_opcua.unwrap_or(false));
        let snmp_enabled = !config.no_snmp.unwrap_or(false);
        let lldp_enabled = !config.no_lldp.unwrap_or(false);
        let server_url = config.server_url.clone().unwrap_or_default();
        let site = config.site.clone().unwrap_or_default();
        let api_key = config.api_key.clone().unwrap_or_default();
        #[cfg(windows)]
        let win10pcap_available = profinet::win10pcap_available();
        #[cfg(windows)]
        let win10pcap_interface_available =
            win10pcap_available && profinet::win10pcap_interface_available(&interface);
        Self {
            targets,
            interface,
            source_mac,
            output,
            snmp_version,
            snmp_community,
            snmp_username,
            snmp_context,
            snmp_auth_protocol,
            snmp_auth_password,
            snmp_privacy_protocol,
            snmp_privacy_password,
            opcua_username: config.opcua_username.unwrap_or_default(),
            opcua_password: config.opcua_password.unwrap_or_default(),
            arp_enabled,
            profinet_enabled,
            s7_enabled,
            enip_enabled,
            bacnet_enabled,
            fins_enabled,
            fox_enabled,
            opcua_enabled,
            snmp_enabled,
            lldp_enabled,
            server_url,
            site,
            api_key,
            ack_authorized: false,
            interfaces,
            log_text: "OTserver Scanner GUI Ready.\n".to_string(),
            status: "Ready".to_string(),
            is_scanning: false,
            cancellation: None,
            log_rx: None,
            install_rx: None,
            is_installing: false,
            #[cfg(windows)]
            win10pcap_available,
            #[cfg(windows)]
            win10pcap_interface_available,
        }
    }

    fn snmp_settings(&self) -> Option<SnmpSettings> {
        let settings = SnmpSettings {
            version: (self.snmp_version == "3").then_some("3".to_string()),
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

        ScannerConfig {
            targets: if targets_vec.is_empty() {
                None
            } else {
                Some(targets_vec)
            },
            interface: nonempty_opt(&self.interface),
            source_mac: nonempty_opt(&self.source_mac),
            output: nonempty_opt(&self.output).map(PathBuf::from),
            snmp: self.snmp_settings(),
            no_protocols: None,
            no_arp: (!self.arp_enabled).then_some(true),
            no_profinet: (!self.profinet_enabled).then_some(true),
            no_s7: (!self.s7_enabled).then_some(true),
            no_enip: (!self.enip_enabled).then_some(true),
            no_bacnet: (!self.bacnet_enabled).then_some(true),
            no_fins: (!self.fins_enabled).then_some(true),
            no_fox: (!self.fox_enabled).then_some(true),
            no_opcua: (!self.opcua_enabled).then_some(true),
            no_snmp: (!self.snmp_enabled).then_some(true),
            no_lldp: (!self.lldp_enabled).then_some(true),
            opcua_ports: None,
            opcua_username: nonempty_opt(&self.opcua_username),
            opcua_password: nonempty_opt(&self.opcua_password),
            server_url: nonempty_opt(&self.server_url),
            site: nonempty_opt(&self.site),
            api_key: nonempty_opt(&self.api_key),
        }
    }

    fn save_config(&mut self) {
        let config = self.to_config();
        match save_config_sync(&config) {
            Ok(_) => {
                self.status = "Config saved to otscanner.json".to_string();
            }
            Err(err) => {
                self.status = format!("Failed to save config: {err}");
            }
        }
    }

    #[cfg(windows)]
    fn refresh_win10pcap(&mut self) {
        self.win10pcap_available = profinet::win10pcap_available();
        self.win10pcap_interface_available =
            self.win10pcap_available && profinet::win10pcap_interface_available(&self.interface);
    }

    fn start_scan(&mut self) {
        if !self.ack_authorized {
            self.status = "Error: --ack-authorized required to start scan!".to_string();
            self.log_text
                .push_str("Error: You must check the authorization box before scanning.\n");
            return;
        }

        self.save_config();

        let config = self.to_config();
        let targets_vec: Vec<String> = self
            .targets
            .split(&[',', '\n', ';'][..])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let args = ScanArgs {
            targets: targets_vec,
            interface: nonempty_opt(&self.interface),
            source_mac: nonempty_opt(&self.source_mac),
            output: nonempty_opt(&self.output).map(PathBuf::from),
            ack_authorized: true,
            no_protocols: false,
            no_arp: !self.arp_enabled,
            no_profinet: !self.profinet_enabled,
            no_s7: !self.s7_enabled,
            no_enip: !self.enip_enabled,
            no_bacnet: !self.bacnet_enabled,
            no_fins: !self.fins_enabled,
            no_fox: !self.fox_enabled,
            no_opcua: !self.opcua_enabled,
            no_snmp: !self.snmp_enabled,
            no_lldp: !self.lldp_enabled,
            server_url: nonempty_opt(&self.server_url),
            site: nonempty_opt(&self.site),
        };

        let env_key = std::env::var("OTSERVER_API_KEY").ok();
        let options: ScanOptions = match resolve_scan(args, config, env_key) {
            Ok(opts) => opts,
            Err(err) => {
                self.status = format!("Configuration error: {err}");
                self.log_text
                    .push_str(&format!("Configuration error: {err}\n"));
                return;
            }
        };

        let (tx, rx) = mpsc::channel::<String>();
        let cancellation = Arc::new(AtomicBool::new(false));
        self.log_rx = Some(rx);
        self.cancellation = Some(Arc::clone(&cancellation));
        self.is_scanning = true;
        self.status = "Scan running...".to_string();
        self.log_text.push_str("\n--- Starting Scan ---\n");

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to build tokio runtime for scan thread");

            let logger = GuiLogger { sender: tx.clone() };

            let marker = rt.block_on(async {
                match scan(&options, &logger, &cancellation).await {
                    Ok(partial) => {
                        if !cancellation.load(Ordering::Relaxed)
                            && let Some(upload) = &options.upload
                            && let Err(err) = upload_scan(upload, &options.output, &logger).await
                        {
                            logger.log(format!("Upload error: {err}"));
                        }
                        if cancellation.load(Ordering::Relaxed) {
                            logger.log("Scan stopped. Partial results were written.".to_string());
                        } else if partial {
                            logger.log("Scan completed with partial errors.".to_string());
                        } else {
                            logger.log("Scan completed successfully.".to_string());
                        }
                        if cancellation.load(Ordering::Relaxed) {
                            "[STOPPED]"
                        } else {
                            "[FINISHED]"
                        }
                    }
                    Err(err) => {
                        logger.log(format!("Scan error: {err}"));
                        "[FAILED]"
                    }
                }
            });

            let _ = tx.send(marker.to_string());
        });
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.log_rx {
            while let Ok(msg) = rx.try_recv() {
                if msg == "[FINISHED]" {
                    self.is_scanning = false;
                    self.cancellation = None;
                    self.status = "Scan completed.".to_string();
                } else if msg == "[STOPPED]" {
                    self.is_scanning = false;
                    self.cancellation = None;
                    self.status = "Scan stopped; partial output written.".to_string();
                } else if msg == "[FAILED]" {
                    self.is_scanning = false;
                    self.cancellation = None;
                    self.status = "Scan failed.".to_string();
                } else {
                    self.log_text.push_str(&msg);
                    self.log_text.push('\n');
                }
            }
        }

        let install_result = self.install_rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some(result) = install_result {
            self.install_rx = None;
            self.is_installing = false;
            match result {
                Ok(message) => {
                    self.log_text.push_str(&format!("\n{message}\n"));
                    self.interfaces = profinet::interfaces().unwrap_or_default();
                    #[cfg(windows)]
                    self.refresh_win10pcap();
                    self.status = "Win10Pcap installation completed.".into();
                }
                Err(error) => {
                    self.log_text
                        .push_str(&format!("\nWin10Pcap installation error: {error}\n"));
                    self.status = "Win10Pcap installation failed.".into();
                }
            }
        }

        if self.is_scanning || self.is_installing {
            ctx.request_repaint();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("OTserver Scanner");
            ui.label("Read-only OT asset discovery tool");
            ui.separator();

            egui::ScrollArea::vertical().show(ui, |ui| {
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
                                if selected_changed.is_some() {
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
                            && let Some(mac) = iface.addresses.first()
                        {
                            self.source_mac = mac.clone();
                            self.save_config();
                        }
                    });

                    ui.label("Enabled protocols:");
                    let mut protocol_changed = false;
                    ui.horizontal_wrapped(|ui| {
                        protocol_changed |= ui.toggle_value(&mut self.arp_enabled, "ARP").changed();
                        protocol_changed |= ui
                            .toggle_value(&mut self.profinet_enabled, "PROFINET DCP")
                            .changed();
                        protocol_changed |= ui.toggle_value(&mut self.s7_enabled, "S7").changed();
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
                        protocol_changed |=
                            ui.toggle_value(&mut self.opcua_enabled, "OPC UA").changed();
                        protocol_changed |=
                            ui.toggle_value(&mut self.snmp_enabled, "SNMP").changed();
                        protocol_changed |=
                            ui.toggle_value(&mut self.lldp_enabled, "LLDP").changed();
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
                            self.log_text.push_str(
                                "\nInstalling the bundled, signed Win10Pcap GPLv2 package...\n",
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
                            &[("2c", "SNMPv2c"), ("3", "SNMPv3")],
                        ) {
                            self.save_config();
                        }
                    });
                    if self.snmp_version == "3" {
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
                    } else {
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

                ui.add_space(8.0);

                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("Scan Authorization & Controls");
                    ui.checkbox(
                        &mut self.ack_authorized,
                        "I confirm I am authorized to scan these networks (--ack-authorized)",
                    );

                    ui.horizontal(|ui| {
                        let scan_btn = ui.add_enabled(
                            !self.is_scanning && !self.is_installing && self.ack_authorized,
                            egui::Button::new("▶ Start Scan"),
                        );
                        if scan_btn.clicked() {
                            self.start_scan();
                        }

                        if ui
                            .add_enabled(self.is_scanning, egui::Button::new("Stop Scan"))
                            .clicked()
                            && let Some(cancellation) = &self.cancellation
                        {
                            cancellation.store(true, Ordering::Relaxed);
                            self.status = "Stopping scan...".to_string();
                        }

                        if ui.button("💾 Save Config").clicked() {
                            self.save_config();
                        }

                        if ui.button("🗑 Clear Logs").clicked() {
                            self.log_text.clear();
                        }
                    });
                });

                ui.add_space(8.0);

                ui.group(|ui| {
                    ui.set_min_width(ui.available_width());
                    ui.heading("Scan Log Output");
                    egui::ScrollArea::vertical()
                        .max_height(220.0)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut self.log_text)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(f32::INFINITY)
                                    .lock_focus(true),
                            );
                        });
                });
            });

            ui.separator();
            ui.horizontal(|ui| {
                ui.label(format!("Status: {}", self.status));
            });
        });
    }
}

pub fn run_gui() -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 720.0])
            .with_min_inner_size([500.0, 500.0])
            .with_title("OTserver Scanner"),
        ..Default::default()
    };

    eframe::run_native(
        "OTserver Scanner",
        options,
        Box::new(|cc| Ok(Box::new(GuiApp::new(cc)))),
    )
    .map_err(|err| format!("GUI error: {err}"))
}

#[cfg(test)]
mod tests {
    use super::bound_ip_addresses;
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
    }
}
