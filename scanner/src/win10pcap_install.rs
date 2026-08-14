//! Explicit elevated installation of the bundled, signed Win10Pcap GPLv2 package.

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::{Command, Stdio};
#[cfg(windows)]
use std::time::{Duration, Instant};

#[cfg(windows)]
const INSTALLER: &[u8] = include_bytes!("../windows/Win10Pcap-v10.2-5002.msi");
#[cfg(windows)]
const INSTALL_TIMEOUT: Duration = Duration::from_secs(180);
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(windows)]
pub fn install() -> Result<String, String> {
    if otserver_scanner::profinet::win10pcap_available() {
        return Ok("Win10Pcap is already installed and its packet backend is available.".into());
    }
    // SAFETY: IsUserAnAdmin inspects the current process token and takes no arguments.
    if unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() } == 0 {
        return Err(
            "Administrator elevation is required. Close OTserver Scanner, right-click the executable, select 'Run as administrator', and choose Install Win10Pcap again."
                .into(),
        );
    }
    let directory = std::env::temp_dir().join(format!(
        "otserver-win10pcap-install-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir(&directory).map_err(|error| {
        format!("Could not create the Win10Pcap installation directory: {error}")
    })?;
    let result = install_from(&directory);
    if let Err(error) = std::fs::remove_dir_all(&directory) {
        eprintln!(
            "warning: could not remove temporary Win10Pcap installation directory {}: {error}",
            directory.display()
        );
    }
    result
}

#[cfg(windows)]
fn install_from(directory: &Path) -> Result<String, String> {
    let installer = directory.join("Win10Pcap-v10.2-5002.msi");
    std::fs::write(&installer, INSTALLER)
        .map_err(|error| format!("Could not extract the Win10Pcap installer: {error}"))?;
    let msiexec = system_directory()?.join("msiexec.exe");
    let mut child = Command::new(msiexec)
        .args(["/i"])
        .arg(&installer)
        .args(["/qn", "/norestart"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|error| format!("Could not launch the Win10Pcap MSI installer: {error}"))?;

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < INSTALL_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(250));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(
                    "Win10Pcap installation exceeded three minutes and was stopped. Check Windows Installer and driver-installation logs before retrying."
                        .into(),
                );
            }
            Err(error) => {
                return Err(format!(
                    "Could not wait for the Win10Pcap installer: {error}"
                ));
            }
        }
    };
    let code = status.code().unwrap_or(-1);
    if code != 0 && code != 3010 {
        return Err(format!(
            "Win10Pcap installation failed with Windows Installer exit code {code}. Run OTserver Scanner as Administrator and check Event Viewer > Windows Logs > Application for MsiInstaller details."
        ));
    }

    let detected = (0..40).any(|_| {
        if otserver_scanner::profinet::win10pcap_available() {
            true
        } else {
            std::thread::sleep(Duration::from_millis(250));
            false
        }
    });
    if !detected {
        return Err(
            "The Win10Pcap MSI completed, but its packet backend is not available. Restart Windows if the installer requested it, then verify that the Win10Pcap service is running."
                .into(),
        );
    }
    if code == 3010 {
        Ok(
            "Win10Pcap installed successfully. Windows requested a restart; active DCP may require rebooting before the driver binds to every adapter."
                .into(),
        )
    } else {
        Ok(
            "Win10Pcap installed successfully. Active PROFINET DCP now uses the selected physical Ethernet interface directly."
                .into(),
        )
    }
}

#[cfg(windows)]
fn system_directory() -> Result<PathBuf, String> {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = [0_u16; 32_768];
    // SAFETY: buffer is writable for the supplied element count.
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err(format!(
            "Could not locate the Windows system directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(PathBuf::from(String::from_utf16_lossy(&buffer[..length])))
}

#[cfg(not(windows))]
pub fn install() -> Result<String, String> {
    Err("Win10Pcap installation is only available on Windows.".into())
}
