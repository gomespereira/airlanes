use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

use crate::model::{Analysis, Band, Network, infer_band};

const REDACTED_SSID_LOCATION_HINT: &str = "SSID names are hidden (redacted). On macOS, enable Location Services for this terminal app (Terminal, Cursor, iTerm, etc.) in System Settings → Privacy & Security → Location Services, then restart the terminal.";

pub struct Scanner {
    backend: Backend,
}

enum Backend {
    MacOs,
    LinuxNmcli,
}

impl Scanner {
    pub fn detect() -> Result<Self> {
        if cfg!(target_os = "macos") {
            return Ok(Self {
                backend: Backend::MacOs,
            });
        }

        if cfg!(target_os = "linux") {
            return Ok(Self {
                backend: Backend::LinuxNmcli,
            });
        }

        bail!("Unsupported platform. This app currently supports macOS and Linux.")
    }

    pub fn scan(&self) -> Result<(Analysis, Option<String>)> {
        let networks = match self.backend {
            Backend::MacOs => scan_macos()?,
            Backend::LinuxNmcli => scan_linux_nmcli()?,
        };

        let analysis = Analysis::from_networks(networks);
        let note = macos_redaction_note_after_scan(&analysis);
        Ok((analysis, note))
    }

    pub fn initial_snapshot(&self) -> Result<Option<Analysis>> {
        match self.backend {
            Backend::MacOs => initial_snapshot_macos(),
            Backend::LinuxNmcli => Ok(None),
        }
    }

    pub fn prepare(&self) -> Result<Option<String>> {
        match self.backend {
            Backend::MacOs => prepare_macos_status(),
            Backend::LinuxNmcli => Ok(None),
        }
    }

    pub fn backend_label(&self) -> &'static str {
        match self.backend {
            Backend::MacOs => "macOS (system_profiler)",
            Backend::LinuxNmcli => "NetworkManager (nmcli)",
        }
    }
}

/// After a scan, if every SSID still looks redacted (typical when macOS Location access is off),
/// returns guidance for the user. Always [`None`] on non-macOS builds.
pub fn macos_redaction_note_after_scan(analysis: &Analysis) -> Option<String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = analysis;
        None
    }
    #[cfg(target_os = "macos")]
    {
        if analysis.networks.is_empty() {
            return None;
        }
        if analysis
            .networks
            .iter()
            .all(|network| is_redacted_ssid(&network.ssid))
        {
            Some(REDACTED_SSID_LOCATION_HINT.into())
        } else {
            None
        }
    }
}

#[cfg(target_os = "macos")]
fn prepare_macos_status() -> Result<Option<String>> {
    let context = current_wifi_context()?;
    Ok(Some(match context {
        Some(context) => format!(
            "Using macOS fast snapshot + system_profiler scan. Current network: {} on channel {}.",
            context.ssid, context.channel
        ),
        None => "Using macOS fast snapshot + system_profiler scan.".into(),
    }))
}

#[cfg(not(target_os = "macos"))]
fn prepare_macos_status() -> Result<Option<String>> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn initial_snapshot_macos() -> Result<Option<Analysis>> {
    let Some(current) = current_wifi_context()? else {
        return Ok(None);
    };

    Ok(Some(Analysis::from_networks(vec![Network {
        ssid: current.ssid,
        channel: current.channel,
        signal_dbm: -55,
        security: current.security,
        band: infer_band(current.channel),
    }])))
}

#[cfg(not(target_os = "macos"))]
fn initial_snapshot_macos() -> Result<Option<Analysis>> {
    Ok(None)
}

#[cfg(target_os = "macos")]
fn scan_macos() -> Result<Vec<Network>> {
    let current = current_wifi_context()?;
    let mut networks = run_system_profiler_scan(false)?;

    if networks
        .iter()
        .all(|network| is_redacted_ssid(&network.ssid))
    {
        if let Ok(privileged_networks) = run_system_profiler_scan(true) {
            if privileged_networks
                .iter()
                .any(|network| !is_redacted_ssid(&network.ssid))
            {
                networks = merge_redacted_networks(networks, privileged_networks);
            }
        }
    }

    if let Some(current) = current {
        restore_current_network_name(&mut networks, &current);
    }

    if networks.is_empty() {
        bail!("No Wi-Fi networks detected from system_profiler.");
    }

    Ok(networks)
}

#[cfg(not(target_os = "macos"))]
fn scan_macos() -> Result<Vec<Network>> {
    bail!("macOS scanning is only available on macOS.")
}

fn scan_linux_nmcli() -> Result<Vec<Network>> {
    let output = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "SSID,CHAN,SIGNAL,SECURITY",
            "device",
            "wifi",
            "list",
            "--rescan",
            "yes",
        ])
        .output()
        .context("run nmcli wifi scan")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nmcli scan failed: {}", stderr.trim());
    }

    parse_nmcli_output(&String::from_utf8_lossy(&output.stdout))
}

#[derive(Deserialize)]
struct MacNetworkRecord {
    ssid: String,
    channel: u16,
    signal_dbm: i16,
    security: String,
}

#[allow(dead_code)]
fn parse_macos_json(input: &str) -> Result<Vec<Network>> {
    let records: Vec<MacNetworkRecord> =
        serde_json::from_str(input).context("parse CoreWLAN JSON")?;
    Ok(records
        .into_iter()
        .map(|record| Network {
            band: infer_band(record.channel),
            ssid: record.ssid,
            channel: record.channel,
            signal_dbm: record.signal_dbm,
            security: record.security,
        })
        .collect())
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
struct CurrentWifiContext {
    ssid: String,
    channel: u16,
    security: String,
}

#[cfg(target_os = "macos")]
fn current_wifi_context() -> Result<Option<CurrentWifiContext>> {
    let interface = detect_wifi_interface()?;
    let Some(interface) = interface else {
        return Ok(None);
    };

    let ssid = current_wifi_ssid(&interface)?;
    let channel = current_wifi_channel(&interface)?;
    let security = current_wifi_security(&interface)?.unwrap_or_else(|| "Connected".into());

    match (ssid, channel) {
        (Some(ssid), Some(channel)) => Ok(Some(CurrentWifiContext {
            ssid,
            channel,
            security,
        })),
        _ => Ok(None),
    }
}

#[cfg(target_os = "macos")]
fn detect_wifi_interface() -> Result<Option<String>> {
    let output = Command::new("networksetup")
        .arg("-listallhardwareports")
        .output()
        .context("discover macOS Wi-Fi interface")?;

    if !output.status.success() {
        return Ok(Some("en0".into()));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut saw_wifi_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Hardware Port:") {
            saw_wifi_block = trimmed.contains("Wi-Fi") || trimmed.contains("AirPort");
            continue;
        }
        if saw_wifi_block && trimmed.starts_with("Device:") {
            return Ok(trimmed
                .split_once(':')
                .map(|(_, value)| value.trim().to_string())
                .filter(|value| !value.is_empty()));
        }
    }

    Ok(Some("en0".into()))
}

#[cfg(target_os = "macos")]
fn current_wifi_ssid(interface: &str) -> Result<Option<String>> {
    let networksetup = Command::new("networksetup")
        .args(["-getairportnetwork", interface])
        .output()
        .context("read current macOS Wi-Fi network")?;
    if networksetup.status.success() {
        let text = String::from_utf8_lossy(&networksetup.stdout);
        if let Some((_, value)) = text.split_once(": ") {
            let ssid = value.trim();
            if !ssid.is_empty()
                && !ssid.eq_ignore_ascii_case("You are not associated with an AirPort network.")
            {
                return Ok(Some(ssid.to_string()));
            }
        }
    }

    let ipconfig = Command::new("ipconfig")
        .args(["getsummary", interface])
        .output()
        .context("read current macOS Wi-Fi summary")?;
    if !ipconfig.status.success() {
        return Ok(None);
    }

    let text = String::from_utf8_lossy(&ipconfig.stdout);
    Ok(text
        .lines()
        .find_map(|line| {
            line.split_once("SSID : ")
                .map(|(_, value)| value.trim().to_string())
        })
        .filter(|ssid| !ssid.is_empty() && !is_redacted_ssid(ssid)))
}

#[cfg(target_os = "macos")]
fn current_wifi_channel(interface: &str) -> Result<Option<u16>> {
    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("launch scutil for macOS Wi-Fi channel")?;

    if let Some(mut stdin) = child.stdin.take() {
        write!(stdin, "show State:/Network/Interface/{interface}/AirPort\n")?;
    }

    let output = child.wait_with_output().context("read scutil output")?;
    if !output.status.success() {
        return Ok(None);
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text.lines().find_map(|line| {
        if line.contains("CHANNEL") {
            line.split_whitespace().last()?.parse::<u16>().ok()
        } else {
            None
        }
    }))
}

#[cfg(target_os = "macos")]
fn current_wifi_security(interface: &str) -> Result<Option<String>> {
    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("launch scutil for macOS Wi-Fi security")?;

    if let Some(mut stdin) = child.stdin.take() {
        write!(stdin, "show State:/Network/Interface/{interface}/AirPort\n")?;
    }

    let output = child.wait_with_output().context("read scutil output")?;
    if !output.status.success() {
        return Ok(None);
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text.lines().find_map(|line| {
        if line.contains("AUTH_TYPE") {
            line.split_whitespace()
                .last()
                .map(|value| value.to_string())
        } else {
            None
        }
    }))
}

#[cfg(target_os = "macos")]
fn run_system_profiler_scan(use_sudo: bool) -> Result<Vec<Network>> {
    let mut command = if use_sudo {
        let mut command = Command::new("sudo");
        command.args(["-n", "system_profiler", "SPAirPortDataType"]);
        command
    } else {
        let mut command = Command::new("system_profiler");
        command.arg("SPAirPortDataType");
        command
    };

    let output = command.output().context("run system_profiler wifi scan")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("system_profiler scan failed: {}", stderr.trim());
    }

    parse_system_profiler_output(&String::from_utf8_lossy(&output.stdout))
}

fn is_redacted_ssid(ssid: &str) -> bool {
    let normalized = ssid.trim();
    normalized.eq_ignore_ascii_case("<redacted>")
        || normalized.eq_ignore_ascii_case("[redacted]")
        || normalized.eq_ignore_ascii_case("redacted")
        || normalized.starts_with("<Hidden")
}

#[cfg(target_os = "macos")]
fn restore_current_network_name(networks: &mut Vec<Network>, current: &CurrentWifiContext) {
    if let Some(network) = networks
        .iter_mut()
        .find(|network| network.channel == current.channel)
    {
        if is_redacted_ssid(&network.ssid) {
            network.ssid = current.ssid.clone();
        }
        if network.security == "Unknown" {
            network.security = current.security.clone();
        }
    } else {
        networks.push(Network {
            ssid: current.ssid.clone(),
            channel: current.channel,
            signal_dbm: -55,
            security: current.security.clone(),
            band: infer_band(current.channel),
        });
    }
}

fn normalize_security_for_merge(raw: &str) -> String {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() || trimmed == "unknown" {
        return String::new();
    }
    let stripped = trimmed
        .strip_suffix(" personal")
        .map(str::trim)
        .unwrap_or(trimmed.as_str());
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn security_matches_for_merge(primary: &str, candidate: &str) -> bool {
    let p = normalize_security_for_merge(primary);
    let c = normalize_security_for_merge(candidate);
    if p.is_empty() || c.is_empty() {
        return true;
    }
    p == c
}

fn pick_candidate_by_signal<'a>(
    candidates: &[&'a Network],
    reference_dbm: i16,
) -> Option<&'a Network> {
    if candidates.is_empty() {
        return None;
    }
    if candidates.len() == 1 {
        return Some(candidates[0]);
    }
    candidates
        .iter()
        .min_by_key(|c| (c.signal_dbm as i32 - reference_dbm as i32).abs())
        .copied()
}

fn merge_redacted_networks(mut primary: Vec<Network>, privileged: Vec<Network>) -> Vec<Network> {
    for network in &mut primary {
        if !is_redacted_ssid(&network.ssid) {
            continue;
        }

        let candidates: Vec<&Network> = privileged
            .iter()
            .filter(|c| c.channel == network.channel && !is_redacted_ssid(&c.ssid))
            .collect();

        if candidates.is_empty() {
            continue;
        }

        let narrowed: Vec<&Network> = if normalize_security_for_merge(&network.security).is_empty()
        {
            Vec::new()
        } else {
            candidates
                .iter()
                .copied()
                .filter(|c| security_matches_for_merge(&network.security, &c.security))
                .collect()
        };

        let best = if !narrowed.is_empty() {
            pick_candidate_by_signal(&narrowed, network.signal_dbm)
        } else {
            pick_candidate_by_signal(&candidates, network.signal_dbm)
        };

        if let Some(chosen) = best {
            network.ssid = chosen.ssid.clone();
        }
    }

    primary
}

#[cfg(target_os = "macos")]
fn parse_system_profiler_output(input: &str) -> Result<Vec<Network>> {
    #[derive(Default)]
    struct Pending {
        ssid: Option<String>,
        channel: Option<u16>,
        signal_dbm: Option<i16>,
        security: Option<String>,
    }

    fn finish(pending: &mut Pending, out: &mut Vec<Network>) {
        let Some(channel) = pending.channel else {
            *pending = Pending::default();
            return;
        };

        let ssid = pending
            .ssid
            .take()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "<Hidden>".into());
        let signal_dbm = pending.signal_dbm.unwrap_or(-85);
        let security = pending
            .security
            .take()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "Unknown".into());

        out.push(Network {
            band: infer_band(channel),
            ssid,
            channel,
            signal_dbm,
            security,
        });
        *pending = Pending::default();
    }

    let mut in_wifi_networks = false;
    let mut section_indent = 0usize;
    let mut pending = Pending::default();
    let mut networks = Vec::new();

    for raw_line in input.lines() {
        let indent = raw_line.chars().take_while(|ch| *ch == ' ').count();
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        if line == "Current Network Information:" || line == "Other Local Wi-Fi Networks:" {
            finish(&mut pending, &mut networks);
            in_wifi_networks = true;
            section_indent = indent;
            continue;
        }

        if in_wifi_networks && indent <= section_indent {
            finish(&mut pending, &mut networks);
            in_wifi_networks = false;
        }

        if !in_wifi_networks {
            continue;
        }

        if line.ends_with(':') && !line.contains(": ") {
            finish(&mut pending, &mut networks);
            pending.ssid = Some(line.trim_end_matches(':').trim().to_string());
            continue;
        }

        if let Some(value) = line.strip_prefix("Channel:") {
            pending.channel = value
                .trim()
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u16>().ok());
            continue;
        }

        if let Some(value) = line.strip_prefix("Security:") {
            pending.security = Some(value.trim().to_string());
            continue;
        }

        if let Some(value) = line.strip_prefix("Signal / Noise:") {
            pending.signal_dbm = value
                .trim()
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<i16>().ok());
        }
    }

    finish(&mut pending, &mut networks);
    Ok(networks)
}

fn parse_nmcli_output(input: &str) -> Result<Vec<Network>> {
    input
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_nmcli_line)
        .collect()
}

fn parse_nmcli_line(line: &str) -> Result<Network> {
    let mut fields = line.rsplitn(4, ':').collect::<Vec<_>>();
    fields.reverse();
    if fields.len() != 4 {
        return Err(anyhow!("unable to parse nmcli line: {line}"));
    }

    let ssid = fields[0].replace("\\:", ":");
    let channel: u16 = fields[1].parse().context("parse nmcli channel")?;
    let signal_percent: i16 = fields[2].parse().context("parse nmcli signal percentage")?;
    let signal_dbm = ((signal_percent as f32 / 100.0) * 70.0 - 100.0).round() as i16;
    let security = if fields[3].is_empty() {
        "Open".into()
    } else {
        fields[3].replace("\\:", ":")
    };

    Ok(Network {
        ssid,
        channel,
        signal_dbm,
        security,
        band: band_from_nmcli(channel),
    })
}

fn band_from_nmcli(channel: u16) -> Band {
    infer_band(channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nmcli_rows() {
        let network = parse_nmcli_line("Office WiFi:44:78:WPA2").expect("row parses");
        assert_eq!(network.ssid, "Office WiFi");
        assert_eq!(network.channel, 44);
        assert_eq!(network.band, Band::Ghz5);
    }

    #[test]
    fn parses_macos_json() {
        let json = r#"[{"ssid":"Cafe","channel":6,"signal_dbm":-51,"security":"WPA2"}]"#;
        let networks = parse_macos_json(json).expect("json parses");
        assert_eq!(networks[0].band, Band::Ghz24);
    }

    #[test]
    fn merge_redacted_matches_when_primary_security_unknown() {
        let primary = vec![Network {
            ssid: "<redacted>".into(),
            channel: 6,
            signal_dbm: -65,
            security: "Unknown".into(),
            band: Band::Ghz24,
        }];
        let privileged = vec![Network {
            ssid: "Cafe".into(),
            channel: 6,
            signal_dbm: -67,
            security: "WPA2 Personal".into(),
            band: Band::Ghz24,
        }];
        let merged = merge_redacted_networks(primary, privileged);
        assert_eq!(merged[0].ssid, "Cafe");
    }

    #[test]
    fn merge_redacted_prefers_security_match_over_signal() {
        let primary = vec![Network {
            ssid: "<redacted>".into(),
            channel: 6,
            signal_dbm: -50,
            security: "WPA2 Personal".into(),
            band: Band::Ghz24,
        }];
        let privileged = vec![
            Network {
                ssid: "WrongNet".into(),
                channel: 6,
                signal_dbm: -49,
                security: "WPA3 Personal".into(),
                band: Band::Ghz24,
            },
            Network {
                ssid: "RightNet".into(),
                channel: 6,
                signal_dbm: -80,
                security: "WPA2 Personal".into(),
                band: Band::Ghz24,
            },
        ];
        let merged = merge_redacted_networks(primary, privileged);
        assert_eq!(merged[0].ssid, "RightNet");
    }

    #[test]
    fn merge_redacted_picks_closest_signal_when_multiple_on_channel() {
        let primary = vec![Network {
            ssid: "<redacted>".into(),
            channel: 11,
            signal_dbm: -58,
            security: "Unknown".into(),
            band: Band::Ghz24,
        }];
        let privileged = vec![
            Network {
                ssid: "Far".into(),
                channel: 11,
                signal_dbm: -80,
                security: "WPA2 Personal".into(),
                band: Band::Ghz24,
            },
            Network {
                ssid: "Near".into(),
                channel: 11,
                signal_dbm: -57,
                security: "WPA3 Personal".into(),
                band: Band::Ghz24,
            },
        ];
        let merged = merge_redacted_networks(primary, privileged);
        assert_eq!(merged[0].ssid, "Near");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_system_profiler_scan() {
        let sample = r#"
Wi-Fi:

    Interfaces:
      en0:
        Current Network Information:
          HomeNet:
            PHY Mode: 802.11ax
            Channel: 149 (5GHz, 80MHz)
            Network Type: Infrastructure
            Security: WPA2 Personal
            Signal / Noise: -53 dBm / -90 dBm
        Other Local Wi-Fi Networks:
          Cafe:
            PHY Mode: 802.11n
            Channel: 6 (2GHz, 20MHz)
            Network Type: Infrastructure
            Security: WPA2 Personal
            Signal / Noise: -67 dBm / -92 dBm
"#;
        let networks = parse_system_profiler_output(sample).expect("system_profiler parses");
        assert_eq!(networks.len(), 2);
        assert_eq!(networks[0].ssid, "HomeNet");
        assert_eq!(networks[1].channel, 6);
    }
}
