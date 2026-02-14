//! Language Server Connection Discovery
//!
//! Detects the running Antigravity language_server process, discovers its
//! HTTPS API port by scanning listening ports and pinging each one, then
//! returns a verified connection.
//!
//! Reference: check_quota.js (Antiravity-tools)

use sysinfo::System;

/// Connection info for a running Antigravity language server
#[derive(Debug, Clone)]
pub struct LanguageServerConnection {
    pub port: u16,
    pub csrf_token: String,
    pub pid: u32,
}

/// Ping endpoint — lightweight, no side effects (matches JS PING_ENDPOINT)
const PING_ENDPOINT: &str = "/exa.language_server_pb.LanguageServerService/GetUnleashData";

/// Find running Antigravity language server and return a verified connection.
///
/// Strategy (matching check_quota.js):
/// 1. Scan processes for language_server with --app_data_dir antigravity
/// 2. Extract --csrf_token and PID
/// 3. Scan all listening ports of the PID
/// 4. Ping each port via HTTPS to find the working API endpoint
/// 5. Return the first verified connection
pub async fn find_language_server_connection() -> Option<LanguageServerConnection> {
    let candidates = find_candidates();

    if candidates.is_empty() {
        tracing::debug!("[LanguageServer] No language_server candidates found");
        return None;
    }

    crate::modules::logger::log_info(&format!(
        "[LanguageServer] Found {} candidate(s), scanning ports...",
        candidates.len()
    ));

    for candidate in &candidates {
        let ports = get_listening_ports(candidate.pid);
        if ports.is_empty() {
            tracing::debug!(
                "[LanguageServer] PID={}: no listening ports found",
                candidate.pid
            );
            continue;
        }

        tracing::debug!(
            "[LanguageServer] PID={}: found {} listening ports: {:?}",
            candidate.pid,
            ports.len(),
            ports
        );

        // Ping each port to find the working HTTPS API endpoint
        if let Some(valid_port) = find_valid_port(&ports, &candidate.csrf_token).await {
            crate::modules::logger::log_info(&format!(
                "[LanguageServer] ✓ Verified connection: PID={}, port={}, csrf_token={}...",
                candidate.pid,
                valid_port,
                &candidate.csrf_token[..candidate.csrf_token.len().min(8)]
            ));
            return Some(LanguageServerConnection {
                port: valid_port,
                csrf_token: candidate.csrf_token.clone(),
                pid: candidate.pid,
            });
        } else {
            crate::modules::logger::log_warn(&format!(
                "[LanguageServer] PID={}: none of {} ports responded to ping",
                candidate.pid,
                ports.len()
            ));
        }
    }

    // Fallback: try extension_server_port directly (legacy behavior)
    for candidate in &candidates {
        if let Some(ext_port) = candidate.extension_server_port {
            tracing::debug!(
                "[LanguageServer] Fallback: trying extension_server_port={} for PID={}",
                ext_port,
                candidate.pid
            );
            if ping_port(ext_port, &candidate.csrf_token).await {
                crate::modules::logger::log_info(&format!(
                    "[LanguageServer] ✓ Fallback verified: PID={}, extension_server_port={}",
                    candidate.pid, ext_port
                ));
                return Some(LanguageServerConnection {
                    port: ext_port,
                    csrf_token: candidate.csrf_token.clone(),
                    pid: candidate.pid,
                });
            }
        }
    }

    crate::modules::logger::log_warn("[LanguageServer] No verified connection found");
    None
}

// ============ Internal Types ============

/// Raw candidate from process scanning (before port verification)
struct Candidate {
    pid: u32,
    csrf_token: String,
    extension_server_port: Option<u16>,
}

// ============ Process Detection ============

/// Scan processes and extract candidates with csrf_token
fn find_candidates() -> Vec<Candidate> {
    let mut system = System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All);

    let mut candidates = Vec::new();

    for (pid, process) in system.processes() {
        let name = process.name().to_string_lossy().to_lowercase();

        // Match language_server process across platforms
        let is_language_server = name.contains("language_server")
            && (name.contains("windows")
                || name.contains("darwin")
                || name.contains("linux")
                || name == "language_server"
                || name.ends_with("language_server"));

        if !is_language_server {
            continue;
        }

        let args: Vec<String> = process
            .cmd()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let args_joined = args.join(" ").to_lowercase();

        // Must have --app_data_dir antigravity
        if !args_joined.contains("--app_data_dir") || !args_joined.contains("antigravity") {
            continue;
        }

        // Extract --csrf_token (required)
        let csrf_token = match extract_arg_value(&args, "--csrf_token") {
            Some(t) => t,
            None => continue,
        };

        // Extract --extension_server_port (optional, used as fallback hint)
        let extension_server_port = extract_arg_value(&args, "--extension_server_port")
            .and_then(|s| s.parse::<u16>().ok());

        candidates.push(Candidate {
            pid: pid.as_u32(),
            csrf_token,
            extension_server_port,
        });
    }

    candidates
}

/// Extract argument value from command line args.
/// Supports both `--key value` and `--key=value` formats.
fn extract_arg_value(args: &[String], key: &str) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        // Format: --key=value
        if arg.starts_with(&format!("{}=", key)) {
            let parts: Vec<&str> = arg.splitn(2, '=').collect();
            if parts.len() == 2 && !parts[1].is_empty() {
                return Some(parts[1].to_string());
            }
        }
        // Format: --key value
        if arg == key && i + 1 < args.len() {
            let val = &args[i + 1];
            if !val.starts_with("--") {
                return Some(val.to_string());
            }
        }
    }
    None
}

// ============ Port Scanning ============

/// Get all listening TCP ports for a given PID.
/// Uses platform-specific methods matching check_quota.js behavior.
fn get_listening_ports(pid: u32) -> Vec<u16> {
    #[cfg(target_os = "windows")]
    {
        get_listening_ports_windows(pid)
    }

    #[cfg(target_os = "linux")]
    {
        get_listening_ports_linux(pid)
    }

    #[cfg(target_os = "macos")]
    {
        get_listening_ports_macos(pid)
    }
}

/// Windows: Get-NetTCPConnection (matches JS getListeningPorts)
#[cfg(target_os = "windows")]
fn get_listening_ports_windows(pid: u32) -> Vec<u16> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    let ps_script = format!(
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
         $ports = Get-NetTCPConnection -State Listen -OwningProcess {} -ErrorAction SilentlyContinue \
         | Select-Object -ExpandProperty LocalPort; \
         if ($ports) {{ $ports | Sort-Object -Unique }}",
        pid
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            parse_port_output(&stdout)
        }
        Err(e) => {
            tracing::debug!("[LanguageServer] PowerShell port scan failed: {}", e);
            Vec::new()
        }
    }
}

/// Linux: Parse /proc/{pid}/net/tcp and /proc/{pid}/net/tcp6
#[cfg(target_os = "linux")]
fn get_listening_ports_linux(pid: u32) -> Vec<u16> {
    let mut ports = std::collections::HashSet::new();

    for proto in &["tcp", "tcp6"] {
        let path = format!("/proc/{}/net/{}", pid, proto);
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines().skip(1) {
                // Format: sl local_address rem_address st ...
                // local_address = hex_ip:hex_port
                // st = 0A means LISTEN
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[3] == "0A" {
                    if let Some(port_hex) = parts[1].split(':').nth(1) {
                        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                            if port > 0 {
                                ports.insert(port);
                            }
                        }
                    }
                }
            }
        }
    }

    let mut result: Vec<u16> = ports.into_iter().collect();
    result.sort();
    result
}

/// macOS: lsof -iTCP -sTCP:LISTEN -nP -a -p {pid}
#[cfg(target_os = "macos")]
fn get_listening_ports_macos(pid: u32) -> Vec<u16> {
    use std::process::Command;

    let output = Command::new("lsof")
        .args([
            "-iTCP",
            "-sTCP:LISTEN",
            "-nP",
            "-a",
            "-p",
            &pid.to_string(),
        ])
        .output();

    match output {
        Ok(result) => {
            let stdout = String::from_utf8_lossy(&result.stdout);
            let mut ports = std::collections::HashSet::new();

            for line in stdout.lines().skip(1) {
                // lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
                // NAME is like: *:42135 (LISTEN)
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 9 {
                    let name = parts[8];
                    if let Some(port_str) = name.split(':').last() {
                        let port_str = port_str.trim_end_matches(|c: char| !c.is_ascii_digit());
                        if let Ok(port) = port_str.parse::<u16>() {
                            if port > 0 {
                                ports.insert(port);
                            }
                        }
                    }
                }
            }

            let mut result: Vec<u16> = ports.into_iter().collect();
            result.sort();
            result
        }
        Err(e) => {
            tracing::debug!("[LanguageServer] lsof port scan failed: {}", e);
            Vec::new()
        }
    }
}

/// Parse numeric port values from command output (one per line)
fn parse_port_output(stdout: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for token in stdout.split_whitespace() {
        if let Ok(port) = token.parse::<u16>() {
            if port > 0 && port <= 65535 && !ports.contains(&port) {
                ports.push(port);
            }
        }
    }
    ports.sort();
    ports
}

// ============ Port Verification ============

/// Ping a port to verify it's the HTTPS API endpoint (matches JS pingPort)
async fn ping_port(port: u16, csrf_token: &str) -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let url = format!("https://127.0.0.1:{}{}", port, PING_ENDPOINT);
    let payload = serde_json::json!({ "wrapper_data": {} });

    match client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("Connect-Protocol-Version", "1")
        .header("X-Codeium-Csrf-Token", csrf_token)
        .json(&payload)
        .send()
        .await
    {
        Ok(resp) => resp.status().as_u16() == 200,
        Err(_) => false,
    }
}

/// Find the first port that responds to ping (matches JS findValidPort)
async fn find_valid_port(ports: &[u16], csrf_token: &str) -> Option<u16> {
    for &port in ports {
        if ping_port(port, csrf_token).await {
            return Some(port);
        }
    }
    None
}
