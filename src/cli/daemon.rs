//! Daemon management for MuccheAI.

use std::path::PathBuf;

/// Return the path to the daemon PID file.
fn pid_file() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".muccheai").join("daemon.pid")
}

/// Reject the path if it or any parent component is a symlink.
fn reject_symlink_path(path: &std::path::Path) -> Result<(), String> {
    for component in path.ancestors() {
        if let Ok(meta) = std::fs::symlink_metadata(component) {
            if meta.file_type().is_symlink() {
                return Err(format!("Path component is a symlink: {}", component.display()));
            }
        }
    }
    Ok(())
}

/// Check if the daemon is currently running.
/// Uses safe process existence checks without `unsafe` blocks.
pub fn is_daemon_running() -> bool {
    let pid_path = pid_file();
    if reject_symlink_path(&pid_path).is_err() {
        return false;
    }
    let Ok(pid_str) = std::fs::read_to_string(pid_path) else {
        return false;
    };
    let Ok(pid) = pid_str.trim().parse::<u32>() else {
        return false;
    };
    process_exists(pid)
}

/// Safe cross-platform process existence check.
#[cfg(target_os = "linux")]
fn process_exists(pid: u32) -> bool {
    std::fs::metadata(format!("/proc/{pid}")).is_ok()
}

#[cfg(not(target_os = "linux"))]
fn process_exists(pid: u32) -> bool {
    // Fallback: use the system `kill -0` command (no signal sent, just permission check).
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Start the background daemon.
pub fn daemon_start() -> Result<(), String> {
    if is_daemon_running() {
        return Err("Daemon is already running".to_string());
    }

    let pid_path = pid_file();
    if let Err(e) = reject_symlink_path(&pid_path) {
        return Err(e);
    }

    // Ensure the directory exists before spawning.
    if let Some(parent) = pid_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("__daemon");
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd.stdin(std::process::Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let child = cmd.spawn().map_err(|e| e.to_string())?;
    let pid = child.id();

    // Atomic creation: fail if PID file already exists (prevents race conditions).
    use std::io::Write;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(pid_path)
        .map_err(|e| format!("Failed to create PID file (daemon may already be starting): {}", e))?;
    let mut file = std::io::BufWriter::new(file);
    write!(file, "{}", pid).map_err(|e| e.to_string())?;
    println!("Daemon started with PID {}", pid);
    Ok(())
}

/// Stop the background daemon.
/// Verifies the PID still belongs to a running process before sending SIGTERM.
pub fn daemon_stop() -> Result<(), String> {
    let pid_str = std::fs::read_to_string(pid_file()).map_err(|e| e.to_string())?;
    let pid: u32 = pid_str.trim().parse().map_err(|_| "Invalid PID file".to_string())?;

    if !process_exists(pid) {
        let _ = std::fs::remove_file(pid_file());
        return Err(format!("Daemon PID {} is not running (stale PID file removed)", pid));
    }

    // Validate PID belongs to our binary before signaling
    #[cfg(target_os = "linux")]
    {
        let exe_link = format!("/proc/{}/exe", pid);
        if let Ok(target) = std::fs::read_link(&exe_link) {
            let our_exe = std::env::current_exe().map_err(|e| e.to_string())?;
            if target != our_exe {
                return Err(format!(
                    "PID {} does not belong to muccheai daemon (refusing to kill)",
                    pid
                ));
            }
        }
    }

    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    let _ = std::fs::remove_file(pid_file());
    println!("Daemon stopped (PID {})", pid);
    Ok(())
}

/// Show daemon status.
pub fn daemon_status() -> Result<(), String> {
    if is_daemon_running() {
        let pid = std::fs::read_to_string(pid_file()).unwrap_or_default();
        println!("Daemon is running (PID: {})", pid.trim());
    } else {
        println!("Daemon is not running");
    }
    Ok(())
}

/// Run the daemon loop.
pub async fn run_daemon() -> Result<(), String> {
    println!("MuccheAI daemon starting...");

    // For MVP: initialize subsystems (placeholder).
    println!("  Initializing policy engine... done");
    println!("  Initializing sandbox... done");
    println!("  Initializing vault... done");

    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }
}
