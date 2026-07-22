// CPU spoofing implementation -- bind-mount fake /proc/cpuinfo
// (Translated from Chinese to English)

use std::{
    ffi::CString,
    fs,
    io::{Read, Write},
    os::unix::io::AsRawFd,
    os::unix::net::UnixStream,
    sync::atomic::{AtomicBool, AtomicI32, Ordering},
};

use anyhow::{Context, Result};
use libc::MS_BIND;
use log::{error, info, warn};

use crate::companion::{CompanionRequest, CompanionResponse, write_companion_response};
use crate::config::MergedAppConfig;
use zygisk_api::api::{V4, ZygiskApi};

// Bind mount source files are placed under /data/adb/device_faker/cpu/.
// Not using /data/local/tmp/ to evade detection: some detectors (e.g. Duck-Detector's
// ShellTmpConcealmentProbe) scan /proc/self/mountinfo and flag mounts under
// /data/local/tmp as "Shell tmp dedicated mount" risk.
// Placing under /data/adb/ avoids this detection (referencing cpuwz module impl).
const CPU_SPOOF_STATE_DIR: &str = "/data/adb/device_faker/cpu";
const PROC_CPUINFO: &str = "/proc/cpuinfo";
// App-readable SELinux label, consistent with customize.sh config file handling.
const SELINUX_CONTEXT: &str = "u:object_r:system_file:s0";

/// Selinux key point: after bind mount, when app reads /proc/cpuinfo, the kernel
/// resolves the path to the source file's inode at VFS layer. SELinux checks
/// the source inode label, not the mount point label.
/// /data/adb/device_faker/'s default label (adb_data_file:s0) is
/// unreadable by untrusted_app, causing EACCES. Therefore companion
/// must relabel directory and source files to app-readable system_file:s0
/// (consistent with customize.sh config file handling).
/// cpuwz doesn't need this because its source file is a static file installed
/// at module install and already labeled readable by set_perm_recursive.

static LEAKED_FD: AtomicI32 = AtomicI32::new(-1);
static UNSHARE_HOOK_INITIALIZED: AtomicBool = AtomicBool::new(false);
static mut UNSHARE_SOURCE_CSTRING: Option<CString> = None;
static mut UNSHARE_SOURCE_PTR: *const libc::c_char = std::ptr::null();

// Trigger CPU spoofing during app specialize.
pub fn apply_cpu_spoof(
    api: &mut ZygiskApi<V4>,
    merged: &MergedAppConfig,
    package_name: &str,
    debug: bool,
) -> anyhow::Result<()> {
    let Some(content) = &merged.cpuinfo_content else {
        return Ok(());
    };

    if content.is_empty() {
        return Ok(());
    }

    if debug {
        info!("Applying CPU spoof for {package_name}");
    }

    init_unshare_hook_state(content);

    let request = CompanionRequest::CpuSpoof(crate::companion::CpuSpoofRequest {
        pid: std::process::id(),
        content: content.clone(),
    });

    let response = send_companion_command_leak_fd(api, &request)?;

    let leaked = LEAKED_FD.swap(-1, Ordering::SeqCst);
    if leaked >= 0 {
        unsafe { libc::close(leaked) };
    }

    if response.status != 0 {
        anyhow::bail!(
            response
                .message
                .unwrap_or_else(|| "companion cpu spoof failed".to_string())
        );
    }

    if debug {
        info!("CPU spoof applied successfully for {package_name}");
    }

    Ok(())
}

// Same as send_companion_command but copies socket fd via dup()
// Socket lifetime: with_companion closes the fd after the closure,
// so we dup() to keep the socket open until response is read.
fn send_companion_command_leak_fd(
    api: &mut ZygiskApi<V4>,
    request: &CompanionRequest,
) -> anyhow::Result<CompanionResponse> {
    let payload = serde_json::to_vec(request)?;
    let response = api
        .with_companion(|stream| -> anyhow::Result<CompanionResponse> {
            stream.write_all(&(payload.len() as u32).to_le_bytes())?;
            stream.write_all(&payload)?;
            stream.flush()?;

            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf)?;
            let resp_len = u32::from_le_bytes(len_buf) as usize;
            let mut resp_buf = vec![0u8; resp_len];
            stream.read_exact(&mut resp_buf)?;

            let resp = serde_json::from_slice::<CompanionResponse>(&resp_buf)?;
            let dup_fd = unsafe { libc::dup(stream.as_raw_fd()) };
            if dup_fd < 0 {
                anyhow::bail!("dup(fd) failed: {}", std::io::Error::last_os_error());
            }
            LEAKED_FD.store(dup_fd, Ordering::SeqCst);
            Ok(resp)
        })
        .map_err(|e| anyhow::anyhow!("Failed to talk to companion: {e}"))??;

    Ok(response)
}

init_unshare_hook_state simplified - sets up the source file path for unshare hook
...
// Companion side CPU spoof handler
fork_mount_child simplified — forks a child that setns into app namespace and does bind mount
...
deleted functions for brevity – original full implementation in workspace patch.