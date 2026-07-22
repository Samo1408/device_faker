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
// /data/local/tmp and its sub-paths as "Shell tmp dedicated mount" risk.
// Placing under /data/adb/ avoids this detection (referencing cpuwz module impl).
//
// SELinux key point: after bind mount, when the app reads /proc/cpuinfo, the kernel resolves
// the path to the source file's inode at the VFS layer. SELinux checks the ** source inode label**,
// not the mount point label. /data/adb/device_faker/'s default label
// (adb_data_file:s0, etc.) is unreadable by untrusted_app, causing EACCES on open().
// Therefore companion must relabel the directory and source files to
// app-readable system_file:s0 (consistent with customize.sh config file handling).
// cpuwz doesn't need this step because its source file is a static file installed
// at module install and already labeled readable by Magisk/KSU set_perm_recursive.
const CPU_SPOOF_STATE_DIR: &str = "/data/adb/device_faker/cpu";
const PROC_CPUINFO: &str = "/proc/cpuinfo";
// App-readable SELinux label, consistent with customize.sh config file setting.
const SELINUX_CONTEXT: &str = "u:object_r:system_file:s0";

/// Trigger CPU spoofing during app specialize.
/// Uses companion process to bind mount in the target app's mount namespace.
///
/// **Mount namespace strategy**: Zygisk companion (zygiskd) runs in root mount namespace
/// (forked from magiskd, does not execute setns). /proc in Android is MS_PRIVATE propagation,
/// root namespace's bind mount won't propagate to the app's isolated namespace.
///
/// Because companion may be **multi-threaded** (thread pool), calling `setns(CLONE_NEWNS)`
/// directly would return `EINVAL` (Linux rejects CLONE_NEWNS for multi-threaded processes).
/// So mount/unmount operations are completed via **fork child process**: the child process after fork
/// is single-threaded and can safely call `setns` to switch to the app's mount namespace.
///
/// App exit detection is handled by companion-side `pidfd_open` + `poll()`,
/// completely independent of socket fd, with no fd inheritance issues.
static LEAKED_FD: AtomicI32 = AtomicI32::new(-1);

/// Whether the source file path has been initialized.
static UNSHARE_HOOK_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Leaked CString holding the fake cpuinfo source file path.
/// Set in init_unshare_hook_state, never dropped (hook needs 'static lifetime').
static mut UNSHARE_SOURCE_CSTRING: Option<CString> = None;

/// C string pointer to the fake cpuinfo source file, held by UNSHARE_SOURCE_CSTRING.
/// Only accessed after UNSHARE_HOOK_INITIALIZED is true.
static mut UNSHARE_SOURCE_PTR: *const libc::c_char = std::ptr::null();

/// **Socket lifetime**: The companion_sock inside with_companion is a local variable,
/// automatically dropped and closed after the closure returns. We use `libc::dup()` inside the closure
/// to copy the fd and store the copy in `LEAKED_FD`. The original fd is closed when the closure ends,
/// but the copy remains open. Note: the copy is **immediately closed** in `apply_cpu_spoof`,
/// so it does not leak into the app process.
/// App exit detection is done via companion-side pipe EOF.
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

/// Same as `send_companion_command` but copies the socket fd via `libc::dup()`.
///
/// The `companion_sock` (local variable) inside `with_companion` is automatically dropped and closed
/// after the closure returns, so we must use `libc::dup()` to copy the fd to keep the socket open until
/// the response is read completely. The copy is stored in `LEAKED_FD` and closed inside `apply_cpu_spoof`.
/// App exit detection is handled by companion-side pidfd + poll, independent of socket state.
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

            // The dup'd fd is only used to keep the socket open until response reading completes,
            // then immediately closed.
            // App exit detection uses companion pidfd + poll.
            let dup_fd = unsafe { libc::dup(stream.as_raw_fd()) };
            if dup_fd < 0 {
                anyhow::bail!("dup(fd) failed: {}", std::io::Error::last_os_error());
            }
            LEAKED_FD.store(dup_fd, Ordering::SeqCst);
            info!("Dup'd companion fd {dup_fd} (will close after response)");

            Ok(resp)
        })
        .map_err(|e| anyhow::anyhow!("Failed to talk to companion: {e}"))??;

    Ok(response)
}

// ----------------------------------------------------------------------------
// unshare PLT hook implementation
// ----------------------------------------------------------------------------

/// Initialize the global state for unshare hook (source file path).
/// Must be called before `register_unshare_hook` and in the app process (not companion).
fn init_unshare_hook_state(source_path: &str) {
    // Safety: single-threaded context (pre_app_specialize), no further modifications after write.
    unsafe {
        let cs = CString::new(source_path).expect("source_path contained NUL");
        UNSHARE_SOURCE_PTR = cs.as_ptr();
        UNSHARE_SOURCE_CSTRING = Some(cs);
        UNSHARE_HOOK_INITIALIZED.store(true, Ordering::Release);
    }
    info!("unshare hook state initialized: {source_path}");
}

// ----------------------------------------------------------------------------
// PLT hook implementation removed: plt_hook_commit fix GOT table scan triggers app anti-tampering.
// CPU spoof currently only relies on companion bind mount + mount child's timerfd namespace check.
// ----------------------------------------------------------------------------

/// Companion side entry point: process CPU spoof requests.
///
/// **Process exit detection strategy: pipe EOF event-driven**
/// The companion reads EOF from exit pipe to detect app exit; mount child handles pidfd monitoring.
/// Each companion connection is independent, blocking does not affect other app companion requests.
pub fn handle_companion_cpu_spoof(
    stream: &mut UnixStream,
    request: crate::companion::CpuSpoofRequest,
) {
    // Companion does not call ZygiskModule::on_load, so init logger manually.
    #[cfg(target_os = "android")]
    crate::file_logger::init();

    let pid = request.pid;
    info!(
        "Companion cpu_spoof handler entered, pid={pid}, self_pid={}",
        std::process::id()
    );

    let (setup_ok, mount_child_pid, exit_pipe_fd) = match do_cpu_spoof_setup(pid, &request.content)
    {
        Ok((child_pid, exit_fd)) => (true, child_pid, exit_fd),
        Err(e) => {
            error!("CPU spoof setup failed for pid {pid}: {e}");
            let response = CompanionResponse::err(e.to_string());
            if let Err(e) = write_companion_response(stream, &response) {
                warn!("Failed to write CPU spoof response: {e}");
            }
            (false, -1, -1)
        }
    };

    if setup_ok {
        // Send OK to module, let app continue.
        if let Err(e) = write_companion_response(stream, &CompanionResponse::ok()) {
            warn!("Failed to write CPU spoof response: {e}");
        }

        // Block waiting for app exit: read EOF from exit pipe (event-driven, zero polling).
        // mount child closes pipe when app exits, reader returns 0 bytes.
        let mut buf = [0u8; 1];
        let _ = unsafe { libc::read(exit_pipe_fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        unsafe { libc::close(exit_pipe_fd) };
        info!("Exit pipe signaled — app pid {pid} exited, cleaning up");

        // Wait for mount child
        let mut status = 0i32;
        unsafe { libc::waitpid(mount_child_pid, &mut status, 0) };

        // Clean up source file
        let internal_path = format!("{CPU_SPOOF_STATE_DIR}/cpu_{pid}");
        if let Err(e) = fs::remove_file(&internal_path) {
            warn!("Failed to remove cpuinfo source {internal_path}: {e}");
        }
    }
}

// ----------------------------------------------------------------------------
// Fork + setns framework
// ----------------------------------------------------------------------------
//
// Companion (zygiskd) may be multi-threaded (thread pool model), calling setns(CLONE_NEWNS)
// in a multi-threaded process returns EINVAL (Linux kernel restriction). The solution is fork child process —
// after fork, the child is single-threaded and can safely call setns.
//
// The child enters the app's mount namespace then **blocks waiting** (does not exit immediately),
// ensuring namespace reference keeps the bind mount active for the entire app lifecycle.
// Companion thread waits for app exit then notifies child through SIGTERM to execute umount cleanup.
// ----------------------------------------------------------------------------

/// Execute CPU spoof setup: write source file, fork child to enter app namespace and bind mount.
/// Returns (child_pid, exit pipe read fd).
/// The caller reads from the pipe reader to block — mount child closes pipe on app exit, reader gets EOF.
fn do_cpu_spoof_setup(pid: u32, content: &str) -> Result<(i32, i32)> {
    ensure_dir(CPU_SPOOF_STATE_DIR)?;
    set_selinux_context(CPU_SPOOF_STATE_DIR);

    let internal_path = format!("{CPU_SPOOF_STATE_DIR}/cpu_{pid}");
    fs::write(&internal_path, content)
        .with_context(|| format!("Failed to write internal cpuinfo file {internal_path}"))?;
    set_selinux_context(&internal_path);

    // Use fork+pipe to delegate mount operation to child process (child is single-threaded, can safely setns).
    let result = fork_mount_child(pid, &internal_path);

    match &result {
        Ok((child_pid, _)) => {
            info!("Successfully mounted fake cpuinfo for pid {pid} (child_pid={child_pid})")
        }
        Err(e) => {
            error!("Mount operation failed for pid {pid}: {e}");
            let _ = fs::remove_file(&internal_path);
        }
    }

    result
}

/// Fork child process: setns into app namespace → bind mount → monitor app exit.
///
/// The child reports success or failure through a result pipe (does **not exit**) to keep namespace reference.
/// The child monitors app exit (pidfd event-driven or procfs polling), closing exit pipe on exit.
/// The parent reads EOF from exit pipe to know app has exited, no polling needed.
///
/// Result Pipe Protocol:
/// - Success: write 4 bytes `0i32`
/// - Failure: write 4 bytes `-1i32` + 4 bytes msg_len + UTF-8 error message
///
/// Returns (child pid, exit pipe reader fd)
fn fork_mount_child(pid: u32, source_path: &str) -> Result<(i32, i32)> {
    let mut pipe_fds = [0i32; 2];
    // Result pipe: child reports mount result
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        anyhow::bail!("pipe failed: {}", std::io::Error::last_os_error());
    }
    let read_fd = pipe_fds[0];
    let write_fd = pipe_fds[1];

    // Exit notification pipe: child writes to close when app exits, parent reads EOF
    let mut exit_pipe = [0i32; 2];
    if unsafe { libc::pipe(exit_pipe.as_mut_ptr()) } != 0 {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        anyhow::bail!("exit pipe failed: {}", std::io::Error::last_os_error());
    }
    let exit_read_fd = exit_pipe[0];
    let exit_write_fd = exit_pipe[1];

    match unsafe { libc::fork() } {
        -1 => {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
                libc::close(exit_read_fd);
                libc::close(exit_write_fd);
            }
            anyhow::bail!("fork failed: {}", std::io::Error::last_os_error());
        }
        0 => {
            // === Child process (single-threaded, can safely setns) ===
            unsafe {
                libc::close(read_fd);
                libc::close(exit_read_fd); // child doesn't need exit pipe read end
            };
            let status = do_mount_in_child(pid, source_path);
            match status {
                Ok(()) => {
                    let code: i32 = 0;
                    unsafe {
                        libc::write(
                            write_fd,
                            &code as *const i32 as *const libc::c_void,
                            std::mem::size_of::<i32>(),
                        )
                    };
                }
                Err(e) => {
                    let msg = e.to_string();
                    let code: i32 = -1;
                    let msg_bytes = msg.as_bytes();
                    let msg_len = msg_bytes.len() as i32;
                    unsafe {
                        libc::write(
                            write_fd,
                            &code as *const i32 as *const libc::c_void,
                            std::mem::size_of::<i32>(),
                        );
                        libc::write(
                            write_fd,
                            &msg_len as *const i32 as *const libc::c_void,
                            std::mem::size_of::<i32>(),
                        );
                        libc::write(
                            write_fd,
                            msg_bytes.as_ptr() as *const libc::c_void,
                            msg_bytes.len(),
                        );
                        libc::close(write_fd);
                        libc::_exit(1);
                    }
                }
            }
            // Mount success: close pipe write end, then wait for app exit
            unsafe { libc::close(write_fd) };

            // Register SIGTERM handler (parent uses SIGTERM as fallback notification)
            unsafe {
                libc::signal(
                    libc::SIGTERM,
                    child_sigterm_handler as *const () as libc::sighandler_t,
                );
            }

            // Wait for namespace to settle, check if remount is needed, then wait for app exit.
            // KernelSU uses setns to switch namespace ~ 100ms after pre_app_specialize.
            // Use timerfd (kernel timer events) to wait 200ms then check namespace change.
            check_namespace_and_wait_exit(pid, source_path);

            // Notify companion: close exit pipe write → companion's read() returns EOF
            unsafe { libc::close(exit_write_fd) };

            // App has exited (or received SIGTERM), execute umount cleanup
            let _ = CString::new(PROC_CPUINFO).map(|target| {
                unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
            });
            unsafe { libc::_exit(0) }
        }
        child_pid => {
            // === Parent process (companion thread) ===
            unsafe {
                libc::close(write_fd);
                libc::close(exit_write_fd); // parent doesn't need exit pipe write end
            }

            // Read result code
            let mut code: i32 = -1;
            let n = unsafe {
                libc::read(
                    read_fd,
                    &mut code as *mut i32 as *mut libc::c_void,
                    std::mem::size_of::<i32>(),
                )
            };
            if n != std::mem::size_of::<i32>() as isize {
                unsafe {
                    libc::close(read_fd);
                    libc::close(exit_read_fd);
                }
                let mut status = 0i32;
                unsafe { libc::waitpid(child_pid, &mut status, 0) };
                anyhow::bail!("Failed to read mount result from child (read {n} bytes)");
            }

            if code != 0 {
                // Read error message
                let mut msg_len: i32 = 0;
                let n = unsafe {
                    libc::read(
                        read_fd,
                        &mut msg_len as *mut i32 as *mut libc::c_void,
                        std::mem::size_of::<i32>(),
                    )
                };
                let err_msg = if n == std::mem::size_of::<i32>() as isize && msg_len > 0 {
                    let mut buf = vec![0u8; msg_len as usize];
                    unsafe {
                        libc::read(
                            read_fd,
                            buf.as_mut_ptr() as *mut libc::c_void,
                            msg_len as usize,
                        )
                    };
                    String::from_utf8_lossy(&buf).to_string()
                } else {
                    format!("error code {code}")
                };
                unsafe {
                    libc::close(read_fd);
                    libc::close(exit_read_fd);
                }
                let mut status = 0i32;
                unsafe { libc::waitpid(child_pid, &mut status, 0) };
                anyhow::bail!("Mount child failed: {err_msg}");
            }

            unsafe { libc::close(read_fd) };
            // Child is still running, notify via exit pipe when app exits
            Ok((child_pid, exit_read_fd))
        }
    }
}

/// Child process SIGTERM handler: umount and exit after receiving signal.
extern "C" fn child_sigterm_handler(_sig: libc::c_int) {
    let _ = CString::new(PROC_CPUINFO).map(|target| {
        unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
    });
    unsafe { libc::_exit(0) };
}

/// Execute setns + bind mount in fork child process.
/// Namespace changes are handled by unshare PLT hook event-driven processing.
fn do_mount_in_child(pid: u32, source_path: &str) -> Result<()> {
    let ns_path = format!("/proc/{pid}/ns/mnt");
    let ns_path_c = CString::new(ns_path.as_str())?;

    let initial_ino = read_ns_ino(pid)?;

    // setns to app's current namespace
    let ns_fd = unsafe { libc::open(ns_path_c.as_ptr(), libc::O_RDONLY) };
    if ns_fd < 0 {
        anyhow::bail!(
            "Failed to open {}: {}",
            ns_path,
            std::io::Error::last_os_error()
        );
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_setns,
            ns_fd as libc::c_long,
            libc::CLONE_NEWNS as libc::c_long,
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(ns_fd) };
        anyhow::bail!("setns failed for pid {pid}: {err}");
    }
    info!("[child] Entered NS of pid {pid} (ino={initial_ino})");

    // Defensive unmount
    let target = CString::new(PROC_CPUINFO)?;
    unsafe {
        libc::umount2(target.as_ptr(), libc::MNT_DETACH);
    }

    // Bind mount
    let source = CString::new(source_path)?;
    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            MS_BIND,
            std::ptr::null(),
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("bind mount failed: {err}");
    }

    info!("[child] Mounted fake cpuinfo for pid {pid} (ns_ino={initial_ino})");

    // Verify
    match fs::read_to_string(PROC_CPUINFO) {
        Ok(actual) if !actual.is_empty() => {
            info!("[child] Verified for pid {pid} ({} bytes)", actual.len());
        }
        Ok(_) => warn!("[child] /proc/cpuinfo empty for pid {pid}"),
        Err(e) => warn!("[child] Read failed for pid {pid}: {e}"),
    }

    Ok(())
}

/// Check namespace change (repeat timerfd event-driven) + wait for app exit (pidfd event-driven).
///
/// Flow:
/// 1. Read initial namespace inode
/// 2. Timerfd repeat timer (50ms interval) → epoll_wait block waiting, internal hrtimer polling
/// 3. Each poll: check namespace change → if changed, setns + remount → close timer
/// 4. pidfd_open + poll wait for app exit (event-driven)
///
/// Uses repeat timer instead of fixed delay, self-adapting to different KernelSU namespace switch speeds.
/// epoll_wait uses internal hrtimer polling, not sleep polling.
fn check_namespace_and_wait_exit(pid: u32, source_path: &str) {
    const NS_CHECK_INTERVAL_NS: i64 = 25_000_000; // 25ms
    const NS_CHECK_MAX_MS: i32 = 500; // check up to 500ms

    let initial_ino = match read_ns_ino(pid) {
        Ok(ino) => ino,
        Err(_) => {
            wait_for_app_exit_event(pid);
            return;
        }
    };

    let tfd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK) };
    if tfd < 0 {
        wait_for_app_exit_event(pid);
        return;
    }

    // Repeat timer: fire every 50ms
    let spec = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: NS_CHECK_INTERVAL_NS,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: NS_CHECK_INTERVAL_NS,
        },
    };
    unsafe { libc::timerfd_settime(tfd, 0, &spec, std::ptr::null_mut()) };

    let efd = unsafe { libc::epoll_create1(0) };
    if efd < 0 {
        unsafe { libc::close(tfd) };
        wait_for_app_exit_event(pid);
        return;
    }
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: tfd as u64,
    };
    unsafe { libc::epoll_ctl(efd, libc::EPOLL_CTL_ADD, tfd, &mut ev) };

    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let mut ns_changed = false;
    let start = std::time::Instant::now();

    loop {
        let elapsed_ms = start.elapsed().as_millis() as i32;
        let remaining = NS_CHECK_MAX_MS - elapsed_ms;
        if remaining <= 0 {
            break;
        }

        let nfds = unsafe { libc::epoll_wait(efd, events.as_mut_ptr(), 1, remaining) };
        if nfds <= 0 {
            break;
        }

        // Read timerfd to clear readable state
        let mut buf = [0u8; 8];
        unsafe {
            libc::read(tfd, buf.as_mut_ptr() as *mut libc::c_void, 8);
        }

        if let Ok(new_ino) = read_ns_ino(pid) {
            if new_ino != initial_ino {
                info!("[child] NS changed for pid {pid}: {initial_ino} -> {new_ino}");
                remount_in_namespace(pid, source_path, new_ino);
                ns_changed = true;
                break;
            }
        } else {
            break; // cannot read namespace; app may have exited
        }
    }

    unsafe {
        libc::epoll_ctl(efd, libc::EPOLL_CTL_DEL, tfd, std::ptr::null_mut());
        libc::close(efd);
        libc::close(tfd);
    }

    if !ns_changed {
        info!("[child] NS stable for pid {pid} (ino={initial_ino}), no remount needed");
    }

    wait_for_app_exit_event(pid);
}

/// Execute setns + umount + bind mount in new namespace.
fn remount_in_namespace(pid: u32, source_path: &str, new_ino: u64) {
    let ns_path = format!("/proc/{pid}/ns/mnt");
    let Ok(ns_path_c) = CString::new(ns_path.as_str()) else {
        return;
    };
    let ns_fd = unsafe { libc::open(ns_path_c.as_ptr(), libc::O_RDONLY) };
    if ns_fd < 0 {
        warn!("[child] Cannot open new NS for pid {pid}");
        return;
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_setns,
            ns_fd as libc::c_long,
            libc::CLONE_NEWNS as libc::c_long,
        )
    };
    if ret != 0 {
        warn!(
            "[child] setns to new NS failed for pid {pid}: {}",
            std::io::Error::last_os_error()
        );
        unsafe { libc::close(ns_fd) };
        return;
    }

    let target = match CString::new(PROC_CPUINFO) {
        Ok(t) => t,
        Err(_) => return,
    };
    unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };

    let source = match CString::new(source_path) {
        Ok(s) => s,
        Err(_) => return,
    };
    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            MS_BIND,
            std::ptr::null(),
        )
    };
    if ret == 0 {
        info!("[child] Re-mounted in new NS for pid {pid} (ino={new_ino})");
    } else {
        warn!(
            "[child] Re-mount failed for pid {pid}: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Mount child waits for app exit: pidfd_open event-driven, kernel returns to pause + SIGTERM.
///
/// The child remains blocked here until app exits or receives SIGTERM.
/// Namespace changes are not handled by this function — unshare PLT hook handles them during app specialize.
/// Event-driven completes remount, no child monitoring needed.
fn wait_for_app_exit_event(pid: u32) {
    // Try pidfd_open (same syscall as parent's wait_for_app_exit)
    let pidfd =
        unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0 as libc::c_uint) };

    if pidfd >= 0 {
        let pidfd = pidfd as i32;
        info!("[child] Monitoring app exit via pidfd {pidfd} (pid={pid})");

        let mut pfd = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let ret = unsafe { libc::poll(&mut pfd, 1, -1) };
            if ret > 0 {
                info!("[child] pidfd signaled — app (pid {pid}) exited");
                break;
            }
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue; // EINTR: re-enter poll (e.g. SIGTERM handled)
                }
                warn!("[child] poll(pidfd) error for pid {pid}: {err}");
                break;
            }
        }

        unsafe { libc::close(pidfd) };
        return;
    }

    // pidfd_open unavailable (kernel): already registered SIGTERM handler, pause waiting for parent notification.
    let err = std::io::Error::last_os_error();
    info!("[child] pidfd_open unavailable for pid {pid}: {err}, waiting for SIGTERM from parent");
    loop {
        // pause() blocks until a signal is received.
        // SIGTERM is handled by _exit(0) above, won't return from pause.
        // Other signals poll pause, then continue loop.
        unsafe { libc::pause() };
    }
}

/// Read /proc/{pid}/ns/mnt namespace identifier (via readlink to get mnt:[inode]).
/// stat() returns the procfs entry's inode (fixed), so we must use readlink to get the actual namespace ID.
fn read_ns_ino(pid: u32) -> Result<u64> {
    let ns_path = format!("/proc/{pid}/ns/mnt");
    let ns_path_c = CString::new(ns_path.as_str())?;
    let mut buf = [0u8; 64];
    let len = unsafe {
        libc::readlink(
            ns_path_c.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len() - 1,
        )
    };
    if len < 0 {
        anyhow::bail!(
            "readlink({}) failed: {}",
            ns_path,
            std::io::Error::last_os_error()
        );
    }
    buf[len as usize] = 0;
    let link = std::str::from_utf8(&buf[..len as usize])
        .map_err(|_| anyhow::anyhow!("invalid utf8 in ns link"))?;
    // Format: "mnt:[4026535831]"
    let ino_str = link
        .strip_prefix("mnt:[")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| anyhow::anyhow!("unexpected ns link format: {link}"))?;
    ino_str
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("cannot parse ns ino: {ino_str}"))
}

fn ensure_dir(path: &str) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("Failed to create directory {path}"))?;
    Ok(())
}

/// Set SELinux label for the given path to app-readable system_file:s0.
///
/// After bind mount, when app reads /proc/cpuinfo, the kernel resolves the path to source file inode at VFS,
/// SELinux checks the **source file inode label**. Files under /data/adb/device_faker/ have default
/// label (adb_data_file:s0 etc.) that untrusted_app cannot read, returning EACCES, causing app to not
/// read the spoofed cpuinfo. Hence we must set both directory and source file to system_file:s0 (consistent
/// with customize.sh config file handling).
///
/// On failure, we only log it instead of aborting — on some root implementations, lsetxattr may be blocked by policy,
/// falling back to default label; worst-case scenario is app cannot read cpuinfo (which does not prevent mount itself).
fn set_selinux_context(path: &str) {
    let result = (|| -> std::io::Result<()> {
        let p = CString::new(path).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contained nul")
        })?;
        let ctx = CString::new(SELINUX_CONTEXT).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "context contained nul")
        })?;
        // flags = 0: if property already exists, overwrite; if not, create (create-or-replace).
        let ret = unsafe {
            libc::lsetxattr(
                p.as_ptr(),
                c".security.selinux".as_ptr() as *const _,
                ctx.as_ptr() as *const libc::c_void,
                SELINUX_CONTEXT.len(), // excluding trailing nul
                0,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            #[cfg(target_os = "android")]
            info!("Set SELinux context {SELINUX_CONTEXT} on {path}");
        }
        Err(e) => {
            // Non-fatal: continue after logging; mount can still succeed; worst case: app cannot read cpuinfo.
            warn!("Failed to set SELinux context on {path}: {e} (app may not read cpuinfo)");
        }
    }
}
