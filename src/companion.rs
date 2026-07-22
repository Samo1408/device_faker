use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::net::UnixStream,
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use log::{error, info, warn};
use prop_rs_android::{resetprop::ResetProp, sys_prop};
use serde::{Deserialize, Serialize};
use zygisk_api::api::{V4, ZygiskApi};

// ── Companion-side active session tracking ────────────────────────────
// Companion runs persistently; static state is reliable (unaffected by DlClose).
// Each Apply request restores the previous session's backups first, preventing cross-contamination.

static ACTIVE_SESSION: Mutex<Option<ActiveSession>> = Mutex::new(None);

struct ActiveSession {
    package: String,
    pid: u32,
    backups: HashMap<String, String>,
}

/// Reap exited watcher child processes to prevent zombie accumulation.
fn reap_zombie_watchers() {
    loop {
        match unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } {
            0 | -1 => break,
            _ => {} // Reaped a zombie, keep trying
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CpuSpoofRequest {
    pub pid: u32,
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WriteLogRequest {
    pub lines: Vec<String>,
}

pub fn spoof_system_props_via_companion(
    api: &mut ZygiskApi<V4>,
    prop_map: &HashMap<String, String>,
    delete_props: &[String],
    package_name: &str,
) -> anyhow::Result<()> {
    if prop_map.is_empty() && delete_props.is_empty() {
        return Ok(());
    }

    let request = CompanionRequest::Apply(ResetpropSessionRequest {
        pid: std::process::id(),
        props: prop_map.clone(),
        delete_props: delete_props.to_vec(),
        package_name: package_name.to_string(),
    });

    let response = send_companion_command(api, &request)?;
    if response.status != 0 {
        anyhow::bail!(
            response
                .message
                .unwrap_or_else(|| "companion resetprop failed".to_string())
        );
    }

    // Companion now manages session state and restore logic independently;
    // Zygisk module no longer needs ACTIVE_RESET_SESSION.

    Ok(())
}

pub fn send_companion_command(
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
            Ok(resp)
        })
        .map_err(|e| anyhow::anyhow!("Failed to talk to companion: {e}"))??;

    Ok(response)
}

pub fn handle_companion_request(stream: &mut UnixStream) {
    // Companion does not call ZygiskModule::on_load, so init logger manually.
    #[cfg(target_os = "android")]
    crate::file_logger::init();

    let request = match read_companion_request(stream) {
        Ok(request) => request,
        Err(err) => {
            error!("Companion failed to parse request: {err}");
            let response = CompanionResponse::err("invalid request");
            if let Err(e) = write_companion_response(stream, &response) {
                warn!("Failed to write companion response: {e}");
            }
            return;
        }
    };

    match request {
        CompanionRequest::Apply(request) => {
            let response = match apply_resetprop_session(request) {
                Ok(backups) => CompanionResponse::ok_with_backups(backups),
                Err(err) => {
                    error!("Companion failed to apply resetprop session: {err}");
                    CompanionResponse::err(err.to_string())
                }
            };
            if let Err(e) = write_companion_response(stream, &response) {
                warn!("Failed to write companion response: {e}");
            }
        }
        CompanionRequest::Restore(request) => {
            let response = match restore_properties(request) {
                Ok(_) => CompanionResponse::ok(),
                Err(err) => {
                    error!("Companion failed to restore properties: {err}");
                    CompanionResponse::err(err.to_string())
                }
            };
            if let Err(e) = write_companion_response(stream, &response) {
                warn!("Failed to write companion response: {e}");
            }
        }
        CompanionRequest::CpuSpoof(request) => {
            crate::cpu_spoof::handle_companion_cpu_spoof(stream, request);
        }
        CompanionRequest::WriteLog(request) => {
            let response = match write_log_lines(request) {
                Ok(_) => CompanionResponse::ok(),
                Err(err) => {
                    error!("Companion failed to write log: {err}");
                    CompanionResponse::err(err.to_string())
                }
            };
            if let Err(e) = write_companion_response(stream, &response) {
                warn!("Failed to write companion response: {e}");
            }
        }
    }
}

fn read_companion_request(stream: &mut UnixStream) -> anyhow::Result<CompanionRequest> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let payload_len = u32::from_le_bytes(len_buf) as usize;
    if payload_len == 0 {
        anyhow::bail!("empty request payload");
    }

    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload)?;
    let request = serde_json::from_slice::<CompanionRequest>(&payload)?;
    Ok(request)
}

pub(crate) fn write_companion_response(
    stream: &mut UnixStream,
    response: &CompanionResponse,
) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(response)?;
    stream.write_all(&(bytes.len() as u32).to_le_bytes())?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

/// Rebuild property areas for ALL distinct contexts touched by the given keys.
/// More complete than single-context rebuild; handles custom_props spanning
/// multiple SELinux contexts (e.g. ro.* + debug.* + gsm.*).
fn rebuild_all_contexts(keys_iter: impl Iterator<Item = impl AsRef<str>>) {
    let mut contexts: std::collections::HashSet<String> = std::collections::HashSet::new();
    for key in keys_iter {
        if let Ok(ctx) = sys_prop::get_context(key.as_ref()) {
            contexts.insert(ctx);
        }
    }
    for ctx in &contexts {
        if let Err(e) = sys_prop::rebuild(ctx) {
            warn!("prop area rebuild for {ctx} failed (non-fatal): {e}");
        }
    }
}

fn apply_resetprop_session(
    request: ResetpropSessionRequest,
) -> anyhow::Result<HashMap<String, String>> {
    if request.props.is_empty() && request.delete_props.is_empty() {
        return Ok(HashMap::new());
    }

    // ① Reap exited watcher zombies
    reap_zombie_watchers();

    // ② Check for duplicate request from same package (e.g. multi-process app)
    //    Skip restore+reapply if same package and old process is still alive.
    {
        let mut guard = ACTIVE_SESSION.lock().unwrap();
        if let Some(ref active) = *guard
            && active.package == request.package_name
        {
            // Check if old process is still alive
            let old_alive = unsafe { libc::kill(active.pid as i32, 0) } == 0;
            if old_alive {
                info!(
                    "Skipping duplicate Apply for package '{}' (pid {}), session already active (old pid {} alive)",
                    request.package_name, request.pid, active.pid
                );
                return Ok(active.backups.clone());
            } else {
                info!(
                    "Old session for package '{}' (pid {}) is dead, clearing and re-applying for new pid {}",
                    request.package_name, active.pid, request.pid
                );
                guard.take();
            }
        }
    }

    // ③ If an old session exists (different package), restore its backups first
    {
        let mut guard = ACTIVE_SESSION.lock().unwrap();
        if let Some(old) = guard.take() {
            info!(
                "Restoring previous session backups (package: {}, {} keys) before applying new session for '{}'",
                old.package,
                old.backups.len(),
                request.package_name
            );
            for entry in &old.backups {
                if let Err(e) = apply_resetprop(entry.0, entry.1) {
                    warn!("Failed to restore old session key '{}': {e}", entry.0);
                }
            }
            rebuild_all_contexts(old.backups.keys());
        }
    }

    // ④ Backup current properties (old session restored, now at real values)
    let mut backups = Vec::with_capacity(request.props.len() + request.delete_props.len());

    for key in request.props.keys() {
        let original = backup_property(key)?;
        backups.push(PropBackup {
            key: key.clone(),
            original_value: original,
        });
    }

    for key in &request.delete_props {
        let original = backup_property(key)?;
        backups.push(PropBackup {
            key: key.clone(),
            original_value: original,
        });
    }

    let backups_for_response: HashMap<String, String> = backups
        .iter()
        .map(|entry| (entry.key.clone(), entry.original_value.clone()))
        .collect();

    // ⑤ Apply new spoofed values
    for (key, value) in &request.props {
        apply_resetprop(key, value)?;
    }

    for key in &request.delete_props {
        resetprop_delete(key)?;
    }

    rebuild_all_contexts(request.props.keys().chain(request.delete_props.iter()));

    // ⑥ Fork restore watcher
    if let Err(e) = spawn_restore_watcher(
        request.pid,
        request.props.clone(),
        request.delete_props.clone(),
        backups.clone(),
    ) {
        error!("Failed to spawn restore watcher: {e}, rolling back applied props");
        for entry in &backups {
            let _ = apply_resetprop(&entry.key, &entry.original_value);
        }
        rebuild_all_contexts(backups.iter().map(|b| &b.key));
        anyhow::bail!("failed to spawn restore watcher: {e}");
    }

    // ⑦ Store new session
    *ACTIVE_SESSION.lock().unwrap() = Some(ActiveSession {
        package: request.package_name.clone(),
        pid: request.pid,
        backups: backups
            .iter()
            .map(|b| (b.key.clone(), b.original_value.clone()))
            .collect(),
    });

    Ok(backups_for_response)
}

fn restore_properties(request: RestoreRequest) -> anyhow::Result<()> {
    if request.props.is_empty() {
        return Ok(());
    }

    for (key, value) in &request.props {
        apply_resetprop(key, value)?;
    }

    // Rebuild after restoring originals to reclaim any holes.
    rebuild_all_contexts(request.props.keys());

    Ok(())
}

fn backup_property(key: &str) -> anyhow::Result<String> {
    let output = std::process::Command::new("getprop").arg(key).output()?;
    if !output.status.success() {
        anyhow::bail!("getprop failed for {key}");
    }

    let value = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\n', '\r'])
        .to_string();
    Ok(value)
}

fn new_resetprop() -> anyhow::Result<ResetProp> {
    sys_prop::init()
        .map_err(|e| anyhow::anyhow!("failed to initialize system property API: {e}"))?;

    Ok(ResetProp {
        // `-n`: bypass property_service, direct mmap write.
        // All properties we set (ro.*, persist.*, etc.) benefit from direct
        // mmap — no SELinux policy denials, no init service restarts, no
        // PROP_VALUE_MAX limit.  ro.* is forced to mmap regardless, but
        // skip_svc=true also covers non-ro keys in custom_props.
        skip_svc: true,
        persistent: false,
        persist_only: false,
        verbose: false,
        show_context: false,
        rebuild: false,
    })
}

fn apply_resetprop(key: &str, value: &str) -> anyhow::Result<()> {
    let rp = new_resetprop()?;

    if let Err(e) = rp.set(key, value) {
        // Value exceeds PROP_VALUE_MAX; inline prop_info cannot expand in-place.
        // Delete old property (free inline space), then recreate in long mode.
        warn!("resetprop set failed for {key}, trying delete+set: {e}");
        let _ = rp.delete(key);
        rp.set(key, value)
            .map_err(|e2| anyhow::anyhow!("resetprop delete+set failed for {key}: {e2}"))?;
    }
    Ok(())
}

fn resetprop_delete(key: &str) -> anyhow::Result<()> {
    let rp = new_resetprop()?;

    match rp.delete(key) {
        Ok(true) => Ok(()),
        Ok(false) => anyhow::bail!("resetprop delete failed for {key}: property not found"),
        Err(_) => anyhow::bail!("resetprop delete failed for {key}"),
    }
}

fn spawn_restore_watcher(
    pid: u32,
    props: HashMap<String, String>,
    delete_props: Vec<String>,
    backups: Vec<PropBackup>,
) -> anyhow::Result<i32> {
    unsafe {
        match libc::fork() {
            -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {
                if libc::setsid() == -1 {
                    libc::_exit(1);
                }
                if let Err(e) =
                    watch_process_state_and_sync_props(pid, &props, &delete_props, &backups)
                {
                    error!("Watcher failed for pid {}: {}", pid, e);
                }
                libc::_exit(0);
            }
            child_pid => {
                info!("Spawned restore watcher pid={child_pid} for app pid={pid}");
                Ok(child_pid)
            }
        }
    }
}

fn watch_process_state_and_sync_props(
    pid: u32,
    props: &HashMap<String, String>,
    delete_props: &[String],
    backups: &[PropBackup],
) -> anyhow::Result<()> {
    // Prefer inotify on oom_score_adj (event-driven, zero polling).
    // Fallback to /proc/<pid>/cgroup polling (inotify unavailable on some devices/kernels).
    match watch_via_inotify(pid, props, delete_props, backups) {
        Ok(()) => return Ok(()),
        Err(e) => {
            warn!("inotify on oom_score_adj unavailable ({e}), falling back to cgroup polling");
        }
    }

    watch_via_cgroup_polling(pid, props, delete_props, backups)
}

/// Event-driven: inotify on /proc/<pid>/oom_score_adj + pidfd for process exit.
/// Android OomAdjuster writes oom_score_adj on foreground/background switch: /// - Foreground: 0
/// - Visible: 100
/// - Background/cached: 200-900+
/// inotify IN_MODIFY on procfs oom_score_adj is verified working (Android kernel).
/// Use epoll to monitor both inotify fd and pidfd; block until event, zero polling.
fn watch_via_inotify(
    pid: u32,
    props: &HashMap<String, String>,
    delete_props: &[String],
    backups: &[PropBackup],
) -> anyhow::Result<()> {
    const BACKGROUND_THRESHOLD: i32 = 200;
    const BACKGROUND_DEBOUNCE: Duration = Duration::from_secs(2);

    // pidfd: event-driven app exit detection
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) };
    if pidfd < 0 {
        anyhow::bail!("pidfd_open failed");
    }
    let pidfd = pidfd as i32;

    // inotify: monitor oom_score_adj changes
    let ifd = unsafe { libc::inotify_init() };
    if ifd < 0 {
        unsafe { libc::close(pidfd) };
        anyhow::bail!("inotify_init failed");
    }
    let oom_path = format!("/proc/{pid}/oom_score_adj\0");
    let wd = unsafe {
        libc::inotify_add_watch(
            ifd,
            oom_path.as_ptr() as *const libc::c_char,
            libc::IN_MODIFY,
        )
    };
    if wd < 0 {
        unsafe {
            libc::close(ifd);
            libc::close(pidfd);
        }
        anyhow::bail!("inotify_add_watch on oom_score_adj failed");
    }
    let wd = wd as u32;

    // epoll: monitor both pidfd and inotify fd
    let efd = unsafe { libc::epoll_create1(0) };
    if efd < 0 {
        unsafe {
            libc::inotify_rm_watch(ifd, wd);
            libc::close(ifd);
            libc::close(pidfd);
        }
        anyhow::bail!("epoll_create1 failed");
    }
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: pidfd as u64,
    };
    unsafe { libc::epoll_ctl(efd, libc::EPOLL_CTL_ADD, pidfd, &mut ev) };
    ev.u64 = ifd as u64;
    unsafe { libc::epoll_ctl(efd, libc::EPOLL_CTL_ADD, ifd, &mut ev) };

    let mut is_spoof_applied = true;
    let mut background_since: Option<Instant> = None;
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 2];

    info!("restore watcher: inotify monitoring oom_score_adj for pid {pid}");

    loop {
        let timeout = if let Some(bg_start) = background_since {
            // Background debounce waiting, compute remaining time
            let remaining = BACKGROUND_DEBOUNCE
                .checked_sub(bg_start.elapsed())
                .unwrap_or(Duration::ZERO);
            remaining.as_millis() as i32
        } else {
            -1 // Block indefinitely
        };

        let nfds = unsafe { libc::epoll_wait(efd, events.as_mut_ptr(), 2, timeout) };

        // Debounce expiration check
        if let Some(bg_start) = background_since
            && bg_start.elapsed() >= BACKGROUND_DEBOUNCE
        {
            if is_spoof_applied {
                restore_props_batch(backups)?;
                is_spoof_applied = false;
                info!("restore watcher restored props for pid {pid}");
            }
            background_since = None;
        }

        if nfds < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // Non-EINTR error (e.g. EBADF), restore props before exit
            warn!("restore watcher: epoll_wait error: {err}, attempting restore before exit");
            if is_spoof_applied {
                let _ = restore_props_batch(backups);
            }
            break;
        }

        if nfds == 0 {
            // timeout — debounce may have been handled
            continue;
        }

        // Check for process exit event
        let process_exited = events
            .iter()
            .take(nfds as usize)
            .any(|e| e.u64 == pidfd as u64);
        if process_exited {
            if is_spoof_applied {
                restore_props_batch(backups)?;
            }
            info!("restore watcher: app pid {pid} exited (pidfd event)");
            break;
        }

        // oom_score_adj change
        for ev in events.iter().take(nfds as usize) {
            if ev.u64 == ifd as u64 {
                let mut buf = [0u8; 512];
                let _ =
                    unsafe { libc::read(ifd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

                let oom_val = read_oom_score_adj(pid);
                if oom_val >= BACKGROUND_THRESHOLD {
                    let bg_start = *background_since.get_or_insert_with(Instant::now);
                    if is_spoof_applied && bg_start.elapsed() >= BACKGROUND_DEBOUNCE {
                        restore_props_batch(backups)?;
                        is_spoof_applied = false;
                        info!("restore watcher restored props for pid {pid} (oom={oom_val})");
                        background_since = None;
                    }
                } else {
                    background_since = None;
                    if !is_spoof_applied {
                        apply_props_batch(props, delete_props)?;
                        is_spoof_applied = true;
                        info!(
                            "restore watcher re-applied spoof props for pid {pid} (oom={oom_val})"
                        );
                    }
                }
            }
        }
    }

    unsafe {
        libc::epoll_ctl(efd, libc::EPOLL_CTL_DEL, ifd, std::ptr::null_mut());
        libc::epoll_ctl(efd, libc::EPOLL_CTL_DEL, pidfd, std::ptr::null_mut());
        libc::inotify_rm_watch(ifd, wd);
        libc::close(efd);
        libc::close(ifd);
        libc::close(pidfd);
    }
    Ok(())
}

/// Read /proc/<pid>/oom_score_adj; return 0 on failure (treated as foreground).
fn read_oom_score_adj(pid: u32) -> i32 {
    let path = format!("/proc/{pid}/oom_score_adj");
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .unwrap_or(0)
}

/// Polling fallback: check /proc/<pid>/cgroup for top-app (same as original impl).
fn watch_via_cgroup_polling(
    pid: u32,
    props: &HashMap<String, String>,
    delete_props: &[String],
    backups: &[PropBackup],
) -> anyhow::Result<()> {
    const POLL_INTERVAL: Duration = Duration::from_millis(200);
    const BACKGROUND_DEBOUNCE: Duration = Duration::from_secs(2);

    let proc_path = format!("/proc/{pid}");
    let mut is_spoof_applied = true;
    let mut background_since: Option<Instant> = None;

    info!("restore watcher: cgroup polling for pid {pid}");

    loop {
        if !std::path::Path::new(&proc_path).exists() {
            if is_spoof_applied {
                restore_props_batch(backups)?;
            }
            break;
        }

        if is_process_in_top_app(pid) {
            background_since = None;
            if !is_spoof_applied {
                apply_props_batch(props, delete_props)?;
                is_spoof_applied = true;
                info!("restore watcher re-applied spoof props for pid {pid}");
            }
        } else {
            let bg_start = background_since.get_or_insert_with(Instant::now);
            if is_spoof_applied && bg_start.elapsed() >= BACKGROUND_DEBOUNCE {
                restore_props_batch(backups)?;
                is_spoof_applied = false;
                info!("restore watcher restored props for pid {pid}");
            }
        }

        thread::sleep(POLL_INTERVAL);
    }

    Ok(())
}

fn apply_props_batch(
    props: &HashMap<String, String>,
    delete_props: &[String],
) -> anyhow::Result<()> {
    for (key, value) in props {
        apply_resetprop(key, value)?;
    }

    for key in delete_props {
        resetprop_delete(key)?;
    }

    rebuild_all_contexts(props.keys().chain(delete_props.iter()));

    Ok(())
}

fn restore_props_batch(backups: &[PropBackup]) -> anyhow::Result<()> {
    for entry in backups {
        apply_resetprop(&entry.key, &entry.original_value)?;
    }

    // Rebuild using the first backup's key to find the context.
    rebuild_all_contexts(backups.iter().map(|b| &b.key));

    Ok(())
}

const LOG_PATH: &str = "/data/adb/device_faker/logs/device_faker.log";

fn write_log_lines(request: WriteLogRequest) -> anyhow::Result<()> {
    if request.lines.is_empty() {
        return Ok(());
    }

    write_log_lines_to_path(LOG_PATH, &request.lines)
}

fn write_log_lines_to_path(path: &str, lines: &[String]) -> anyhow::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    for line in lines {
        writeln!(file, "{line}")?;
    }

    file.flush()?;
    Ok(())
}

fn is_process_in_top_app(pid: u32) -> bool {
    let cgroup_path = format!("/proc/{pid}/cgroup");
    match fs::read_to_string(&cgroup_path) {
        Ok(content) => content.lines().any(|line| line.contains("top-app")),
        Err(_) => true,
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ResetpropSessionRequest {
    pid: u32,
    props: HashMap<String, String>,
    delete_props: Vec<String>,
    package_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct RestoreRequest {
    props: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "cmd", content = "payload")]
pub enum CompanionRequest {
    Apply(ResetpropSessionRequest),
    Restore(RestoreRequest),
    CpuSpoof(CpuSpoofRequest),
    WriteLog(WriteLogRequest),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CompanionResponse {
    pub status: i32,
    pub message: Option<String>,
    pub backups: Option<HashMap<String, String>>,
}

impl CompanionResponse {
    pub fn ok() -> Self {
        Self {
            status: 0,
            message: None,
            backups: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            status: -1,
            message: Some(msg.into()),
            backups: None,
        }
    }

    pub fn ok_with_backups(backups: HashMap<String, String>) -> Self {
        Self {
            status: 0,
            message: None,
            backups: Some(backups),
        }
    }
}

#[derive(Clone)]
struct PropBackup {
    key: String,
    original_value: String,
}
