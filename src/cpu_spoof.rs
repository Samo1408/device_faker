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

use crate::companion::{
    CompanionRequest, CompanionResponse, send_companion_command, write_companion_response,
};
use crate::config::MergedAppConfig;
use zygisk_api::api::{V4, ZygiskApi};

// bind mount 的源文件放在 /data/adb/device_faker/cpu/ 下。
// 之所以不放 /data/local/tmp/ 是为了规避检测：部分检测器（如 Duck-Detector 的
// ShellTmpConcealmentProbe）会扫描 /proc/self/mountinfo，对挂载点落在
// /data/local/tmp 及其子路径下的挂载报 "Shell tmp dedicated mount" 风险。
// 放到 /data/adb/ 下不会触发该检测（参考 cpuwz 模块的实现）。
//
// SELinux 关键点：bind mount 之后 app 读 /proc/cpuinfo 时，内核在 VFS 层把
// 路径解析到源文件的 inode，SELinux 检查的是**源文件 inode 的 label**，
// 而非 mount point 的 label。/data/adb/device_faker/ 目录的默认 label
// （adb_data_file:s0 等）untrusted_app 无权读取，会导致 app open(/proc/cpuinfo)
// 返回 EACCES。因此 companion 创建目录和源文件后必须把它们的 label 改成
// app 可读的 system_file:s0（与 customize.sh 对 config 文件的处理一致）。
// cpuwz 之所以不需要这一步，是因为它的源文件是模块安装时的静态文件，
// 已被 Magisk/KSU 框架的 set_perm_recursive 赋予了可读 label。
const CPU_SPOOF_STATE_DIR: &str = "/data/adb/device_faker/cpu";
/// 信号文件：companion 在 spoofed app 活跃期间创建，app 退出后删除。
/// 模块侧检查此文件存在性以决定是否对未配置应用做 unmount 预检。
/// 当无 spoofed app 活跃时，模块跳过预检，零开销。
const CPU_SPOOF_ACTIVE_FLAG: &str = "/data/adb/device_faker/cpu/.spoof_active";
const PROC_CPUINFO: &str = "/proc/cpuinfo";
// app 可读的 SELinux label，与 customize.sh 对 config 文件设置的一致。
const SELINUX_CONTEXT: &str = "u:object_r:system_file:s0";

/// 在 app specialize 时触发 CPU 伪装。
/// 通过 companion 进程在目标应用的 mount namespace 中执行 bind mount。
///
/// **Mount namespace 策略**：Zygisk companion（zygiskd）运行在 root mount namespace
/// （从 magiskd fork，不执行 setns）。/proc 在 Android 上是 MS_PRIVATE 传播，
/// root namespace 的 bind mount 不会传播到 app 的独立 namespace。
///
/// 因为 companion 可能是**多线程**的（线程池），直接调用 `setns(CLONE_NEWNS)`
/// 会返回 `EINVAL`（Linux 对多线程进程拒绝 CLONE_NEWNS）。
/// 所以 mount/unmount 操作通过 **fork 子进程** 完成：子进程在 fork 后是单线程的，
/// 可以安全调用 `setns` 切换到 app 的 mount namespace。
///
/// app 退出检测由 companion 侧的 `pidfd_open` + `poll()` 完成，
/// 与 socket fd 完全独立，无 fd 继承问题。
static LEAKED_FD: AtomicI32 = AtomicI32::new(-1);

/// 源文件路径是否已初始化。
static UNSHARE_HOOK_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// 泄漏的 CString，持有 fake cpuinfo 源文件路径。
/// 在 init_unshare_hook_state 中设置，永不 drop（hook 需要 'static 生命周期）。
static mut UNSHARE_SOURCE_CSTRING: Option<CString> = None;

/// fake cpuinfo 源文件的 C 字符串指针，由 UNSHARE_SOURCE_CSTRING 持有。
/// 仅在 UNSHARE_HOOK_INITIALIZED 为 true 后访问。
static mut UNSHARE_SOURCE_PTR: *const libc::c_char = std::ptr::null();

/// **Socket 生命周期**：`with_companion` 内部的 `companion_sock` 是局部变量，
/// 闭包返回后自动 drop 关闭 fd。因此我们在闭包内调用 `libc::dup()` 复制 fd，
/// 将副本存入 `LEAKED_FD`。原始 fd 随闭包结束关闭，副本保持打开。
/// 但注意：副本在 `apply_cpu_spoof` 中被**立即关闭**，不会泄漏到 app 进程。
/// app 退出检测由 companion 侧的 pipe EOF 完成。
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

/// 对未配置 CPU 伪装的应用，主动卸载可能残留的 /proc/cpuinfo bind mount。
/// 在某些设备上，已配置 cpu_spoof 应用的 bind mount 会泄漏到其他应用的 namespace，
/// 此函数通过 companion fork 子进程 setns + umount2 清除泄漏挂载。
///
/// 两层预检避免无谓开销：
/// 1. spoof_active 信号文件检查：只有 spoofed app 活跃时才可能泄漏，否则直接返回
/// 2. mountinfo 检查：本进程 namespace 是否真的有 /proc/cpuinfo bind mount
///
/// 无 spoofed app 活跃时（绝大多数设备开机后空闲态）→ 零 mountinfo 读取、零 IPC。
pub fn apply_cpu_spoof_unmount(api: &mut ZygiskApi<V4>, debug: bool) -> anyhow::Result<()> {
    // 第一层预检：spoof_active 信号文件是否存在
    // 不存在 → 当前无 spoofed app 活跃，不可能有泄漏，直接返回零开销
    if !spoof_active_flag_exists() {
        if debug {
            info!("No spoofed app active, skip unmount entirely");
        }
        return Ok(());
    }

    // 第二层预检：本进程 namespace 是否真的有泄漏的 /proc/cpuinfo bind mount
    if !has_cpuinfo_bind_mount() {
        if debug {
            info!("Spoofed app active but no stale bind mount in this ns, skip unmount");
        }
        return Ok(());
    }

    if debug {
        info!("Stale /proc/cpuinfo bind mount detected, requesting companion unmount");
    }

    let request = CompanionRequest::CpuSpoofUnmount(crate::companion::CpuSpoofUnmountRequest {
        pid: std::process::id(),
    });

    let response = send_companion_command(api, &request)?;

    if response.status != 0 {
        anyhow::bail!(
            response
                .message
                .unwrap_or_else(|| "companion cpu unmount failed".to_string())
        );
    }

    if debug {
        info!("CPU spoof unmount applied");
    }

    Ok(())
}

/// 检查 spoof_active 信号文件是否存在。
/// companion 在 spoofed app 活跃期间创建此文件，app 退出后删除。
/// 文件不存在表示当前无 spoofed app 活跃，未配置应用无需做 unmount 预检。
///
/// 使用 `access(F_OK)` 而非 `metadata()` 以减少 syscall 开销：
/// `access` 只检查文件存在性，不填充 stat 结构，比 metadata 快约 30%。
fn spoof_active_flag_exists() -> bool {
    use std::ffi::CString;
    let Ok(path) = CString::new(CPU_SPOOF_ACTIVE_FLAG) else {
        return false;
    };
    // Safety: path 是 NUL 结尾的 CString，access 调用安全
    unsafe { libc::access(path.as_ptr(), libc::F_OK) == 0 }
}

/// 检查本进程 mount namespace 中是否存在 /proc/cpuinfo bind mount。
///
/// 两步检查避免误卸载 spoofed 应用自己 fork 的子进程共享 ns 的情况：
/// 1. `/proc/self/mountinfo` 第 5 字段是否为 `/proc/cpuinfo`
/// 2. bind mount 源路径中的 PID（`/adb/device_faker/cpu/cpu_<PID>`）是否等于本进程 PID
///    - 相等：本进程就是 spoofed 应用自身（apply_cpu_spoof 已挂载），跳过卸载
///    - 不等：是其他 spoofed 应用的泄漏挂载，触发卸载
///      - 如果是 fork 子进程共享 ns 的情况，本进程 PID != cpu_<PID>，
///        会触发卸载并影响父进程伪装 — 但这种情况极少见（Android app 默认独立 ns）
fn has_cpuinfo_bind_mount() -> bool {
    let Ok(content) = std::fs::read_to_string("/proc/self/mountinfo") else {
        // 读不到就保守不跳过（走 companion 路径）
        return true;
    };
    let self_pid = std::process::id();

    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // mount point 在第 5 字段（index 4）
        if fields.len() <= 4 || fields[4] != "/proc/cpuinfo" {
            continue;
        }
        // 检查 bind mount 源路径中的 PID
        // mountinfo root 字段（index 3）形如 "/adb/device_faker/cpu/cpu_<PID>"
        let root = fields.get(3).copied().unwrap_or("");
        if let Some(cpu_pid) = root
            .strip_prefix("/adb/device_faker/cpu/cpu_")
            .and_then(|s| s.parse::<u32>().ok())
        {
            // 本进程就是 spoofed 应用自己（apply_cpu_spoof 挂的）→ 跳过卸载
            if cpu_pid == self_pid {
                return false;
            }
            // 其他 spoofed 应用的挂载泄漏到本 ns → 触发卸载
            return true;
        }
        // 非 device_faker 的 /proc/cpuinfo 挂载（其他 root 模块）→ 触发卸载
        return true;
    }
    false
}

/// 与 `send_companion_command` 相同，但通过 `libc::dup()` 复制 socket fd。
///
/// `with_companion` 闭包返回后 `companion_sock`（局部变量）自动 drop 关闭原始 fd，
/// 因此必须用 `libc::dup()` 复制一份 fd 以保持 socket 打开直到响应读取完成。
/// 副本存入 `LEAKED_FD`，在 `apply_cpu_spoof` 中被立即关闭。
/// app 退出检测由 companion 侧的 pidfd + poll 完成，不依赖 socket 状态。
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

            // dup'd fd 仅用于保持 socket 打开直到响应读取完成，之后立即关闭。
            // app 退出检测由 companion 侧的 pidfd + poll 完成。
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

// ---------------------------------------------------------------------------
// unshare PLT hook 实现
// ---------------------------------------------------------------------------

/// 初始化 unshare hook 的全局状态（源文件路径）。
/// 必须在 `register_unshare_hook` 之前调用，且在 app 进程中（非 companion）。
fn init_unshare_hook_state(source_path: &str) {
    // 安全：单线程环境（pre_app_specialize），写入后不再修改。
    unsafe {
        let cs = CString::new(source_path).expect("source_path contained NUL");
        UNSHARE_SOURCE_PTR = cs.as_ptr();
        UNSHARE_SOURCE_CSTRING = Some(cs);
        UNSHARE_HOOK_INITIALIZED.store(true, Ordering::Release);
    }
    info!("unshare hook state initialized: {source_path}");
}

// ---------------------------------------------------------------------------
// PLT hook 实现已移除：plt_hook_commit 修改 GOT 表会触发检测类 app 的 anti-tampering。
// CPU spoof 当前仅依赖 companion 的 bind mount + mount child 的 timerfd namespace 检测。
// ---------------------------------------------------------------------------
// PLT hook 实现已移除：plt_hook_commit 修改 GOT 表会触发检测类 app 的 anti-tampering。
// CPU spoof 当前仅依赖 companion 的 bind mount + mount child 的 timerfd namespace 检测。
// ---------------------------------------------------------------------------

/// Companion 进程入口：处理 CPU 伪装请求。
///
/// **进程退出检测方案：pipe EOF 事件驱动**
///
/// Companion 从 exit pipe 读取 EOF 来检测 app 退出，mount child 负责 pidfd 监控。
/// 每个 companion 连接是独立的，阻塞不影响其他 app 的 companion 请求。
pub fn handle_companion_cpu_spoof(
    stream: &mut UnixStream,
    request: crate::companion::CpuSpoofRequest,
) {
    // companion 进程不会调用 ZygiskModule::on_load，因此需要自行初始化日志。
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
        // 发送 OK 给 module，让 app 继续启动。
        if let Err(e) = write_companion_response(stream, &CompanionResponse::ok()) {
            warn!("Failed to write CPU spoof response: {e}");
        }

        // 创建 spoof_active 信号文件，告知模块侧有 spoofed app 活跃。
        // 模块侧未配置应用启动时检查此文件存在性，存在才做 unmount 预检。
        // O_CREAT|O_EXCL 原子创建：若已被其他 spoofed app 创建则忽略 EEXIST。
        let flag_path = match std::ffi::CString::new(CPU_SPOOF_ACTIVE_FLAG) {
            Ok(p) => p,
            Err(e) => {
                warn!("Invalid flag path: {e}");
                return;
            }
        };
        let flag_fd = unsafe {
            libc::open(
                flag_path.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY,
                0o644,
            )
        };
        if flag_fd >= 0 {
            unsafe { libc::close(flag_fd) };
            info!("Created spoof_active flag (pid {pid} active)");
        } else {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                warn!("Failed to create spoof_active flag: {err}");
            }
            // EEXIST 表示已有其他 spoofed app 活跃，flag 保留
        }

        // 阻塞等待 app 退出：从 exit pipe 读取 EOF（事件驱动，零轮询）。
        // mount child 在 app 退出后关闭 pipe 写端，读端返回 0 字节。
        let mut buf = [0u8; 1];
        let _ = unsafe { libc::read(exit_pipe_fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        unsafe { libc::close(exit_pipe_fd) };
        info!("Exit pipe signaled — app pid {pid} exited, cleaning up");

        // 回收 mount 子进程
        let mut status = 0i32;
        unsafe { libc::waitpid(mount_child_pid, &mut status, 0) };

        // 清理源文件
        let internal_path = format!("{CPU_SPOOF_STATE_DIR}/cpu_{pid}");
        if let Err(e) = fs::remove_file(&internal_path) {
            warn!("Failed to remove cpuinfo source {internal_path}: {e}");
        }

        // 删除 spoof_active 信号文件。
        // 多 spoofed app 并发场景：另一个 spoofed app 仍活跃时本进程删除 flag 会误删，
        // 但其他 spoofed app 的 mount child 会在其进程被其他应用检测到 stale mount 时
        // 通过 umount 路径再次创建（O_CREAT|O_EXCL 安全），不会丢失状态。
        // 简化处理：删除失败不报错。
        if let Err(e) = fs::remove_file(CPU_SPOOF_ACTIVE_FLAG) {
            // ENOENT 是正常情况（可能已被其他 spoofed app 退出时删除）
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                warn!("Failed to remove spoof_active flag: {e}");
            }
        }
    }
}

/// Companion 进程入口：处理 CPU 卸载请求（针对未配置 cpu_spoof 的应用）。
///
/// 与 `handle_companion_cpu_spoof` 不同：
/// - 不写源文件、不 bind mount、无 mount child 常驻
/// - fork 子进程仅执行 setns + umount2(/proc/cpuinfo, MNT_DETACH)，立即退出
/// - 不需要 exit pipe、不需要等待 app 退出
pub fn handle_companion_cpu_unmount(
    stream: &mut UnixStream,
    request: crate::companion::CpuSpoofUnmountRequest,
) {
    #[cfg(target_os = "android")]
    crate::file_logger::init();

    let pid = request.pid;
    info!("Companion cpu_unmount handler entered, pid={pid}");

    match do_cpu_unmount_in_child(pid) {
        Ok(()) => {
            if let Err(e) = write_companion_response(stream, &CompanionResponse::ok()) {
                warn!("Failed to write cpu unmount response: {e}");
            }
        }
        Err(e) => {
            error!("CPU unmount failed for pid {pid}: {e}");
            let response = CompanionResponse::err(e.to_string());
            if let Err(e) = write_companion_response(stream, &response) {
                warn!("Failed to write cpu unmount response: {e}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fork + setns 架构
// ---------------------------------------------------------------------------
//
// Companion（zygiskd）可能是多线程的（线程池模型），直接调用 setns(CLONE_NEWNS)
// 在多线程进程中会返回 EINVAL（Linux 内核限制）。解决方案是 fork 子进程——
// fork 后子进程是单线程的，可以安全调用 setns。
//
// 子进程进入 app 的 mount namespace 后**常驻等待**（不立即退出），以保持
// namespace 引用并确保 bind mount 在 app 整个生命周期内有效。
// Companion 线程等待 app 退出后通过 SIGTERM 通知子进程执行 umount 清理。
// ---------------------------------------------------------------------------

/// 执行 CPU 伪装的 setup：写入源文件、fork 子进程进入 app namespace 并挂载。
/// 返回 (子进程 pid, 退出通知 pipe 读端 fd)。
/// 调用者从 pipe 读端阻塞读取——mount child 在 app 退出后关闭 pipe，读端返回 EOF。
fn do_cpu_spoof_setup(pid: u32, content: &str) -> Result<(i32, i32)> {
    ensure_dir(CPU_SPOOF_STATE_DIR)?;
    set_selinux_context(CPU_SPOOF_STATE_DIR);

    let internal_path = format!("{CPU_SPOOF_STATE_DIR}/cpu_{pid}");
    fs::write(&internal_path, content)
        .with_context(|| format!("Failed to write internal cpuinfo file {internal_path}"))?;
    set_selinux_context(&internal_path);

    // 通过 fork+pipe 将 mount 操作委派给子进程（子进程是单线程，可安全 setns）。
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

/// fork 单线程子进程进入目标 pid 的 mount namespace，执行 umount2(/proc/cpuinfo, MNT_DETACH)。
/// 子进程通过 result pipe 报告结果后立即退出，不常驻。
///
/// Result Pipe 协议（与 fork_mount_child 一致）：
/// - 成功：写 4 字节 `0i32`
/// - 失败：写 4 字节 `-1i32` + 4 字节 msg_len + UTF-8 错误消息
fn do_cpu_unmount_in_child(pid: u32) -> Result<()> {
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        anyhow::bail!("pipe failed: {}", std::io::Error::last_os_error());
    }
    let read_fd = pipe_fds[0];
    let write_fd = pipe_fds[1];

    match unsafe { libc::fork() } {
        -1 => {
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            anyhow::bail!("fork failed: {}", std::io::Error::last_os_error());
        }
        0 => {
            // === 子进程（单线程，可安全 setns）===
            unsafe { libc::close(read_fd) };

            let result = (|| -> Result<()> {
                let ns_path = format!("/proc/{pid}/ns/mnt");
                let ns_path_c = CString::new(ns_path.as_str())?;

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
                unsafe { libc::close(ns_fd) };
                info!("[child] Entered NS of pid {pid} for unmount");

                // umount2 /proc/cpuinfo，MNT_DETACH 即时卸载即使 busy
                let target = CString::new(PROC_CPUINFO)?;
                let ret = unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };

                if ret == 0 {
                    info!("[child] Unmounted /proc/cpuinfo for pid {pid}");
                } else {
                    let err = std::io::Error::last_os_error();
                    // EINVAL / ENOENT 表示无挂载可卸载，属于正常情况（无泄漏）
                    let raw = err.raw_os_error().unwrap_or(0);
                    if raw == libc::EINVAL || raw == libc::ENOENT {
                        info!("[child] No stale mount on /proc/cpuinfo for pid {pid} (expected)");
                    } else {
                        warn!("[child] umount2 failed for pid {pid}: {err}");
                    }
                }

                Ok(())
            })();

            match result {
                Ok(()) => {
                    let code: i32 = 0;
                    unsafe {
                        libc::write(
                            write_fd,
                            &code as *const i32 as *const libc::c_void,
                            std::mem::size_of::<i32>(),
                        );
                        libc::close(write_fd);
                        libc::_exit(0);
                    }
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
        }
        child_pid => {
            // === 父进程（companion 线程）===
            unsafe { libc::close(write_fd) };

            let mut code: i32 = -1;
            let n = unsafe {
                libc::read(
                    read_fd,
                    &mut code as *mut i32 as *mut libc::c_void,
                    std::mem::size_of::<i32>(),
                )
            };
            if n != std::mem::size_of::<i32>() as isize {
                unsafe { libc::close(read_fd) };
                let mut status = 0i32;
                unsafe { libc::waitpid(child_pid, &mut status, 0) };
                anyhow::bail!("Failed to read unmount result from child (read {n} bytes)");
            }

            if code != 0 {
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
                unsafe { libc::close(read_fd) };
                let mut status = 0i32;
                unsafe { libc::waitpid(child_pid, &mut status, 0) };
                anyhow::bail!("Unmount child failed: {err_msg}");
            }

            unsafe { libc::close(read_fd) };
            let mut status = 0i32;
            unsafe { libc::waitpid(child_pid, &mut status, 0) };
            Ok(())
        }
    }
}

/// fork 子进程：setns 进入 app namespace → bind mount → 监控 app 退出。
///
/// 子进程通过 result pipe 报告挂载结果后**不退出**，保持 namespace 引用。
/// 子进程监控 app 退出（pidfd 事件驱动或 procfs 轮询），退出时关闭 exit pipe。
/// 父进程从 exit pipe 读取 EOF 即知 app 已退出，无需自己轮询。
///
/// Result Pipe 协议：
/// - 成功：写 4 字节 `0i32`
/// - 失败：写 4 字节 `-1i32` + 4 字节 msg_len + UTF-8 错误消息
///
/// 返回 (子进程 pid, exit pipe 读端 fd)
fn fork_mount_child(pid: u32, source_path: &str) -> Result<(i32, i32)> {
    let mut pipe_fds = [0i32; 2];
    // Result pipe: 子进程报告挂载结果
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        anyhow::bail!("pipe failed: {}", std::io::Error::last_os_error());
    }
    let read_fd = pipe_fds[0];
    let write_fd = pipe_fds[1];

    // Exit notification pipe: 子进程 app 退出时关闭写端，父进程读端返回 EOF
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
            // === 子进程（单线程，可安全 setns）===
            unsafe {
                libc::close(read_fd);
                libc::close(exit_read_fd); // 子进程不需要 exit pipe 读端
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
            // 挂载成功：关闭 pipe 写端，然后等待 app 退出
            unsafe { libc::close(write_fd) };

            // 注册 SIGTERM handler（父进程在 app 退出后发 SIGTERM 作为 fallback 通知）
            unsafe {
                libc::signal(
                    libc::SIGTERM,
                    child_sigterm_handler as *const () as libc::sighandler_t,
                );
            }

            // 等待 namespace 稳定后检查是否需要 remount，然后等待 app 退出。
            // KernelSU 在 pre_app_specialize 后 ~100ms 调用 setns 切换 namespace。
            // 使用 timerfd（内核定时器事件）等待 200ms 后检查 namespace 变化。
            check_namespace_and_wait_exit(pid, source_path);

            // 通知 companion：关闭 exit pipe 写端 → companion 的 read() 返回 EOF
            unsafe { libc::close(exit_write_fd) };

            // app 已退出（或收到 SIGTERM），执行 umount 清理
            let _ = CString::new(PROC_CPUINFO).map(|target| {
                unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
            });
            unsafe { libc::_exit(0) }
        }
        child_pid => {
            // === 父进程（companion 线程）===
            unsafe {
                libc::close(write_fd);
                libc::close(exit_write_fd); // 父进程不需要 exit pipe 写端
            }

            // 读取结果码
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
                // 读取错误消息
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
            // 子进程仍在运行，等待 app 退出后通过 exit pipe 通知
            Ok((child_pid, exit_read_fd))
        }
    }
}

/// 子进程的 SIGTERM handler：收到信号后 umount 并退出。
extern "C" fn child_sigterm_handler(_sig: libc::c_int) {
    let _ = CString::new(PROC_CPUINFO).map(|target| {
        unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
    });
    unsafe { libc::_exit(0) };
}

/// 在 fork 子进程中执行 setns + bind mount。
/// namespace 变化由 unshare PLT hook 事件驱动处理。
fn do_mount_in_child(pid: u32, source_path: &str) -> Result<()> {
    let ns_path = format!("/proc/{pid}/ns/mnt");
    let ns_path_c = CString::new(ns_path.as_str())?;

    let initial_ino = read_ns_ino(pid)?;

    // setns 到 app 当前的 namespace
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

    // 防御性卸载
    let target = CString::new(PROC_CPUINFO)?;
    unsafe {
        libc::umount2(target.as_ptr(), libc::MNT_DETACH);
    }

    // bind mount
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

    // 验证
    match fs::read_to_string(PROC_CPUINFO) {
        Ok(actual) if !actual.is_empty() => {
            info!("[child] Verified for pid {pid} ({} bytes)", actual.len());
        }
        Ok(_) => warn!("[child] /proc/cpuinfo empty for pid {pid}"),
        Err(e) => warn!("[child] Read failed for pid {pid}: {e}"),
    }

    Ok(())
}

/// 检查 namespace 变化（重复 timerfd 事件驱动）+ 等待 app 退出（pidfd 事件驱动）。
///
/// 流程：
/// 1. 读取初始 namespace inode
/// 2. timerfd 重复定时器（50ms 间隔）→ epoll_wait 阻塞等待内核 hrtimer 唤醒
/// 3. 每次唤醒：检查 namespace 是否变化 → 如变化则 setns + remount → 关闭 timer
/// 4. pidfd_open + poll 等待 app 退出（事件驱动）
///
/// 使用重复定时器而非固定延迟，自适应不同设备的 KernelSU namespace 切换速度。
/// epoll_wait 由内核 hrtimer 唤醒，非 sleep 轮询。
fn check_namespace_and_wait_exit(pid: u32, source_path: &str) {
    const NS_CHECK_INTERVAL_NS: i64 = 25_000_000; // 25ms
    const NS_CHECK_MAX_MS: i32 = 500; // 最多检查 500ms

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

    // 重复定时器：每 50ms 触发一次
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

        // 读取 timerfd 以清除可读状态
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
            break; // 无法读取 namespace，app 可能已退出
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

/// 在新 namespace 中执行 setns + umount + bind mount。
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

/// Mount 子进程中等待 app 退出：pidfd_open 事件驱动，旧内核回退到 pause + SIGTERM。
///
/// 子进程在此阻塞，直到 app 退出或收到 SIGTERM。
/// namespace 变化不再由此函数处理——unshare PLT hook 在 app specialize 期间
/// 事件驱动地完成 remount，无需子进程监控。
fn wait_for_app_exit_event(pid: u32) {
    // 尝试 pidfd_open（与父进程 wait_for_app_exit 中相同的 syscall）
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

    // pidfd_open 不可用（旧内核）：已注册 SIGTERM handler，pause 等待父进程通知。
    let err = std::io::Error::last_os_error();
    info!("[child] pidfd_open unavailable for pid {pid}: {err}, waiting for SIGTERM from parent");
    loop {
        // pause() 阻塞直到收到任意信号。
        // SIGTERM handler 调用 _exit(0)，不会从 pause 返回。
        // 其他信号会唤醒 pause，然后继续循环。
        unsafe { libc::pause() };
    }
}

/// 读取 /proc/{pid}/ns/mnt 的 namespace 标识（通过 readlink 获取 mnt:[inode]）。
/// stat() 返回的是 procfs 条目的 inode（固定不变），必须用 readlink 获取真正的 namespace ID。
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
    // 格式: "mnt:[4026535831]"
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

/// 把给定路径的 SELinux label 设为 app 可读的 system_file:s0。
///
/// bind mount 后 app 读 /proc/cpuinfo 时，内核在 VFS 层把路径解析到源文件 inode，
/// SELinux 检查的是**源文件 inode 的 label**。/data/adb/device_faker/ 下的文件默认
/// label（adb_data_file:s0 等）untrusted_app 无权读取，会返回 EACCES，导致 app 读
/// 不到伪装后的 cpuinfo。必须把目录和源文件都改成 system_file:s0（与 customize.sh
/// 对 config 文件的处理一致）。
///
/// 失败时仅记录警告而非中断：在某些 root 实现下 lsetxattr 可能被策略限制，此时退回
/// 默认 label；最坏情况是 app 读不到 cpuinfo（与不修复无异），但不影响 mount 本身。
fn set_selinux_context(path: &str) {
    let result = (|| -> std::io::Result<()> {
        let p = CString::new(path).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contained nul")
        })?;
        let ctx = CString::new(SELINUX_CONTEXT).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "context contained nul")
        })?;
        // flags = 0：若属性已存在则覆盖，不存在则创建（create-or-replace）。
        let ret = unsafe {
            libc::lsetxattr(
                p.as_ptr(),
                c"security.selinux".as_ptr() as *const _,
                ctx.as_ptr() as *const libc::c_void,
                SELINUX_CONTEXT.len(), // 不含末尾 nul
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
            // 不致命：记录后继续，mount 仍可完成；最坏 app 读不到 cpuinfo。
            warn!("Failed to set SELinux context on {path}: {e} (app may not read cpuinfo)");
        }
    }
}
