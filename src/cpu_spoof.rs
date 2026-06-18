use std::{
    ffi::CString,
    fs,
    io::Read,
    io::Write,
    os::unix::io::AsRawFd,
    os::unix::net::UnixStream,
    sync::atomic::{AtomicI32, Ordering},
};

use anyhow::{Context, Result};
use libc::MS_BIND;
use log::{error, info, warn};

use crate::companion::{CompanionRequest, CompanionResponse, write_companion_response};
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
const PROC_CPUINFO: &str = "/proc/cpuinfo";
// app 可读的 SELinux label，与 customize.sh 对 config 文件设置的一致。
const SELINUX_CONTEXT: &str = "u:object_r:system_file:s0";

/// 在 app specialize 时触发 CPU 伪装。
/// 通过 companion 进程在目标应用的 mount namespace 中执行 bind mount。
/// Zygisk 框架保证 companion 进程已经位于目标进程的 mount namespace 中，
/// 因此不需要手动 setns。
///
/// app 退出检测由 companion 侧的 `pidfd_open` + `poll()` 完成，
/// 与 socket fd 完全独立，无 fd 继承问题。
static LEAKED_FD: AtomicI32 = AtomicI32::new(-1);

/// **Socket 生命周期**：`with_companion` 内部的 `companion_sock` 是局部变量，
/// 闭包返回后自动 drop 关闭 fd。因此我们在闭包内调用 `libc::dup()` 复制 fd，
/// 将副本存入 `LEAKED_FD`。原始 fd 随闭包结束关闭，副本保持打开。
/// 但注意：副本在 `apply_cpu_spoof` 中被**立即关闭**，不会泄漏到 app 进程。
/// app 退出检测由 companion 侧的 `pidfd_open` + `poll()` 完成。
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

    let request = CompanionRequest::CpuSpoof(crate::companion::CpuSpoofRequest {
        pid: std::process::id(),
        content: content.clone(),
    });

    // 发送请求并获取响应。
    // 现在 app 退出检测由 companion 侧的 pidfd + poll 完成，
    // 不再需要泄漏 socket fd。dup'd fd 在 companion 返回后立即关闭。
    let response = send_companion_command_leak_fd(api, &request)?;

    // 立即关闭泄漏的 fd，避免它被 fork 到 app 进程。
    // pidfd 方案完全独立于 socket，不需要这个 fd 存活。
    let leaked = LEAKED_FD.swap(-1, Ordering::SeqCst);
    if leaked >= 0 {
        unsafe { libc::close(leaked) };
        info!("Closed leaked companion fd {leaked} (pidfd handles monitoring)");
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

/// Companion 进程入口：处理 CPU 伪装请求。
///
/// **进程退出检测方案：`pidfd_open` + `poll()`**
///
/// Companion 直接在当前进程阻塞等待 app 退出，**不 fork 子进程**。
/// 每个 companion 连接是独立的，阻塞不影响其他 app 的 companion 请求。
/// 这彻底消除了 fork 模型中旧 watcher 与新 mount 之间的竞态条件。
///
/// `pidfd_open` 打开目标进程的 fd（Linux 5.3+），与 socket 完全独立。
/// `poll(pidfd)` 在进程退出时被内核唤醒（POLLIN），是真正的事件驱动。
/// 对旧内核回退到 /proc/<pid> 存在性检查。
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

    let setup_ok = match do_cpu_spoof_setup(pid, &request.content) {
        Ok(()) => true,
        Err(e) => {
            error!("CPU spoof setup failed for pid {pid}: {e}");
            let response = CompanionResponse::err(e.to_string());
            if let Err(e) = write_companion_response(stream, &response) {
                warn!("Failed to write CPU spoof response: {e}");
            }
            false
        }
    };

    if setup_ok {
        // 发送 OK 给 module，让 app 继续启动。
        if let Err(e) = write_companion_response(stream, &CompanionResponse::ok()) {
            warn!("Failed to write CPU spoof response: {e}");
        }

        // 当前 companion 连接已服务完毕，直接阻塞等待 app 退出。
        // 每个 companion 是独立的，阻塞不影响其他 app。
        // 不 fork 子进程——彻底消除旧 watcher 与新 mount 之间的竞态。
        wait_for_app_exit(pid);
        cleanup_mount_and_source(pid);
    }
}

/// 使用 `pidfd_open` + `poll()` 阻塞等待目标进程退出。
///
/// `pidfd_open` (Linux 5.3+, Android API 31 所需内核版本) 返回一个专门的文件描述符，
/// 当目标进程退出时内核将其标记为可读。`poll()` 阻塞直到可读，是纯事件驱动。
/// 与 socket EOF 方案不同，pidfd 不涉及任何 fd 继承问题。
///
/// 对不支持 `pidfd_open` 的旧内核，自动回退到 `/proc/<pid>` 存在性检查。
fn wait_for_app_exit(pid: u32) {
    // 尝试 pidfd_open（syscall 434 on aarch64）
    let pidfd =
        unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0 as libc::c_uint) };

    if pidfd >= 0 {
        let pidfd = pidfd as i32;
        info!("Monitoring app pid {pid} via pidfd {pidfd} (event-driven)");

        loop {
            let mut pfd = libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pfd, 1, -1) };
            if ret > 0 {
                info!("pidfd signaled — app (pid {pid}) has exited");
                break;
            }
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                warn!("poll(pidfd) error for pid {pid}: {err}");
                break;
            }
        }

        unsafe { libc::close(pidfd) };
        return;
    }

    // Fallback：pidfd_open 不可用（旧内核），使用 /proc/<pid> 检查。
    let err = std::io::Error::last_os_error();
    warn!("pidfd_open failed for pid {pid}: {err}, falling back to procfs check");

    let proc_path = format!("/proc/{pid}");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
        if !std::path::Path::new(&proc_path).exists() {
            info!("App (pid {pid}) exited (procfs check)");
            break;
        }
    }
}

fn do_cpu_spoof_setup(pid: u32, content: &str) -> Result<()> {
    ensure_dir(CPU_SPOOF_STATE_DIR)?;
    // 目录必须 app 可读，否则其下新建文件的 label 继承也可能受影响。
    set_selinux_context(CPU_SPOOF_STATE_DIR);

    let internal_path = format!("{CPU_SPOOF_STATE_DIR}/cpu_{pid}");
    fs::write(&internal_path, content)
        .with_context(|| format!("Failed to write internal cpuinfo file {internal_path}"))?;
    // 源文件的 label 决定 app 读 /proc/cpuinfo（bind 后解析到此 inode）的 SELinux 判定，
    // 必须在 mount 之前设好。
    set_selinux_context(&internal_path);

    unsafe {
        let source = CString::new(internal_path.as_str())?;
        let target = CString::new(PROC_CPUINFO)?;
        let ret = libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            MS_BIND,
            std::ptr::null(),
        );

        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // 挂载失败时立即清理源文件，避免残留。
            let _ = fs::remove_file(&internal_path);
            anyhow::bail!("mount failed: {err}");
        }
    }

    info!("Successfully mounted fake cpuinfo to {PROC_CPUINFO} for pid {pid}");

    // 读回验证：确认 bind mount 对当前 namespace 可见，且内容正确。
    match fs::read_to_string(PROC_CPUINFO) {
        Ok(actual) if actual == content => {
            info!("Mount verification passed for pid {pid}");
        }
        Ok(actual) => {
            warn!(
                "Mount verification MISMATCH for pid {pid}: \
                 expected {} bytes, got {} bytes — bind mount may not be visible",
                content.len(),
                actual.len()
            );
        }
        Err(e) => {
            warn!("Mount verification read failed for pid {pid}: {e}");
        }
    }

    // 不在 setup 中 fork watcher：app 退出检测由 handle_companion_cpu_spoof
    // 中的 pidfd + poll 方案完成。

    Ok(())
}

/// 执行 umount 和源文件清理。在 companion 检测到 app 退出后调用。
///
/// `umount2(MNT_DETACH)` 执行 lazy detach：立即从挂载层级移除，
/// 已持有的 fd 仍可继续读直到关闭。如果 mount 已随 namespace 销毁消失，
/// umount 会返回 EINVAL，视为正常。
fn cleanup_mount_and_source(pid: u32) {
    let internal_path = format!("{CPU_SPOOF_STATE_DIR}/cpu_{pid}");

    let target = match CString::new(PROC_CPUINFO) {
        Ok(t) => t,
        Err(e) => {
            warn!("Failed to create CString for umount: {e}");
            return;
        }
    };
    let ret = unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        warn!("umount2 /proc/cpuinfo failed (may already be gone): {err}");
    } else {
        info!("umounted fake cpuinfo for pid {pid}");
    }

    if let Err(e) = fs::remove_file(&internal_path) {
        warn!("Failed to remove cpuinfo source {internal_path}: {e}");
    }
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
