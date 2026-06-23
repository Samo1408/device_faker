//! COW 属性伪造引擎。
//!
//! - 已有属性：用 bionic `__system_property_find()` + COW remap + 原地 patch
//! - 新增属性：按需启动 companion resetprop（有 restore watcher）

use std::{cell::RefCell, collections::HashMap};

use log::{info, warn};

// ── bionic 类型定义 ────────────────────────────────────────────────────────

type FnSystemPropertyFind = unsafe extern "C" fn(*const libc::c_char) -> *const libc::c_void;

// prop_info 布局（bionic short property，Android 8+ 稳定）：
//   offset 0: u32 serial  — 高 8 位 = 值长度，低 24 位 = 生成计数器，bit 0 = dirty
//   offset 4: u8[92] value — NUL 终止
const PROP_VALUE_MAX: usize = 92;

// ── COW 范围缓存（per-thread，避免重复 remap 同一区域）────────────────────

struct PropRange {
    start: usize,
    end: usize,
}

thread_local! {
    static COW_RANGES: RefCell<Vec<PropRange>> = const { RefCell::new(Vec::new()) };
}

// ── bionic 符号加载 ────────────────────────────────────────────────────────

fn sys_prop_find() -> Option<FnSystemPropertyFind> {
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__system_property_find".as_ptr()) };
    if sym.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut libc::c_void, FnSystemPropertyFind>(sym) })
    }
}

// ── 入口 ───────────────────────────────────────────────────────────────────

/// 对目标进程的所有属性应用 COW 伪造（patch 已有）。
///
/// 返回未能通过 COW patch 的属性列表（设备上不存在），供 companion resetprop 处理。
pub fn apply_cow_spoof(
    prop_map: &HashMap<String, String>,
) -> anyhow::Result<Vec<(String, String)>> {
    let mut unfound: Vec<(String, String)> = Vec::new();

    if prop_map.is_empty() {
        return Ok(unfound);
    }

    let find_fn = match sys_prop_find() {
        Some(f) => f,
        None => {
            anyhow::bail!("__system_property_find not available (dlsym failed)");
        }
    };

    let filtered: Vec<(&str, &str)> = prop_map
        .iter()
        .filter(|(_, v)| !v.is_empty() && v.len() <= PROP_VALUE_MAX)
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    if filtered.is_empty() {
        return Ok(unfound);
    }

    let mappings = collect_prop_area_mappings();

    let mut cow_patched = 0usize;

    for (key, value) in &filtered {
        match cow_patch_existing(find_fn, key, value, &mappings) {
            Ok(true) => cow_patched += 1,
            Ok(false) => {
                // 属性不存在于 prop_area，交给 companion resetprop
                unfound.push((key.to_string(), value.to_string()));
            }
            Err(e) => warn!("COW patch failed for '{key}': {e}"),
        }
    }

    if cow_patched > 0 {
        info!("COW patched {cow_patched}/{} props", filtered.len());
    }

    COW_RANGES.with(|r| r.borrow_mut().clear());
    Ok(unfound)
}

// ── 已有属性：COW patch ────────────────────────────────────────────────────

fn cow_patch_existing(
    find_fn: FnSystemPropertyFind,
    key: &str,
    value: &str,
    mappings: &[PropAreaMapping],
) -> anyhow::Result<bool> {
    let ckey =
        std::ffi::CString::new(key).map_err(|_| anyhow::anyhow!("invalid property name: {key}"))?;
    let prop_ptr = unsafe { find_fn(ckey.as_ptr()) };
    if prop_ptr.is_null() {
        return Ok(false); // 属性不存在
    }

    // 确保 prop_info 所在的 prop_area 已 COW remap
    // 如果 remap 失败（mapping 找不到），返回 false 让 companion 接管
    if ensure_prop_area_private(prop_ptr as *const u8, mappings).is_err() {
        return Ok(false);
    }

    // Patch serial + value
    patch_prop_info(prop_ptr as *mut u8, value);

    Ok(true)
}

// ── 映射收集 ───────────────────────────────────────────────────────────────

struct PropAreaMapping {
    start: usize,
    end: usize,
    path: String,
    offset: u64,
}

fn collect_prop_area_mappings() -> Vec<PropAreaMapping> {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return vec![];
    };

    let mut result = vec![];
    for line in maps.lines() {
        let mut ws = line.split_whitespace();
        let Some(range) = ws.next() else { continue };
        let Some(_perms) = ws.next() else { continue };
        let Some(off_str) = ws.next() else { continue };
        let Some(_dev) = ws.next() else { continue };
        let Some(_inode) = ws.next() else { continue };
        let Some(path) = ws.next() else { continue };

        if !path.starts_with("/dev/__properties__/") {
            continue;
        }

        let Some((start_s, end_s)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = usize::from_str_radix(start_s, 16) else {
            continue;
        };
        let Ok(end) = usize::from_str_radix(end_s, 16) else {
            continue;
        };
        let Ok(offset) = u64::from_str_radix(off_str, 16) else {
            continue;
        };

        result.push(PropAreaMapping {
            start,
            end,
            path: path.to_string(),
            offset,
        });
    }
    result
}

// ── COW remap ──────────────────────────────────────────────────────────────

/// 确保 `prop_ptr` 所在的 `/dev/__properties__/*` 映射已被 COW remap。
fn ensure_prop_area_private(
    prop_ptr: *const u8,
    mappings: &[PropAreaMapping],
) -> anyhow::Result<()> {
    let addr = prop_ptr as usize;

    // 缓存命中检查
    let cached = COW_RANGES.with(|r| {
        r.borrow()
            .iter()
            .any(|range| addr >= range.start && addr < range.end)
    });
    if cached {
        return Ok(());
    }

    // 找到包含 prop_ptr 的映射
    let mapping = mappings
        .iter()
        .find(|m| addr >= m.start && addr < m.end)
        .ok_or_else(|| {
            anyhow::anyhow!("prop_info at {addr:#x} not in any /dev/__properties__ mapping")
        })?;

    let size = mapping.end - mapping.start;

    let cpath = std::ffi::CString::new(mapping.path.as_str())
        .map_err(|_| anyhow::anyhow!("invalid path: {path}", path = mapping.path))?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        anyhow::bail!(
            "open({path}): {err}",
            path = mapping.path,
            err = std::io::Error::last_os_error()
        );
    }

    let ret = unsafe {
        libc::mmap(
            mapping.start as *mut libc::c_void,
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            fd,
            mapping.offset as libc::off_t,
        )
    };
    unsafe { libc::close(fd) };

    if ret == libc::MAP_FAILED {
        anyhow::bail!(
            "mmap COW remap failed for {path}: {err}",
            path = mapping.path,
            err = std::io::Error::last_os_error()
        );
    }

    COW_RANGES.with(|r| {
        r.borrow_mut().push(PropRange {
            start: mapping.start,
            end: mapping.end,
        });
    });

    info!(
        "COW remapped {path} [{start:#x}-{end:#x}]",
        path = mapping.path,
        start = mapping.start,
        end = mapping.end
    );
    Ok(())
}

// ── 属性 patch ─────────────────────────────────────────────────────────────

/// 原地 patch prop_info 的 serial + value（bionic 写入协议）。
fn patch_prop_info(prop_ptr: *mut u8, value: &str) {
    let serial_ptr = prop_ptr as *mut u32;
    let value_ptr = unsafe { prop_ptr.add(4) };
    let val_bytes = value.as_bytes();
    let len = val_bytes.len();

    unsafe {
        let old = serial_ptr.read_volatile();

        // dirty bit
        serial_ptr.write_volatile(old | 1);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::Release);

        // 写新值
        std::ptr::copy_nonoverlapping(val_bytes.as_ptr(), value_ptr, len);
        value_ptr.add(len).write(0);
        if len + 1 < PROP_VALUE_MAX {
            std::ptr::write_bytes(value_ptr.add(len + 1), 0, PROP_VALUE_MAX - len - 1);
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::Release);

        // 写最终 serial
        let new_serial =
            ((len as u32) << 24) | (((old & 0x00FF_FFFFu32).wrapping_add(2)) & 0x00FF_FFFFu32);
        serial_ptr.write_volatile(new_serial);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_serial_encoding() {
        let len: u32 = 10;
        let old_serial: u32 = (5 << 24) | (100 << 2) | 0;
        let new_serial =
            ((len as u32) << 24) | (((old_serial & 0x00FF_FFFF).wrapping_add(2)) & 0x00FF_FFFF);
        assert_eq!(new_serial >> 24, 10);
        assert_eq!(new_serial & 1, 0);
    }
}
