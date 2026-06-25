//! COW 属性伪造引擎。
//!
//! - 已有属性：bionic `__system_property_find()` + COW remap + 原地 patch
//! - 不存在属性：COW remap + `MmapPropArea::emplace()` 在私有副本中插入 trie 节点
//!   （不依赖 companion resetprop，per-process 隔离零驻留）
//!
//! # 实现说明
//!
//! 不存在属性的插入通过 `MmapPropArea`（ksu_props）在 COW-remapped 内存上操作：
//! - `transmute((ptr, len))` → `MmapMut` 构造 `MmapPropArea`（MmapMut = `{ptr, len}` on Unix）
//! - `ManuallyDrop` 防止 `MmapPropArea` drop → `MmapMut` drop → munmap（COW 副本需保持存活）
//! - `emplace()` 内部 bump allocator 分配 trie 节点 + prop_info，Release store 发布指针

use std::{cell::RefCell, collections::HashMap};

use log::{debug, info, warn};

// ── bionic 类型定义 ────────────────────────────────────────────────────────

type FnSystemPropertyFind = unsafe extern "C" fn(*const libc::c_char) -> *const libc::c_void;

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

/// 对目标进程的所有属性应用 COW 伪造。
///
/// - 已有属性：COW remap + 原地 patch
/// - 不存在属性：在对应 prop_area 的 COW 映射中插入 trie 节点 + prop_info
///
/// 返回仍未能处理的属性列表（映射找不到或空间不足），供 companion resetprop 兜底。
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
    let mut cow_inserted = 0usize;

    for (key, value) in &filtered {
        match cow_patch_existing(find_fn, key, value, &mappings) {
            Ok(true) => cow_patched += 1,
            Ok(false) => {
                // 属性不存在 → 尝试在 COW prop_area 中插入新 trie 节点
                match cow_patch_new(key, value, &mappings) {
                    Ok(true) => cow_inserted += 1,
                    Ok(false) => {
                        unfound.push((key.to_string(), value.to_string()));
                    }
                    Err(e) => {
                        warn!("COW insert failed for '{key}': {e}");
                        unfound.push((key.to_string(), value.to_string()));
                    }
                }
            }
            Err(e) => warn!("COW patch failed for '{key}': {e}"),
        }
    }

    if cow_patched > 0 || cow_inserted > 0 {
        info!(
            "COW spoof: {cow_patched} patched, {cow_inserted} inserted, {} total",
            filtered.len()
        );
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

/// munmap `/dev/__properties__/*` 中路径匹配指定模式的映射。
/// 这些属性值为空，munmap 不影响任何功能。
pub fn unmap_prop_areas(patterns: &[String]) {
    if patterns.is_empty() {
        return;
    }

    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return;
    };

    for line in maps.lines() {
        if !line.contains("/dev/__properties__/") {
            continue;
        }
        if !patterns.iter().any(|p| line.contains(p.as_str())) {
            continue;
        }

        let mut ws = line.split_whitespace();
        let Some(range) = ws.next() else { continue };

        let Some((start_s, end_s)) = range.split_once('-') else {
            continue;
        };
        let Ok(start) = usize::from_str_radix(start_s, 16) else {
            continue;
        };
        let Ok(end) = usize::from_str_radix(end_s, 16) else {
            continue;
        };

        let size = end - start;
        let ret = unsafe { libc::munmap(start as *mut libc::c_void, size) };
        if ret == 0 {
            info!("Unmapped prop area: {range}");
        }
    }
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

// ── 新增属性：COW trie 插入 ───────────────────────────────────────────────

/// 尝试在 COW-remapped 的 prop_area 中为不存在的属性插入新 trie 节点。
///
/// 通过 `MmapPropArea::emplace()` 在 COW 内存上操作 trie 结构：
/// - MAP_PRIVATE|MAP_FIXED 替换原始映射为 COW 私有副本
/// - `transmute((ptr, len))` → `MmapMut` 构造 MmapPropArea
/// - `emplace()` 内部 bump allocator 分配 trie 节点 + prop_info
/// - ManuallyDrop 防止 MmapPropArea drop → MmapMut drop → munmap（COW 副本需保持存活）
fn cow_patch_new(key: &str, value: &str, mappings: &[PropAreaMapping]) -> anyhow::Result<bool> {
    use memmap2::MmapMut;
    use prop_rs_android::mmap_prop_area::MmapPropArea;

    let key_prefix = match key.find('.') {
        Some(i) => &key[..i],
        None => key,
    };

    // 第一遍：只读扫描，找到前缀匹配的 mapping（不做 COW remap）
    let target = mappings.iter().find(|m| {
        if !m.path.starts_with("/dev/__properties__/") {
            return false;
        }
        let size = m.end - m.start;
        if size < 128 {
            return false;
        }
        let ptr = m.start as *mut u8;
        let magic = unsafe { (ptr.add(8) as *const u32).read_unaligned() };
        let version = unsafe { (ptr.add(12) as *const u32).read_unaligned() };
        if magic != 0x504f_5250 || version != 0xfc6e_d0ab {
            return false;
        }
        area_has_prefix(ptr, size, key_prefix)
    });

    let mapping = match target {
        Some(m) => m,
        None => return Ok(false),
    };

    // 第二步：只对目标 mapping 做 COW remap（最小化 rw-p 暴露）
    ensure_prop_area_private(mapping.start as *const u8, mappings)?;

    let size = mapping.end - mapping.start;
    let ptr = mapping.start as *mut u8;

    // 构造 MmapPropArea（transmute ptr+len → MmapMut，ManuallyDrop 防 munmap）
    let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((ptr, size)) };
    let mut area = match MmapPropArea::new(mmap_mut) {
        Ok(a) => std::mem::ManuallyDrop::new(a),
        Err(_) => return Ok(false),
    };

    // 检查属性是否已存在
    if let Ok(Some(_)) = area.find(key) {
        debug!("COW trie: '{key}' already exists, skipping insert");
        return Ok(false);
    }

    // 插入新属性
    match area.emplace(key, value.as_bytes(), 0) {
        Ok(()) => {
            info!("COW trie: inserted '{key}' into {}", mapping.path);
            Ok(true)
        }
        Err(e) => {
            warn!("COW trie emplace failed for '{key}': {e}");
            Ok(false)
        }
    }
}

/// 检查 prop_area trie 根节点的 children BST 中是否有 name == prefix 的节点。
///
/// 绝对地址：base + 0 = root node，root.children 在 base+16，
/// children 指向的节点 name 在 base + children + TRIE_HEADER_SIZE。
fn area_has_prefix(base: *mut u8, pa_size: usize, prefix: &str) -> bool {
    const TRIE_HEADER_SIZE: usize = 20;
    const TRIE_CHILDREN_OFF: usize = 16;
    const TRIE_LEFT_OFF: usize = 8;
    const TRIE_RIGHT_OFF: usize = 12;
    const PA_HEADER_SIZE: usize = 128;

    if pa_size < PA_HEADER_SIZE + TRIE_HEADER_SIZE + 4 {
        return false;
    }

    // 根节点在 base + PA_HEADER_SIZE，children 字段在 base + PA_HEADER_SIZE + 16
    let children =
        unsafe { (base.add(PA_HEADER_SIZE + TRIE_CHILDREN_OFF) as *const u32).read_unaligned() };
    if children == 0 {
        return false;
    }

    // children 是 data offset，绝对地址 = base + PA_HEADER_SIZE + children
    let mut current = PA_HEADER_SIZE + children as usize;
    let pref = prefix.as_bytes();
    let mut depth = 0u32;

    loop {
        if depth > 500 || current + TRIE_HEADER_SIZE + 4 > pa_size {
            return false;
        }

        let namelen = unsafe { (base.add(current) as *const u32).read_unaligned() } as usize;
        let name_start = current + TRIE_HEADER_SIZE;

        if name_start + namelen > pa_size {
            return false;
        }

        let name = unsafe { std::slice::from_raw_parts(base.add(name_start), namelen) };

        if name == pref {
            return true;
        }

        // BST 比较：先长度后字典序（与 MmapPropArea::cmp_name 一致）
        let child_off = if pref.len() < namelen || (pref.len() == namelen && pref < name) {
            TRIE_LEFT_OFF
        } else {
            TRIE_RIGHT_OFF
        };

        let child = unsafe { (base.add(current + child_off) as *const u32).read_unaligned() };
        if child == 0 {
            return false;
        }

        current = PA_HEADER_SIZE + child as usize;
        depth += 1;
    }
}
