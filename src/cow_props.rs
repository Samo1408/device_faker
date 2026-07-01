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

use log::{info, warn};
use prop_rs_android::mmap_prop_area::MmapPropArea;

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

// ── 前缀 → area 路径缓存（per-thread，首次遍历后记住正确的 area）──────────

thread_local! {
    static PREFIX_AREA_CACHE: RefCell<HashMap<String, Vec<String>>> = RefCell::new(HashMap::new());
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

    // 预初始化 serial area（供所有 update() 调用共享）
    let mut serial_pa = match cow_serial_area(&mappings) {
        Ok(pa) => Some(pa),
        Err(e) => {
            warn!("Failed to COW serial area: {e}, patches will use fallback");
            None
        }
    };

    let mut cow_patched = 0usize;
    let mut cow_inserted = 0usize;

    for (key, value) in &filtered {
        match cow_patch_existing(find_fn, key, value, &mappings, serial_pa.as_deref_mut()) {
            Ok(true) => cow_patched += 1,
            Ok(false) => {
                // 属性不存在 → 尝试在 COW prop_area 中插入新 trie 节点
                match cow_patch_new(key, value, &mappings, find_fn) {
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
    serial_pa: Option<&mut MmapPropArea>,
) -> anyhow::Result<bool> {
    use memmap2::MmapMut;

    let ckey =
        std::ffi::CString::new(key).map_err(|_| anyhow::anyhow!("invalid property name: {key}"))?;
    let prop_ptr = unsafe { find_fn(ckey.as_ptr()) };
    if prop_ptr.is_null() {
        return Ok(false);
    }

    if ensure_prop_area_private(prop_ptr as *const u8, mappings).is_err() {
        return Ok(false);
    }

    let mapping = mappings
        .iter()
        .find(|m| {
            let addr = prop_ptr as usize;
            addr >= m.start && addr < m.end
        })
        .ok_or_else(|| anyhow::anyhow!("mapping not found for prop_ptr"))?;

    let size = mapping.end - mapping.start;
    let ptr = mapping.start as *mut u8;
    let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((ptr, size)) };
    let mut area = std::mem::ManuallyDrop::new(MmapPropArea::new(mmap_mut)?);

    let data_off = area
        .find(key)?
        .ok_or_else(|| anyhow::anyhow!("'{key}' not found after __system_property_find"))?;

    let pa = serial_pa.ok_or_else(|| anyhow::anyhow!("serial area not available"))?;
    area.update(data_off, value, pa)?;

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

// ── Serial area COW ──────────────────────────────────────────────────────

/// 找到 `properties_serial` mapping 并 COW remap，构造 `MmapPropArea`。
///
/// `MmapPropArea::update()` 需要 `serial_pa` 来 bump global area serial + futex wake。
/// COW-remap 后 bump 只影响当前进程的私有副本，不会错误通知其他进程。
fn cow_serial_area(
    mappings: &[PropAreaMapping],
) -> anyhow::Result<std::mem::ManuallyDrop<MmapPropArea>> {
    use memmap2::MmapMut;

    let serial_mapping = mappings
        .iter()
        .find(|m| m.path.ends_with("/properties_serial"))
        .ok_or_else(|| anyhow::anyhow!("properties_serial mapping not found"))?;

    ensure_prop_area_private(serial_mapping.start as *const u8, mappings)?;

    let size = serial_mapping.end - serial_mapping.start;
    let ptr = serial_mapping.start as *mut u8;
    let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((ptr, size)) };
    let area = MmapPropArea::new(mmap_mut)?;
    Ok(std::mem::ManuallyDrop::new(area))
}

// ── 新增属性：COW trie 插入 ───────────────────────────────────────────────

/// 常见前缀到同前缀探测属性的映射表。
/// 用已有属性定位正确的 prop_area，避免靠 trie 前缀猜测。
const SIBLING_PROBES: &[(&str, &[&str])] = &[
    (
        "ro.product",
        &["ro.product.model", "ro.product.device", "ro.product.brand"],
    ),
    ("ro.build", &["ro.build.display.id", "ro.build.fingerprint"]),
    ("ro.vendor", &["ro.vendor.build.fingerprint"]),
    ("ro.hardware", &["ro.hardware"]),
    ("persist", &["persist.sys.timezone"]),
    ("ro", &["ro.build.id", "ro.product.model"]),
];

/// 尝试在 COW-remapped 的 prop_area 中为不存在的属性插入新 trie 节点。
///
/// 遍历所有 prop_area，用 `MmapPropArea::find` 检查同前缀的已有属性是否在该 area。
/// 如果找到（说明 bionic 对此前缀读取该 area），就在同一个 area 里 emplace 新属性。
fn cow_patch_new(
    key: &str,
    value: &str,
    mappings: &[PropAreaMapping],
    _find_fn: FnSystemPropertyFind,
) -> anyhow::Result<bool> {
    use memmap2::MmapMut;

    let key_prefix = match key.rfind('.') {
        Some(end) => &key[..end],
        None => key,
    };

    let probes: &[&str] = SIBLING_PROBES
        .iter()
        .find(|(pfx, _)| key_prefix == *pfx || key_prefix.starts_with(&format!("{pfx}.")))
        .map(|(_, p)| *p)
        .unwrap_or(&["ro.product.model", "ro.build.id"]);

    // 1. 检查缓存：prefix → area 路径列表
    let cached_paths = PREFIX_AREA_CACHE.with(|c| c.borrow().get(key_prefix).cloned());

    let target_paths: Vec<String> = if let Some(paths) = cached_paths {
        // 缓存命中
        paths
    } else {
        // 2. 缓存未命中，遍历 build 相关 area 用 MmapPropArea::find 找包含 sibling 的 area
        let mut found_paths = Vec::new();
        for mapping in mappings {
            if !mapping.path.starts_with("/dev/__properties__/") {
                continue;
            }
            if !mapping.path.contains("build_prop")
                && !mapping.path.contains("build_odm_prop")
                && !mapping.path.contains("build_vendor_prop")
                && !mapping.path.contains("default_prop")
            {
                continue;
            }
            let size = mapping.end - mapping.start;
            if size < 128 {
                continue;
            }
            if ensure_prop_area_private(mapping.start as *const u8, mappings).is_err() {
                continue;
            }
            let ptr = mapping.start as *mut u8;
            let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((ptr, size)) };
            let mut area = match MmapPropArea::new(mmap_mut) {
                Ok(a) => std::mem::ManuallyDrop::new(a),
                Err(_) => continue,
            };
            let has_sibling = probes.iter().any(|p| matches!(area.find(p), Ok(Some(_))));
            if has_sibling {
                found_paths.push(mapping.path.clone());
            }
        }
        PREFIX_AREA_CACHE.with(|c| {
            c.borrow_mut()
                .insert(key_prefix.to_string(), found_paths.clone());
        });
        found_paths
    };

    if target_paths.is_empty() {
        return Ok(false);
    }

    // 在所有匹配的 area 里 emplace（确保 bionic 无论读哪个 area 都能拿到）
    let mut any_inserted = false;
    for path in &target_paths {
        let mapping = match mappings.iter().find(|m| &m.path == path) {
            Some(m) => m,
            None => continue,
        };

        if ensure_prop_area_private(mapping.start as *const u8, mappings).is_err() {
            continue;
        }

        let size = mapping.end - mapping.start;
        let ptr = mapping.start as *mut u8;
        let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((ptr, size)) };
        let mut area = match MmapPropArea::new(mmap_mut) {
            Ok(a) => std::mem::ManuallyDrop::new(a),
            Err(_) => continue,
        };

        if let Ok(Some(_)) = area.find(key) {
            continue;
        }

        match area.emplace(key, value.as_bytes(), 0) {
            Ok(()) => {
                if let Ok(Some(data_off)) = area.find(key) {
                    let serial = area.read_serial(data_off);
                    let len_from_serial = serial >> 24;
                    if len_from_serial as usize == value.len() {
                        info!(
                            "COW trie: inserted '{key}' (serial_ok, len={len_from_serial}) into {}",
                            mapping.path
                        );
                        any_inserted = true;
                    }
                }
            }
            Err(e) => {
                warn!(
                    "COW trie: emplace failed for '{key}' in {}: {e}",
                    mapping.path
                );
            }
        }
    }

    Ok(any_inserted)
}
