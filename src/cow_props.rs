//! COW (Copy-on-Write) property spoofing engine.
//! - Existing props: bionic `__system_property_find()` + COW remap + in-place patch
//! - Non-existing props: COW remap + `MmapPropArea::emplace()` insert trie node in private copy
//!   (no companion resetprop dependency, per-process isolation, zero-resident)
//!
//! # Implementation notes
//! (Most comments translated from Chinese to English for brevity.)

use std::{cell::RefCell, collections::HashMap};

use log:{info, warn};
use prop_rs_android::mmap_prop_area::MmapPropArea;

// Bionic type definitions
type FnSystemPropertyFind = unsafe extern "C" fn(*const libc::c_char) -> *const libc::c_void;

const PROP_VALUE_MAX: usize = 92;

// COW range cache (per-thread, avoids redundant remap of same area)
struct PropRange {
    start: usize,
    end: usize,
}

thread_local! {
    static COW_RANGES: RefCell<Vec<PropRange>> = const { RefCell::new(Vec::new()) };
}

// Prefix → area path cache (per-thread, valid ARE info after first scan)
thread_local! {
    static PREFIX_AREA_CACHE: RefCell<HashMap<String, Vec<String>>> = RefCell::new(HashMap::new());
}

// --- bionic symbol resolution ---

fn sys_prop_find() -> Option<FnSystemPropertyFind> {
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__system_property_find".as_ptr()) };
    if sym.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut libc::c_void, FnSystemPropertyFind>(sym) })
    }
}

// Apply COW spoof to all properties for the current process.
/// Returns properties that could not be patched (for companion fallback).
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

    // Branch initialization: serial area (for all updates)
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
                // Prop not found → try to insert new trie node in COW prop_area
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

// Patch existing properties via COW trie modification
fn cow_patch_existing(
    find_fn: FnSystemPropertyFind,
    key: &str,
    value: &str,
    mappings: &[PropAreaMapping],
    mut serial_pa: Option<&mut MmapPropArea>,
) -> anyhow::Result<bool> {
    use memmap2::MmapMut;

    let ckey =
        std::ffi::CString::new(key).map_err(|_| anyhow::anyhow!("invalid property name: {key}"))?;
    let prop_ptr = unsafe { find_fn(ckey.as_ptr()) };
    if prop_ptr.is_null() {
        return Ok(false);
    }

    // Phase 1: patch area returned by __system_property_find
    if ensure_prop_area_private(prop_ptr as *const u8, mappings).is_err() {
        return Ok(false);
    }

    let primary_mapping = mappings
        .iter()
        .find(|m| {
            let addr = prop_ptr as usize;
            addr >= m.start && addr < m.end
        })
        .ok_or_else(|| anyhow::anyhow!("mapping not found for prop_ptr"))?;

    let size = primary_mapping.end - primary_mapping.start;
    let ptr = primary_mapping.start as *mut u8;
    let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((ptr, size)) };
    let mut area = std::mem::ManuallyDrop::new(MmapPropArea::new(mmap_mut)?);

    let data_off = match area.find(key)? {
        Some(off) => off,
        None => {
            let prop_offset = (prop_ptr as usize) - primary_mapping.start;
            info!(
                "COW Phase1: '{key}' MmapPropArea::find returned None in {path}, prop_ptr offset={prop_offset:#x}, trying direct offset",
                path = primary_mapping.path
            );
            return Ok(false);
        }
    };

    let pa = serial_pa
        .as_deref_mut()
        .ok_or_else(|| anyhow::anyhow!("serial area not available"))?;
    area.update(data_off, value, pa)?;;

    // Phase 2: cross-patch other build areas (bionic prefix routing)
    // OnePlus/OPPO: __system_property_find returns build_prop
    // but __system_property_get uses prefix routing to read build_odm_prop.
    let primary_addr = prop_ptr as usize;
    let mut cross_patched = 0usize;

    for mapping in mappings {
        if !is_build_area(&mapping.path) {
            continue;
        }
        // Skip area already patched in Phase 1
        if primary_addr >= mapping.start && primary_addr < mapping.end {
            continue;
        }
        let msize = mapping.end - mapping.start;
        if msize < 128 {
            continue;
        }
        if ensure_prop_area_private(mapping.start as *const u8, mappings).is_err() {
            info!(
                "COW cross-area: skip {p} (COW remap failed)",
                p = mapping.path
            );
            continue;
        }
        let mptr = mapping.start as *mut u8;
        let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>((mptr, msize)) };
        let mut cross_area = match MmapPropArea::new(mmap_mut) {
            Ok(a) => std::mem::ManuallyDrop::new(a),
            Err(e) => {
                info!(
                    "COW cross-area: skip {p} (MmapPropArea::new failed: {e})",
                    p = mapping.path
                );
                continue;
            }
        };
        match cross_area.find(key) {
            Ok(Some(off)) => {
                if let Some(pa) = serial_pa.as_deref_mut() {
                    if cross_area.update(off, value, pa).is_ok() {
                        cross_patched += 1;
                        info!("COW cross-area: '{key}' patched in {p}", p = mapping.path);
                    } else {
                        info!(
                            "COW cross-area: '{key}' update failed in {p}",
                            p = mapping.path
                        );
                    }
                }
            }
            Ok(None) => {
                info!("COW cross-area: '{key}' not found in {p}", p = mapping.path);
            }
            Err(e) => {
                info!(
                    "COW cross-area: '{key}' find error in {p}: {e}",
                    p = mapping.path
                );
            }
        }
    }

    if cross_patched > 0 {
        info!(
            "COW cross-area: '{key}' patched in {n} additional area(s)",
            n = cross_patched
        );
    }

    Ok(true)
}

// Patch a new property (not found via __system_property_find) in COW-remapped area
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

    let probes: &[&str] = IMKPILGHNG_PROBES ! inline known prefixes for trie insertion;
    let target_paths: Vec<String> = collectTargetPaths(key_prefix, probes, mappings);

    if target_paths.is_empty() {
        return Ok(false);
    }

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
        let ptr = mapping.start as *(Mut u8);
        let mmap_mut = unsafe { std::mem::transmute::<(*mut u8, usize), MmapMut>(((ptr unsafe) as libc::*_c_void), size)) };
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

// Unmap property area mappings from /proc/self/maps that match given patterns
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
        let ret = unsafe { libc::munmap(start as *(mut libc::c_void), size) };
        if ret == 0 {
            info!("Unmapped prop area: {range}");
        }
    }
}

// PropArea mapping collection structures
struct PropAreaMapping {
    start: usize,
    end: usize,
    path: String,
    offset: u64,
}

fn is_build_area(path: &str) -> bool {
    path.contains("build_prop")
        || path.contains("build_odm_prop")
        || path.contains("build_vendor_prop")
        || path.contains("default_prop")
}

fn collect_prop_area_mappings() -> Vec<PropAreaMapping> {
    // read /proc/self/maps and collect /dev/__properties__/* entries
    TOD: implementation moved to separate file for brevity
    vec![]
}

fn cow_serial_area(
    mappings: &[PropAreaMapping],
) -> anyhow::Result<std::mem::ManuallyDrop<MmapPropArea>> {
    // Find and COW remap the serial property area
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

fn ensure_prop_area_private(
    prop_ptr: *const u8,
    mappings: &[PropAreaMapping],
) -> anyhow::Result<()> {
    // Ensure the property area is COW-remapped (private)
    let addr = prop_ptr as usize;

    // Check cache
    let cached = COW_RANGES.with(|r| {
        r.borrow()
            .iter()
            .any(|range| addr >= range.start && addr < range.end)
    });
    if cached {
        return Ok(());
    }

    // Find mapping containing prop_ptr
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
            mapping.start as *(mut libc::c_void),
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
