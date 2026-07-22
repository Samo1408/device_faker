use std::collections::HashMap;

use anyhow::Result;
use serde::Deserialize;

/// Device profile template
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceTemplate {
    /// Package name list
    #[serde(default)]
    pub packages: Vec<String>,
    /// Device information
    #[serde(default)]
    pub manufacturer: Option<String>,
    #[serde(default)]
    pub brand: Option<String>,
    #[serde(default)]
    pub marketname: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub device: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub hardware: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub characteristics: Option<String>,
    /// Android version spoofing (e.g. "15", "14")
    #[serde(default)]
    pub android_version: Option<String>,
    /// SDK version spoofing (e.g. 35, 34)
    #[serde(default)]
    pub sdk_int: Option<u32>,
    /// Custom property map
    #[serde(default)]
    pub custom_props: Option<HashMap<String, String>>,
    /// Force FORCE_DENYLIST_UNMOUNT for matching apps (default: inherit global)
    #[serde(default)]
    pub force_denylist_unmount: Option<bool>,
    /// CPU spoof preset name (references [cpu_presets])
    #[serde(default)]
    pub cpu_spoof: Option<String>,
    /// Custom CPU spoof content (higher priority than cpu_spoof)
    #[serde(default)]
    pub cpu_spoof_custom: Option<String>,
    /// Property map patterns to clear from /proc/self/maps (default: inherit global)
    #[serde(default)]
    pub hide_maps: Option<Vec<String>>,
    /// Skip COW property spoofing; delegate all props to companion resetprop
    /// When true, getprop and in-process reads are consistent (for integrity detection)
    #[serde(default)]
    pub companion_resetprop: Option<bool>,
    /// Telephony spoofing config for this template
    #[serde(default)]
    pub telephony: Option<TelephonyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub package: String,
    /// Direct device info override
    #[serde(default)]
    pub manufacturer: Option<String>,
    #[serde(default)]
    pub brand: Option<String>,
    #[serde(default)]
    pub marketname: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub device: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub hardware: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub build_id: Option<String>,
    #[serde(default)]
    pub characteristics: Option<String>,
    /// Android version spoofing (e.g. "15", "14")
    #[serde(default)]
    pub android_version: Option<String>,
    /// SDK version spoofing (e.g. 35, 34)
    #[serde(default)]
    pub sdk_int: Option<u32>,
    /// Custom property map
    #[serde(default)]
    pub custom_props: Option<HashMap<String, String>>,
    /// Force FORCE_DENYLIST_UNMOUNT for this app (default: inherit global setting)
    #[serde(default)]
    pub force_denylist_unmount: Option<bool>,
    /// CPU spoof preset name (references [cpu_presets])
    #[serde(default)]
    pub cpu_spoof: Option<String>,
    /// Custom CPU spoof content (higher priority than cpu_spoof)
    #[serde(default)]
    pub cpu_spoof_custom: Option<String>,
    /// Property map patterns to clear from /proc/self/maps (default: inherit global)
    #[serde(default)]
    pub hide_maps: Option<Vec<String>>,
    /// Skip COW property spoofing; delegate all props to companion resetprop
    /// When true, getprop and in-process reads are consistent (for integrity detection)
    #[serde(default)]
    pub companion_resetprop: Option<bool>,
    /// Telephony spoofing config for this template
    #[serde(default)]
    pub telephony: Option<TelephonyConfig>,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Enable FORCE_DENYLIST_UNMOUNT by default (hide module mount traces)
    #[serde(default)]
    pub default_force_denylist_unmount: bool,
    /// Enable debug logging (disabled by default for stealth)
    #[serde(default)]
    pub debug: bool,
    /// Device profile template definitions
    #[serde(default)]
    pub templates: HashMap<String, DeviceTemplate>,
    /// Application configurations
    #[serde(default)]
    pub apps: Vec<AppConfig>,
    /// Global default CPU spoof preset name
    #[serde(default)]
    pub default_cpu_spoof: Option<String>,
    /// CPU spoof preset lookup table
    #[serde(default)]
    pub cpu_presets: HashMap<String, String>,
    /// Property map patterns to clear from /proc/self/maps (disabled by default)
    #[serde(default)]
    pub default_hide_maps: Vec<String>,
    /// Global telephony / SIM spoofing configuration
    #[serde(default)]
    pub telephony: TelephonyConfig,
}

impl Config {
    pub fn from_toml(content: &str) -> Result<Self> {
        Ok(toml::from_str(content)?)
    }

    /// Find app config by package name (direct config first) or template config
    pub fn get_app_config(&self, package_name: &str) -> Option<&AppConfig> {
        self.apps.iter().find(|app| app.package == package_name)
    }

    /// Find template for a package (from template's packages list)
    pub fn find_template_for_package(&self, package_name: &str) -> Option<&DeviceTemplate> {
        self.templates
            .values()
            .find(|template| template.packages.iter().any(|pkg| pkg == package_name))
    }

    /// Get merged config for a package (direct config first, then template packages)
    pub fn get_merged_config(&self, package_name: &str) -> Option<MergedAppConfig> {
        // Prefer direct app config lookup
        if let Some(app) = self.get_app_config(package_name) {
            let mut merged = MergedAppConfig {
                manufacturer: app.manufacturer.clone(),
                brand: app.brand.clone(),
                marketname: app.marketname.clone(),
                model: app.model.clone(),
                name: app.name.clone(),
                device: app.device.clone(),
                product: app.product.clone(),
                hardware: app.hardware.clone(),
                fingerprint: app.fingerprint.clone(),
                build_id: app.build_id.clone(),
                characteristics: app.characteristics.clone(),
                android_version: app.android_version.clone(),
                sdk_int: app.sdk_int,
                custom_props: app.custom_props.clone(),
                force_denylist_unmount: app
                    .force_denylist_unmount
                    .unwrap_or(self.default_force_denylist_unmount),
                cpu_spoof: app.cpu_spoof.clone(),
                cpu_spoof_custom: app.cpu_spoof_custom.clone(),
                cpuinfo_content: None,
                hide_maps: app
                    .hide_maps
                    .clone()
                    .unwrap_or_else(|| self.default_hide_maps.clone()),
                companion_resetprop: app.companion_resetprop.unwrap_or(false),
                telephony_config: app.telephony.clone().unwrap_or_else(|| self.telephony.clone()),
            };
            merged.telephony_config.apply_country_preset();
            merged.cpuinfo_content = merged.resolve_cpuinfo(self);
            return Some(merged);
        }

        // If no direct config, search template packages list
        if let Some(template) = self.find_template_for_package(package_name) {
            let mut merged = MergedAppConfig {
                manufacturer: template.manufacturer.clone(),
                brand: template.brand.clone(),
                marketname: template.marketname.clone(),
                model: template.model.clone(),
                name: template.name.clone(),
                device: template.device.clone(),
                product: template.product.clone(),
                hardware: template.hardware.clone(),
                fingerprint: template.fingerprint.clone(),
                build_id: template.build_id.clone(),
                characteristics: template.characteristics.clone(),
                android_version: template.android_version.clone(),
                sdk_int: template.sdk_int,
                custom_props: template.custom_props.clone(),
                force_denylist_unmount: template
                    .force_denylist_unmount
                    .unwrap_or(self.default_force_denylist_unmount),
                cpu_spoof: template.cpu_spoof.clone(),
                cpu_spoof_custom: template.cpu_spoof_custom.clone(),
                cpuinfo_content: None,
                hide_maps: template
                    .hide_maps
                    .clone()
                    .unwrap_or_else(|| self.default_hide_maps.clone()),
                companion_resetprop: template.companion_resetprop.unwrap_or(false),
                telephony_config: template.telephony.clone().unwrap_or_else(|| self.telephony.clone()),
            };
            merged.telephony_config.apply_country_preset();
            merged.cpuinfo_content = merged.resolve_cpuinfo(self);
            return Some(merged);
        }

        None
    }

    /// Build merged system property map
    /// Empty strings are ignored and not added to the map
    /// Properties marked __DELETE__ are recorded in delete_props
    pub fn build_merged_property_map(merged: &MergedAppConfig) -> HashMap<String, String> {
        let mut map = HashMap::new();

        // Partition-specific prefixes: OnePlus/OPPO devices use bionic prefix routing for these variants
        const PARTITION_PREFIXES: &[&str] = &[
            "odm",
            "vendor",
            "system",
            "system_ext",
            "product",
            "bootimage",
        ];

        if let Some(manufacturer) = &merged.manufacturer
            && !manufacturer.is_empty()
        {
            map.insert("ro.product.manufacturer".to_string(), manufacturer.clone());
            for pfx in PARTITION_PREFIXES {
                map.insert(
                    format!("ro.product.{pfx}.manufacturer"),
                    manufacturer.clone(),
                );
            }
        }
        if let Some(brand) = &merged.brand
            && !brand.is_empty()
        {
            map.insert("ro.product.brand".to_string(), brand.clone());
            for pfx in PARTITION_PREFIXES {
                map.insert(format!("ro.product.{pfx}.brand"), brand.clone());
            }
        }
        if let Some(marketname) = &merged.marketname
            && !marketname.is_empty()
        {
            map.insert("ro.product.marketname".to_string(), marketname.clone());
            // OnePlus/OPPO devices read ro.vendor.oplus.market.name instead of ro.product.marketname
            map.insert(
                "ro.vendor.oplus.market.name".to_string(),
                marketname.clone(),
            );
        }
        if let Some(model) = &merged.model
            && !model.is_empty()
        {
            map.insert("ro.product.model".to_string(), model.clone());
            for pfx in PARTITION_PREFIXES {
                map.insert(format!("ro.product.{pfx}.model"), model.clone());
            }
        }
        if let Some(name) = &merged.name
            && !name.is_empty()
        {
            map.insert("ro.product.name".to_string(), name.clone());
            for pfx in PARTITION_PREFIXES {
                map.insert(format!("ro.product.{pfx}.name"), name.clone());
            }
        }
        if let Some(device) = &merged.device
            && !device.is_empty()
        {
            map.insert("ro.product.device".to_string(), device.clone());
            for pfx in PARTITION_PREFIXES {
                map.insert(format!("ro.product.{pfx}.device"), device.clone());
            }
        } else if let Some(name) = &merged.name
            && !name.is_empty()
        {
            // Fallback to name if device is not set (legacy behavior)
            map.insert("ro.product.device".to_string(), name.clone());
            for pfx in PARTITION_PREFIXES {
                map.insert(format!("ro.product.{pfx}.device"), name.clone());
            }
        }

        if let Some(hardware) = &merged.hardware
            && !hardware.is_empty()
        {
            map.insert("ro.hardware".to_string(), hardware.clone());
        }

        if let Some(fingerprint) = &merged.fingerprint
            && !fingerprint.is_empty()
        {
            map.insert("ro.build.fingerprint".to_string(), fingerprint.clone());
        }

        if let Some(build_id) = &merged.build_id
            && !build_id.is_empty()
        {
            map.insert("ro.build.id".to_string(), build_id.clone());
            map.insert("ro.system.build.id".to_string(), build_id.clone());
            map.insert("ro.vendor.build.id".to_string(), build_id.clone());
            map.insert("ro.product.build.id".to_string(), build_id.clone());
        }

        if let Some(characteristics) = &merged.characteristics
            && !characteristics.is_empty()
        {
            map.insert(
                "ro.build.characteristics".to_string(),
                characteristics.clone(),
            );
        }

        // Android version spoofing properties
        if let Some(android_version) = &merged.android_version
            && !android_version.is_empty()
        {
            map.insert(
                "ro.build.version.release".to_string(),
                android_version.clone(),
            );
            map.insert(
                "ro.system.build.version.release".to_string(),
                android_version.clone(),
            );
            map.insert(
                "ro.vendor.build.version.release".to_string(),
                android_version.clone(),
            );
            map.insert(
                "ro.product.build.version.release".to_string(),
                android_version.clone(),
            );
        }

        if let Some(sdk_int) = merged.sdk_int {
            let sdk_str = sdk_int.to_string();
            map.insert("ro.build.version.sdk".to_string(), sdk_str.clone());
            map.insert("ro.system.build.version.sdk".to_string(), sdk_str.clone());
            map.insert("ro.vendor.build.version.sdk".to_string(), sdk_str.clone());
            map.insert("ro.product.build.version.sdk".to_string(), sdk_str.clone());
        }

        // Custom properties
        if let Some(custom_props) = &merged.custom_props {
            for (key, value) in custom_props {
                if value == "__DELETE__" {
                    continue;
                }
                let final_value = if value == "__EMPTY__" {
                    "".to_string()
                } else {
                    value.clone()
                };
                map.insert(key.clone(), final_value);
            }
        }

        // ── Telephony / SIM / Country spoofing properties ──────────────
        let tc = &merged.telephony_config;
        if let Some(ref iso) = tc.sim_country_iso {
            map.insert("gsm.sim.operator.iso-country".to_string(), iso.clone());
            map.insert("gsm.operator.iso-country".to_string(), iso.clone());
        }
        if let Some(ref mcc) = tc.mcc {
            map.insert("gsm.sim.operator.mcc".to_string(), mcc.clone());
            map.insert("gsm.operator.mcc".to_string(), mcc.clone());
        }
        if let Some(ref mnc) = tc.mnc {
            map.insert("gsm.sim.operator.mnc".to_string(), mnc.clone());
            map.insert("gsm.operator.mnc".to_string(), mnc.clone());
            if let Some(ref mcc) = tc.mcc {
                map.insert("gsm.sim.operator.numeric".to_string(), format!("{mcc}{mnc}"));
                map.insert("gsm.operator.numeric".to_string(), format!("{mcc}{mnc}"));
            }
        }
        if let Some(ref op_name) = tc.operator_name {
            map.insert("gsm.sim.operator.alpha".to_string(), op_name.clone());
            map.insert("gsm.operator.alpha".to_string(), op_name.clone());
        }
        if let Some(ref tz) = tc.timezone {
            map.insert("persist.sys.timezone".to_string(), tz.clone());
        }
        if let Some(ref iccid) = tc.iccid {
            map.insert("persist.radio.iccid".to_string(), iccid.clone());
        }
        if let Some(ref soc_mfr) = tc.soc_manufacturer {
            map.insert("ro.soc.manufacturer".to_string(), soc_mfr.clone());
        }
        if let Some(ref soc_model) = tc.soc_model {
            map.insert("ro.soc.model".to_string(), soc_model.clone());
            map.insert("ro.hardware.chipname".to_string(), soc_model.clone());
        }
        if let Some(ref bootloader) = tc.bootloader {
            map.insert("ro.bootloader".to_string(), bootloader.clone());
        }
        if let Some(ref baseband) = tc.baseband {
            map.insert("ro.baseband".to_string(), baseband.clone());
        }
        if let Some(ref serial) = tc.device_serial {
            map.insert("ro.serialno".to_string(), serial.clone());
        }
        if tc.hide_airplane_mode {
            map.insert("persist.sys.airplane_mode_on".to_string(), "0".to_string());
        }
        if tc.hide_developer_mode {
            map.insert("persist.sys.developer_options".to_string(), "0".to_string());
        }

        map
    }

    /// Build list of properties to delete (for companion mode)
    pub fn build_delete_props_list(merged: &MergedAppConfig) -> Vec<String> {
        let mut delete_props = Vec::new();

        if merged.brand.as_ref().is_some_and(|s| s == "__DELETE__") {
            delete_props.push("ro.product.brand".to_string());
        }
        if merged
            .manufacturer
            .as_ref()
            .is_some_and(|s| s == "__DELETE__")
        {
            delete_props.push("ro.product.manufacturer".to_string());
        }
        if merged.model.as_ref().is_some_and(|s| s == "__DELETE__") {
            delete_props.push("ro.product.model".to_string());
        }
        if merged.name.as_ref().is_some_and(|s| s == "__DELETE__") {
            delete_props.push("ro.product.name".to_string());
        }
        if merged.device.as_ref().is_some_and(|s| s == "__DELETE__") {
            delete_props.push("ro.product.device".to_string());
        }
        if merged
            .marketname
            .as_ref()
            .is_some_and(|s| s == "__DELETE__")
        {
            delete_props.push("ro.product.marketname".to_string());
        }
        if merged
            .fingerprint
            .as_ref()
            .is_some_and(|s| s == "__DELETE__")
        {
            delete_props.push("ro.build.fingerprint".to_string());
        }
        if merged.build_id.as_ref().is_some_and(|s| s == "__DELETE__") {
            delete_props.push("ro.build.id".to_string());
            delete_props.push("ro.system.build.id".to_string());
            delete_props.push("ro.vendor.build.id".to_string());
            delete_props.push("ro.product.build.id".to_string());
        }
        if merged
            .characteristics
            .as_ref()
            .is_some_and(|s| s == "__DELETE__")
        {
            delete_props.push("ro.build.characteristics".to_string());
        }
        if merged.hardware.as_ref().is_some_and(|s| s == "__DELETE__") {
            delete_props.push("ro.hardware".to_string());
        }

        if let Some(custom_props) = &merged.custom_props {
            for (key, value) in custom_props {
                if value == "__DELETE__" {
                    delete_props.push(key.clone());
                }
            }
        }

        delete_props
    }
}

/// Merged app config (template + direct overrides)
#[derive(Debug, Clone)]
pub struct MergedAppConfig {
    pub manufacturer: Option<String>,
    pub brand: Option<String>,
    pub marketname: Option<String>,
    pub model: Option<String>,
    pub name: Option<String>,
    pub device: Option<String>,
    pub product: Option<String>,
    pub hardware: Option<String>,
    pub fingerprint: Option<String>,
    pub build_id: Option<String>,
    pub characteristics: Option<String>,
    pub android_version: Option<String>,
    pub sdk_int: Option<u32>,
    pub custom_props: Option<HashMap<String, String>>,
    pub force_denylist_unmount: bool,
    /// CPU spoof preset name
    pub cpu_spoof: Option<String>,
    /// Custom CPU spoof content
    pub cpu_spoof_custom: Option<String>,
    /// Final content to bind-mount to /proc/cpuinfo (resolved)
    pub cpuinfo_content: Option<String>,
    /// Property map patterns to clear from /proc/self/maps
    pub hide_maps: Vec<String>,
    /// Skip COW; all props via companion resetprop (default: false)
    pub companion_resetprop: bool,
    /// Telephony / SIM / country spoofing configuration
    pub telephony_config: TelephonyConfig,
}

impl MergedAppConfig {
    /// Compute final CPU spoof content
    pub fn resolve_cpuinfo(&self, config: &Config) -> Option<String> {
        if let Some(custom) = &self.cpu_spoof_custom
            && !custom.is_empty()
        {
            return Some(custom.clone());
        }

        let preset_name = self
            .cpu_spoof
            .as_ref()
            .or(config.default_cpu_spoof.as_ref())?;

        config.cpu_presets.get(preset_name).cloned()
    }
}

// ── Telephony / SIM / Country spoofing config ──────────────────────────────────

/// Configuration for telephony, SIM, and network identity spoofing.
/// This is embedded within the main Config and passed to each hook module.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TelephonyConfig {
    /// Selected country ISO code (e.g. "us", "gb", "de", "jp")
    #[serde(default)]
    pub country_iso: Option<String>,
    /// SIM country ISO (e.g. "us")
    #[serde(default)]
    pub sim_country_iso: Option<String>,
    /// Mobile Country Code (e.g. "311" for US)
    #[serde(default)]
    pub mcc: Option<String>,
    /// Mobile Network Code (e.g. "480" for Verizon)
    #[serde(default)]
    pub mnc: Option<String>,
    /// Operator / carrier display name
    #[serde(default)]
    pub operator_name: Option<String>,
    /// SIM serial number / ICCID (editable + random generation)
    #[serde(default)]
    pub sim_serial: Option<String>,
    /// Timezone ID (e.g. "America/Chicago")
    #[serde(default)]
    pub timezone: Option<String>,
    /// Device serial number (editable + random generation)
    #[serde(default)]
    pub device_serial: Option<String>,
    /// SoC manufacturer (e.g. "Qualcomm", "Google")
    #[serde(default)]
    pub soc_manufacturer: Option<String>,
    /// SoC model (e.g. "Snapdragon 8 Gen 3", "Tensor G3")
    #[serde(default)]
    pub soc_model: Option<String>,
    /// Bootloader version string (editable + random generation)
    #[serde(default)]
    pub bootloader: Option<String>,
    /// Baseband version string (editable + random generation)
    #[serde(default)]
    pub baseband: Option<String>,
    /// ICCID value (editable + random generation)
    #[serde(default)]
    pub iccid: Option<String>,
    /// IP address spoofing (editable + random generation)
    #[serde(default)]
    pub ip_address: Option<String>,
    /// Hide airplane mode (always report as OFF)
    #[serde(default)]
    pub hide_airplane_mode: bool,
    /// Hide developer options and USB debugging
    #[serde(default)]
    pub hide_developer_mode: bool,
    /// Country source (e.g. "network", "sim", "locale")
    #[serde(default)]
    pub country_source: Option<String>,
}

/// Country presets: maps ISO code → (MCC, MNC, timezone, lat, lon)
#[derive(Debug, Clone)]
pub struct CountryPreset {
    pub iso: &'static str,
    pub label: &'static str,
    pub mcc: &'static str,
    pub mnc: &'static str,
    pub timezone: &'static str,
    pub lat: f64,
    pub lon: f64,
}

/// Built-in country presets (20+ countries).
pub const COUNTRY_PRESETS: &[CountryPreset] = &[
    CountryPreset { iso: "us", label: "United States", mcc: "311", mnc: "480", timezone: "America/Chicago", lat: 41.8781, lon: -87.6298 },
    CountryPreset { iso: "gb", label: "United Kingdom", mcc: "234", mnc: "15", timezone: "Europe/London", lat: 51.5074, lon: -0.1278 },
    CountryPreset { iso: "de", label: "Germany", mcc: "262", mnc: "01", timezone: "Europe/Berlin", lat: 52.5200, lon: 13.4050 },
    CountryPreset { iso: "ca", label: "Canada", mcc: "302", mnc: "720", timezone: "America/Toronto", lat: 43.6532, lon: -79.3832 },
    CountryPreset { iso: "ch", label: "Switzerland", mcc: "228", mnc: "01", timezone: "Europe/Zurich", lat: 47.3769, lon: 8.5417 },
    CountryPreset { iso: "kr", label: "South Korea", mcc: "450", mnc: "05", timezone: "Asia/Seoul", lat: 37.5665, lon: 126.9780 },
    CountryPreset { iso: "jp", label: "Japan", mcc: "440", mnc: "10", timezone: "Asia/Tokyo", lat: 35.6762, lon: 139.6503 },
    CountryPreset { iso: "fr", label: "France", mcc: "208", mnc: "01", timezone: "Europe/Paris", lat: 48.8566, lon: 2.3522 },
    CountryPreset { iso: "au", label: "Australia", mcc: "505", mnc: "01", timezone: "Australia/Sydney", lat: -33.8688, lon: 151.2093 },
    CountryPreset { iso: "br", label: "Brazil", mcc: "724", mnc: "05", timezone: "America/Sao_Paulo", lat: -23.5505, lon: -46.6333 },
    CountryPreset { iso: "in", label: "India", mcc: "405", mnc: "01", timezone: "Asia/Kolkata", lat: 28.6139, lon: 77.2090 },
    CountryPreset { iso: "ru", label: "Russia", mcc: "250", mnc: "01", timezone: "Europe/Moscow", lat: 55.7558, lon: 37.6173 },
    CountryPreset { iso: "it", label: "Italy", mcc: "222", mnc: "01", timezone: "Europe/Rome", lat: 41.9028, lon: 12.4964 },
    CountryPreset { iso: "es", label: "Spain", mcc: "214", mnc: "01", timezone: "Europe/Madrid", lat: 40.4168, lon: -3.7038 },
    CountryPreset { iso: "nl", label: "Netherlands", mcc: "204", mnc: "04", timezone: "Europe/Amsterdam", lat: 52.3676, lon: 4.9041 },
    CountryPreset { iso: "se", label: "Sweden", mcc: "240", mnc: "01", timezone: "Europe/Stockholm", lat: 59.3293, lon: 18.0686 },
    CountryPreset { iso: "no", label: "Norway", mcc: "242", mnc: "01", timezone: "Europe/Oslo", lat: 59.9139, lon: 10.7522 },
    CountryPreset { iso: "sg", label: "Singapore", mcc: "525", mnc: "01", timezone: "Asia/Singapore", lat: 1.3521, lon: 103.8198 },
    CountryPreset { iso: "ae", label: "UAE", mcc: "424", mnc: "02", timezone: "Asia/Dubai", lat: 25.2048, lon: 55.2708 },
    CountryPreset { iso: "sa", label: "Saudi Arabia", mcc: "420", mnc: "01", timezone: "Asia/Riyadh", lat: 24.7136, lon: 46.6753 },
    CountryPreset { iso: "tr", label: "Turkey", mcc: "286", mnc: "01", timezone: "Europe/Istanbul", lat: 41.0082, lon: 28.9784 },
    CountryPreset { iso: "mx", label: "Mexico", mcc: "334", mnc: "020", timezone: "America/Mexico_City", lat: 19.4326, lon: -99.1332 },
];

impl CountryPreset {
    pub fn find(iso: &str) -> Option<&'static CountryPreset> {
        COUNTRY_PRESETS.iter().find(|p| p.iso.eq_ignore_ascii_case(iso))
    }
}

impl TelephonyConfig {
    /// Merge country preset values into this config if country_iso is set.
    pub fn apply_country_preset(&mut self) {
        if let Some(ref iso) = self.country_iso {
            if let Some(preset) = CountryPreset::find(iso) {
                if self.mcc.is_none() { self.mcc = Some(preset.mcc.to_string()); }
                if self.mnc.is_none() { self.mnc = Some(preset.mnc.to_string()); }
                if self.sim_country_iso.is_none() { self.sim_country_iso = Some(preset.iso.to_uppercase()); }
                if self.timezone.is_none() { self.timezone = Some(preset.timezone.to_string()); }
            }
        }
    }
}
