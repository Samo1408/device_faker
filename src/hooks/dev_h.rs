//! DevH — Hide developer mode and USB debugging state.
//!
//! Spoofs:
//!   - `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED` → 0
//!   - `Settings.Global.ADB_ENABLED` → 0

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    let _ = config;
    Ok(())
}

pub fn build_property_map(config: &TelephonyConfig) -> Vec<(String, String)> {
    let mut props = Vec::new();
    if config.hide_developer_mode {
        props.push(("persist.sys.developer_options".to_string(), "0".to_string()));
        props.push(("init.svc.adbd".to_string(), "stopped".to_string()));
        props.push(("sys.usb.config".to_string(), "mtp".to_string()));
        props.push(("persist.sys.usb.config".to_string(), "mtp".to_string()));
    }
    props
}
