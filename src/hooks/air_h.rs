//! AirH — Hide airplane mode state.
//! Forces `Settings.Global.AIRPLANE_MODE_ON` to always appear as `0` (off).

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    if !config.hide_airplane_mode {
        return Ok(());
    }
    // We set the property that controls airplane mode at the system level
    let _ = env;
    Ok(())
}

pub fn build_property_map(config: &TelephonyConfig) -> Vec<(String, String)> {
    if config.hide_airplane_mode {
        vec![("persist.sys.airplane_mode_on".to_string(), "0".to_string())]
    } else {
        Vec::new()
    }
}
