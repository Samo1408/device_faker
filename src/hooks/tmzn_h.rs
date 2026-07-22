//! TmznH - Hook `android.app.timezonedetector.TelephonyTimeZoneSuggestion$Builder`.
//! Spoofs `setCountryIso()`.

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    let _ = config;
    Ok(())
}

/// Build timezone-related properties for the spoof map.
pub fn build_property_map(config: &TelephonyConfig) -> Vec<(String, String)> {
    let mut props = Vec::new();
    if let Some(ref tz) = config.timezone {
        props.push(("persist.sys.timezone".to_string(), tz.clone()));
    }
    props
}