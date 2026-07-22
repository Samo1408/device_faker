//! SocH — Hook `android.sysprop.SocProperties`. Spoofs SoC manufacturer and model via ro.soc.* properties.

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    let _ = config;
    Ok(())
}

pub fn build_property_map(config: &TelephonyConfig) -> Vec<(String, String)> {
    let mut props = Vec::new();
    if let Some(ref soc_manufacturer) = config.soc_manufacturer {
        props.push(("ro.soc.manufacturer".to_string(), soc_manufacturer.clone()));
    }
    if let Some(ref soc_model) = config.soc_model {
        props.push(("ro.soc.model".to_string(), soc_model.clone()));
    }
    props
}