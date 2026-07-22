//! LocH — Hook `android.location.Country`.
//! Spoofs `getCountryCode()`, `getCountryIso`(), `getSource()`.

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    let _ = config;
    Ok(())
}

pub fn build_property_map(config: &TelephonyConfig) -> Vec<(String, String)> {
    let mut props = Vec::new();
    if let Some(ref iso) = config.sim_country_iso {
        props.push(("gsm.operator.iso-country".to_string(), iso.clone()));
        props.push(("gsm.sim.operator.iso-country".to_string(), iso.clone()));
    }
    props
}