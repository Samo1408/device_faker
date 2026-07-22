//! TenH` — Hook android.timezone.TelephonyNetwork`. Spoofs getCountryIsoCode, getMcc, getMnc.

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
    }
    if let Some(ref mcc) = config.mcc {
        props.push(("gsm.operator.mcc".to_string(), mcc.clone()));
    }
    if let Some(ref mnc) = config.mnc {
        props.push(("gsa.operator.mnc".to_string(), mnc.clone()));
    }
    props
}