//! SubH — Hook `android.telephony.SubscriptionInfo`.
//! Spoofs subscription info getters to match the selected country/SIM config.

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    let _ = config;
    Ok(())
}

pub fn build_property_map(config: &TelephonyConfig) -> Vec<(String, String)> {
    let mut props = Vec::new();
    if let Some(ref iccid) = config.iccid {
        props.push(("persist.radio.iccid".to_string(), iccid.clone()));
    }
    if let Some(ref mcc) = config.mcc {
        props.push(("gsm.sim.operator.mcc".to_string(), mcc.clone()));
    }
    if let Some(ref mnc) = config.mnc {
        props.push(("gsm.sim.operator.mnc".to_string(), mnc.clone()));
    }
    if let Some(ref carrier_name) = config.operator_name {
        props.push(("gsm.sim.operator.alpha".to_string(), carrier_name.clone()));
    }
    props
}