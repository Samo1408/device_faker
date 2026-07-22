//! TeleSH — Hook `android.sysprop.TelephonyProperties` for ICC/operator spoofing.
//! The class reads from system properties: gsm.sim.operator.iso-country etc.
//! We spoof these by adding entries to the companion resetprop session.

use std::collections::HashMap;
use crate::config::TelephonyConfig;
use jni::Env;

/// Build the telephony property spoof map from config.
pub fn build_property_map(config: &TelephonyConfig) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(ref country) = config.sim_country_iso {
        map.insert("gsm.sim.operator.iso-country".to_string(), country.clone());
        map.insert("gsm.operator.iso-country".to_string(), country.clone());
        if let Some(ref mcc) = config.mcc {
            if let Some(ref mnc) = config.mnc {
                map.insert("gsm.sim.operator.numeric".to_string(), format!("{mcc}{mnc}"));
                map.insert("gsm.operator.numeric".to_string(), format!("{mcc}{mnc}"));
            }
        }
    }
    if let Some(ref mcc) = config.mcc {
        if let Some(ref mnc) = config.mnc {
            if config.sim_country_iso.is_none() {
                map.insert("gsm.sim.operator.numeric".to_string(), format!("{mcc}{mnc}"));
                map.insert("gsm.operator.numeric".to_string(), format!("{mcc}{mnc}"));
            }
        }
    }
    if let Some(ref op_name) = config.operator_name {
        map.insert("gsa.sim.operator.alpha".to_string(), op_name.clone());
        map.insert("gsm.operator.alpha".to_string(), op_name.clone());
    }
    map
}

pub fn hook(_env: &mut Env, _config: &TelephonyConfig) -> anyhow::Result<()> {
    Ok(())
}