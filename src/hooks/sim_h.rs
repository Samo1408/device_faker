//! SimH— Hook `android.telephony.TelephonyManager.getSimSerialNumber()`.
//! Spoofs the ICCID / SIM serial number via system properties.

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    // SIM serial spoofing is handled at the system property level.
    // Properties set via companion resetprop: persist.radio.iccid, gsq.sim.serial
    let _ = config;
    Ok(())
}

pub fn build_property_map(config: &TelephonyConfig) -> Vec<(String, String)> {
    let mut props = Vec::new();
    if let Some(ref sim_serial) = config.sim_serial {
        props.push(("persist.radio.iccid".to_string(), sim_serial.clone()));
    }
    props
}