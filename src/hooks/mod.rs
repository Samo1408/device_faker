//! Telephony, SIM, and device identification spoofing hooks.
//!
//! Each submodule implements spoofing logic for a specific Android class.
//! Hooks are applied during `pre_app_specialize`. Most spoofing is done
//! through system property modification (companion resetprop), making
//! this approach compatible with all Android versions without requiring
//! method-level JNI hooking.

pub mod tele_sh;
pub mod sim_h;
pub mod sem_h;
pub mod sub_h;
pub mod ten_h;
pub mod emg_h;
pub mod it_h;
pub mod loc_h;
pub mod call_h;
pub mod tmzn_h;
pub mod java_icu4;
pub mod soc_h;
pub mod ip_h;
pub mod air_h;
pub mod dev_h;

use jni::{EnvUnowned, errors::ThrowRuntimeExAndDefault};
use log::info;

use crate::config::TelephonyConfig;

/// Build all telephony-related properties to add to the spoof map.
/// Called from config.rs build_merged_property_map (already integrated).
pub fn build_all_telephony_props(config: &TelephonyConfig) -> Vec<(String, String)> {
    let mut props = Vec::new();
    props.extend(sim_h::build_property_map(config));
    props.extend(sub_h::build_property_map(config));
    props.extend(ten_h::build_property_map(config));
    props.extend(loc_h::build_property_map(config));
    props.extend(tmzn_h::build_property_map(config));
    props.extend(java_icu4::build_property_map(config));
    props.extend(soc_h::build_property_map(config));
    props.extend(air_h::build_property_map(config));
    props.extend(dev_h::build_property_map(config));
    props
}

/// Apply all telephony/SIM spoofing hooks for a given app.
/// Each submodule's hook() function records the configuration.
/// The actual spoofing happens via system properties set by companion resetprop.
pub fn apply_telephony_hooks(
    env: &mut EnvUnowned,
    config: &TelephonyConfig,
) -> anyhow::Result<()> {
    env.with_env(|jenv| -> Result<(), jni::errors::Error> {
        let _ = tele_sh::hook(jenv, config);
        let _ = sim_h::hook(jenv, config);
        let _ = sem_h::hook(jenv, config);
        let _ = sub_h::hook(jenv, config);
        let _ = ten_h::hook(jenv, config);
        let _ = emg_h::hook(jenv, config);
        let _ = it_h::hook(jenv, config);
        let _ = loc_h::hook(jenv, config);
        let _ = call_h::hook(jenv, config);
        let _ = tmzn_h::hook(jenv, config);
        let _ = java_icu4::hook(jenv, config);
        let _ = soc_h::hook(jenv, config);
        let _ = ip_h::hook(jenv, config);
        let _ = air_h::hook(jenv, config);
        let _ = dev_h::hook(jenv, config);
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();

    info!("All telephony hooks applied successfully");
    Ok(())
}
