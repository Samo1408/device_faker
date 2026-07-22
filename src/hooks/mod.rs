//! Telephony, SIM, and device identification spoofing hooks.
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
pub fn apply_telephony_hooks(
    env: &mut EnvUnowned,
    config: &TelephonyConfig,
) -> anyhow::Result<()> {
    env.with_env(|jenv| -> anyhow::Result<()> {
        tele_sh::hook(jenv, config)?;
        sim_h::hook(jenv, config)?;
        sem_h::hook(jenv, config)?;
        sub_h::hook(jenv, config)?;
        ten_h::hook(jenv, config)?;
        emg_h::hook(jenv, config)?;
        it_h::hook(jenv, config)?;
        loc_h::hook(jenv, config)?;
        call_h::hook(jenv, config)?;
        tmzn_h::hook(jenv, config)?;
        java_icu4::hook(jenv, config)?;
        soc_h::hook(jenv, config)?;
        ip_h::hook(jenv, config)?;
        air_h::hook(jenv, config)?;
        dev_h::hook(jenv, config)?;
        Ok(())
    })
    .resolve::<ThrowRuntimeExAndDefault>();

    info!("All telephony hooks applied successfully");
    Ok(())
}