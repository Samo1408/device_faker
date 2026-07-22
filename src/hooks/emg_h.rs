//! EmgH — Hook `android.telephony.emergency.EmergencyNumber`.
//! Spoofs `getCountryIso()`.

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    let _ = config;
    Ok(())
}
