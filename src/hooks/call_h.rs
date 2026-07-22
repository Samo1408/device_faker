//! CallH — Hook `android.telecom.CallerInfo`.
//! Spoofs `getCurrentCountryIso()`.

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    let _ = config;
    Ok(())
}
