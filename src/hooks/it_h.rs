//! ITH — Hook `com.android.internal.telephony.ITelephony$Stub$Proxy`.
//! Spoofs `getNetworkCountryIsoForPhone()`.

use jni::Env;
use crate::config::TelephonyConfig;

pub fn hook(_env: &mut Env, config: &TelephonyConfig) -> anyhow::Result<()> {
    // ITelephony is an AIDL-generated proxy. Country ISO derives from gsn.operator.iso-country.
    let _ = config;
    Ok(())
}
